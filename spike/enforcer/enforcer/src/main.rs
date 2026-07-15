use anyhow::{bail, Context, Result};
use aya::{
    maps::{Array, MapData},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use clap::{Parser, Subcommand};
use enforcer_common::Rule;
use signal_hook::{consts::SIGHUP, iterator::Signals};

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Run {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        rules: std::path::PathBuf,
        #[arg(long, default_value = "/sys/fs/bpf/aeth")]
        pin_dir: std::path::PathBuf,
    },
    Stats {
        #[arg(long, default_value = "/sys/fs/bpf/aeth")]
        pin_dir: std::path::PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run { iface, rules, pin_dir } => run(&iface, &rules, &pin_dir),
        Cmd::Stats { pin_dir } => stats(&pin_dir),
    }
}

/// Make sure `/sys/fs/bpf` is an actual mounted bpf filesystem before we try
/// to create the pin dir / pin maps there. On systemd hosts `sys-fs-bpf.mount`
/// does this at boot, but containers (this dev container included) and other
/// minimal environments frequently leave it as a plain directory under sysfs,
/// where `create_dir_all`/`BPF_OBJ_PIN` fail with ENOENT. A real gateway needs
/// the same guarantee, so it lives here rather than in any test/dev wrapper.
fn ensure_bpffs(pin_dir: &std::path::Path) -> Result<()> {
    if !pin_dir.starts_with(BPFFS_ROOT) {
        // Custom pin location: caller is responsible for it being on a bpffs.
        return Ok(());
    }
    let root = std::ffi::CString::new(BPFFS_ROOT).expect("no NUL in constant");
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(root.as_ptr(), &mut st) } == 0 && st.f_type as u64 == BPF_FS_MAGIC {
        return Ok(()); // already a mounted bpffs
    }
    let fstype = std::ffi::CString::new("bpf").expect("no NUL in constant");
    let rc = unsafe {
        libc::mount(
            fstype.as_ptr(), // source (conventionally "bpf"/"bpffs"; unused by kernel)
            root.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        bail!(
            "{BPFFS_ROOT} is not a bpf filesystem and mounting one there failed: {} \
             (map pinning requires bpffs; are we missing CAP_SYS_ADMIN?)",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

const PINNED_MAPS: [&str; 6] = ["COUNTERS", "ACTIVE", "RULES_A", "RULES_B", "RULE_LEN", "FLOWS"];

/// Mount-ns-shared rendezvous file mapping this enforcer instance's map names
/// to their (system-global) BPF map ids, keyed by the pin dir.
///
/// Why it exists: `ip netns exec` does its own unshare(CLONE_NEWNS) + /sys
/// remount on every invocation, and each bpffs mount is an independent, empty
/// superblock — so a later `enforcer stats` invocation can never see the pins
/// the running enforcer created in its own mount ns. BPF object ids, however,
/// are global to the kernel, and /tmp (unlike /sys) survives those unshares
/// as the same shared mount. Keying the filename by the full pin-dir path is
/// what keeps concurrent enforcer instances (e.g. Task 8's two gateways with
/// --pin-dir /sys/fs/bpf/aeth-a and .../aeth-b) deterministically separable:
/// `stats --pin-dir X` reads exactly the ids written by `run --pin-dir X`.
/// The file is overwritten on every `run` start with the same pin dir; a
/// stale file from a dead enforcer is detected in `stats` by re-checking the
/// map's name via MapInfo before trusting the id.
fn map_ids_path(pin_dir: &std::path::Path) -> std::path::PathBuf {
    let key = pin_dir
        .to_string_lossy()
        .trim_matches('/')
        .replace('/', "_");
    std::path::PathBuf::from(format!("/tmp/enforcer-{key}.mapids.json"))
}

fn write_map_ids(pin_dir: &std::path::Path) -> Result<()> {
    let mut ids = serde_json::Map::new();
    for m in PINNED_MAPS {
        let id = MapData::from_pin(pin_dir.join(m))
            .with_context(|| format!("reopening pinned map {m}"))?
            .info()
            .with_context(|| format!("querying map info for {m}"))?
            .id();
        ids.insert(m.to_string(), id.into());
    }
    let path = map_ids_path(pin_dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::Value::Object(ids).to_string())
        .with_context(|| format!("writing map-id file {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("moving map-id file into place at {}", path.display()))?;
    Ok(())
}

fn run(iface: &str, rules_path: &std::path::Path, pin_dir: &std::path::Path) -> Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/enforcer"
    )))?;
    let _ = tc::qdisc_add_clsact(iface); // idempotent-ish: ignore EEXIST
    for (prog, at) in [
        ("aeth_ingress", TcAttachType::Ingress),
        ("aeth_egress", TcAttachType::Egress),
    ] {
        let p: &mut SchedClassifier = ebpf.program_mut(prog).context(prog)?.try_into()?;
        p.load()?;
        p.attach(iface, at)?;
    }
    ensure_bpffs(pin_dir)?;
    std::fs::create_dir_all(pin_dir)
        .with_context(|| format!("creating pin dir {}", pin_dir.display()))?;
    for m in PINNED_MAPS {
        ebpf.map_mut(m).context(m)?.pin(pin_dir.join(m))?;
    }
    write_map_ids(pin_dir)?;

    // Install the SIGHUP handler *before* the first apply_rules so the
    // process is never briefly running with the default disposition (which
    // is termination). This is what lets the enforcer survive `kill -HUP`
    // and treat it as "reload rules" instead of "die" — a plain
    // `std::thread::park()` loop with no signal handler would be killed by
    // the first SIGHUP, silently tearing down TCX enforcement with it.
    let mut signals = Signals::new([SIGHUP]).context("installing SIGHUP handler")?;

    apply_rules(&mut ebpf, rules_path)?;
    eprintln!("enforcer: attached on {iface}; SIGHUP reloads rules");

    for sig in signals.forever() {
        if sig == SIGHUP {
            match apply_rules(&mut ebpf, rules_path) {
                Ok(()) => {}
                Err(e) => eprintln!("enforcer: rule reload failed, keeping previous rules: {e:#}"),
            }
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct RuleSpec {
    src: String,
    dst: String,
    proto: String,
    ports: Option<[u16; 2]>,
    action: String,
}

fn parse_cidr(s: &str) -> Result<(u32, u32)> {
    let (ip, plen) = s.split_once('/').context("cidr must be ip/prefixlen")?;
    Ok((
        u32::from(ip.parse::<std::net::Ipv4Addr>()?).to_be(),
        plen.parse()?,
    ))
}

/// Parses the rules JSON file, writes it into whichever of RULES_A/RULES_B
/// is currently the *inactive* table, sets that table's RULE_LEN entry, then
/// flips ACTIVE to point at it. The flip (`active.set(0, target, 0)`) is a
/// single map update — the kernel side (`scan_rules`) reads ACTIVE exactly
/// once per packet, so every in-flight packet observes either wholly the old
/// generation or wholly the new one, never a half-written table.
fn apply_rules(ebpf: &mut Ebpf, rules_path: &std::path::Path) -> Result<()> {
    let specs: Vec<RuleSpec> = serde_json::from_slice(
        &std::fs::read(rules_path)
            .with_context(|| format!("reading rules file {}", rules_path.display()))?,
    )
    .context("parsing rules JSON")?;

    let rules: Vec<Rule> = specs
        .iter()
        .map(|s| -> Result<Rule> {
            let (src, src_plen) = parse_cidr(&s.src)?;
            let (dst, dst_plen) = parse_cidr(&s.dst)?;
            Ok(Rule {
                src,
                src_plen,
                dst,
                dst_plen,
                proto: match s.proto.as_str() {
                    "tcp" => 6,
                    "udp" => 17,
                    "icmp" => 1,
                    _ => 0, // "any" (or unrecognized -> treated as any, spike-grade)
                },
                port_lo: s.ports.map(|p| p[0]).unwrap_or(0),
                port_hi: s.ports.map(|p| p[1]).unwrap_or(0),
                action: if s.action == "allow" {
                    enforcer_common::ACT_ALLOW
                } else {
                    enforcer_common::ACT_DENY
                },
            })
        })
        .collect::<Result<_>>()?;

    if rules.len() > 64 {
        bail!("{} rules exceeds the 64-entry table capacity", rules.len());
    }

    let active_now: u32 = {
        let a: Array<&MapData, u32> = Array::try_from(ebpf.map("ACTIVE").context("ACTIVE")?)?;
        a.get(&0, 0)?
    };
    let target = 1 - active_now; // write the INACTIVE table, then flip onto it
    let table_name = if target == 0 { "RULES_A" } else { "RULES_B" };

    let mut tbl: Array<&mut MapData, Rule> =
        Array::try_from(ebpf.map_mut(table_name).context(table_name)?)?;
    for (i, r) in rules.iter().enumerate() {
        tbl.set(i as u32, *r, 0)?;
    }
    let mut len: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut("RULE_LEN").context("RULE_LEN")?)?;
    len.set(target, rules.len() as u32, 0)?;

    let mut active: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut("ACTIVE").context("ACTIVE")?)?;
    active.set(0, target, 0)?; // ATOMIC FLIP

    eprintln!("enforcer: {} rules active on table {target}", rules.len());
    Ok(())
}

fn stats(pin_dir: &std::path::Path) -> Result<()> {
    // Resolution order (see map_ids_path for the mount-ns background):
    //  1. The pinned COUNTERS map — works when we share a mount namespace
    //     (and thus the same bpffs instance) with the enforcer that pinned it.
    //  2. The pin-dir-keyed map-id file written by `run --pin-dir <same X>`,
    //     opened via the system-global BPF map id and verified to still be a
    //     map named COUNTERS (guards against id reuse after enforcer death).
    // Never falls back to enumerating loaded maps by name: with multiple
    // enforcer instances in one kernel that returns whichever loaded first —
    // silently reading the WRONG instance's counters. Loud failure beats that.
    let m = match MapData::from_pin(pin_dir.join("COUNTERS")) {
        Ok(m) => m,
        Err(pin_err) => {
            let ids_path = map_ids_path(pin_dir);
            let ids: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&ids_path).with_context(|| {
                    format!(
                        "COUNTERS not found: no pin at {} ({pin_err}) and no map-id file at {} — \
                         is an enforcer running with --pin-dir {}?",
                        pin_dir.join("COUNTERS").display(),
                        ids_path.display(),
                        pin_dir.display()
                    )
                })?,
            )
            .with_context(|| format!("parsing map-id file {}", ids_path.display()))?;
            let id = ids["COUNTERS"]
                .as_u64()
                .with_context(|| format!("no COUNTERS id in {}", ids_path.display()))?
                as u32;
            let m = MapData::from_id(id).with_context(|| {
                format!(
                    "opening map id {id} from {} — stale id file from a dead enforcer?",
                    ids_path.display()
                )
            })?;
            let name = m.info().ok().and_then(|i| i.name_as_str().map(String::from));
            if name.as_deref() != Some("COUNTERS") {
                bail!(
                    "map id {id} from {} is now {:?}, not COUNTERS — stale id file from a dead \
                     enforcer (the id was reused); restart the enforcer",
                    ids_path.display(),
                    name
                );
            }
            m
        }
    };
    let counters: Array<MapData, u64> = Array::try_from(aya::maps::Map::Array(m))?;
    let get = |i| counters.get(&i, 0).unwrap_or(0);
    println!(
        "{{\"allow\":{},\"deny\":{},\"flow_hit\":{},\"icmp_err_pass\":{}}}",
        get(0),
        get(1),
        get(2),
        get(3)
    );
    Ok(())
}
