use anyhow::{bail, Context, Result};
use aya::{
    maps::{loaded_maps, Array, MapData},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use clap::{Parser, Subcommand};

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
    for m in ["COUNTERS", "ACTIVE", "RULES_A", "RULES_B", "RULE_LEN", "FLOWS"] {
        ebpf.map_mut(m).context(m)?.pin(pin_dir.join(m))?;
    }
    apply_rules(&mut ebpf, rules_path)?; // Task 7 — scaffold: writes zero-length table
    eprintln!("enforcer: attached on {iface}; SIGHUP reloads rules");
    // SIGHUP loop added in Task 7; scaffold just parks:
    loop {
        std::thread::park();
    }
}

fn apply_rules(ebpf: &mut Ebpf, _rules_path: &std::path::Path) -> Result<()> {
    let mut len: Array<&mut MapData, u32> = Array::try_from(ebpf.map_mut("RULE_LEN").unwrap())?;
    len.set(0, 0, 0)?;
    let mut active: Array<&mut MapData, u32> = Array::try_from(ebpf.map_mut("ACTIVE").unwrap())?;
    active.set(0, 0, 0)?;
    Ok(())
}

fn stats(pin_dir: &std::path::Path) -> Result<()> {
    // Preferred path: the pinned COUNTERS map. This only works when we share
    // a mount namespace (and thus the same bpffs instance) with the enforcer
    // that pinned it. Under `ip netns exec`, every invocation gets a fresh
    // unshare(CLONE_NEWNS) + /sys remount, so the bpffs the running enforcer
    // mounted and pinned into is invisible here and each new bpffs mount is an
    // independent, empty instance. BPF object ids, however, are system-global:
    // fall back to locating the loaded map named COUNTERS by id. (Spike-grade:
    // assumes a single enforcer instance; Task 7+ can disambiguate via ifindex
    // or pin-path metadata if multiple gateways ever share a kernel.)
    let m = match MapData::from_pin(pin_dir.join("COUNTERS")) {
        Ok(m) => m,
        Err(pin_err) => {
            let info = loaded_maps()
                .filter_map(|i| i.ok())
                .find(|i| i.name_as_str() == Some("COUNTERS"))
                .with_context(|| {
                    format!(
                        "COUNTERS not found: no pin at {} ({pin_err}) and no loaded map named COUNTERS (is the enforcer running?)",
                        pin_dir.join("COUNTERS").display()
                    )
                })?;
            MapData::from_id(info.id()).context("open COUNTERS map by id")?
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
