//! Route/link/MSS programming. Shells out to `ip`/`sysctl`/`nft` — the repo's
//! established pattern (spec §3). Documented runtime deps: iproute2, nftables.
use anyhow::{anyhow, Context};
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawning {cmd} {args:?}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{cmd} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

pub fn set_link_up_mtu(ifname: &str, mtu: u32) -> anyhow::Result<()> {
    run(
        "ip",
        &["link", "set", ifname, "up", "mtu", &mtu.to_string()],
    )
}

pub fn enable_ip_forward() -> anyhow::Result<()> {
    run("sysctl", &["-w", "net.ipv4.ip_forward=1"])
}

/// Set reverse-path filtering to LOOSE (mode 2) on every interface
/// (`conf.all` + `conf.default`, whose numeric `max` with any per-interface
/// value the kernel takes — so 2 wins even where an interface is 1/strict).
///
/// A make-before-break key rotation forwards traffic ASYMMETRICALLY for a
/// brief window: once one gateway flips its send route onto the new epoch's
/// tun (`wg0e<N>`) but its peer hasn't yet flipped the reverse route, a
/// decrypted packet ingresses on `wg0e<N>` while the route back to its source
/// segment still points at `wg0` — which STRICT rp_filter (mode 1, the
/// default on many kernels) drops, silently eating flood packets exactly
/// across the cutover the zero-drop bar measures. Loose mode accepts a source
/// reachable via ANY interface, which it always is here (via the old OR new
/// tun during the overlap), closing that window. Best-effort and idempotent
/// (a plain `sysctl -w`); a forwarding gateway running loose rp_filter is
/// the correct posture, and it is strictly MORE permissive, so it never
/// changes which flows the default-deny ENFORCER (a separate mechanism) drops.
pub fn set_rp_filter_loose() -> anyhow::Result<()> {
    run("sysctl", &["-w", "net.ipv4.conf.all.rp_filter=2"])?;
    run("sysctl", &["-w", "net.ipv4.conf.default.rp_filter=2"])?;
    Ok(())
}

pub fn add_route(cidr: &str, ifname: &str) -> anyhow::Result<()> {
    // `replace` is idempotent (add-or-update).
    run("ip", &["route", "replace", cidr, "dev", ifname])
}

pub fn del_route(cidr: &str, ifname: &str) -> anyhow::Result<()> {
    let out = Command::new("ip")
        .args(["route", "del", cidr, "dev", ifname])
        .output()
        .with_context(|| format!("spawning ip route del {cidr}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A route already gone is not an error (reconcile may double-delete).
    // Verified in-container: a genuinely-missing route yields exactly
    // "RTNETLINK answers: No such process"; a bad device yields
    // "Cannot find device \"...\"" (which must still error).
    if stderr.contains("No such process") {
        return Ok(());
    }
    Err(anyhow!("ip route del {cidr} failed: {stderr}"))
}

pub fn install_mss_clamp(ifname: &str, mss: u16) -> anyhow::Result<()> {
    // Idempotent: delete any prior table, then load a fresh one.
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "wiremesh_mss"])
        .output();
    let ruleset = format!(
        "table inet wiremesh_mss {{\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority mangle;\n\
         \t\tiifname \"{ifname}\" tcp flags syn tcp option maxseg size set {mss}\n\
         \t\toifname \"{ifname}\" tcp flags syn tcp option maxseg size set {mss}\n\
         \t}}\n\
         }}\n"
    );
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning nft -f -")?;
    {
        use std::io::Write;
        // Drop the stdin handle before waiting, to avoid a pipe deadlock
        // if nft writes enough stderr to fill its pipe buffer.
        child.stdin.take().unwrap().write_all(ruleset.as_bytes())?;
    }
    let out = child.wait_with_output().context("waiting on nft")?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft load of wiremesh_mss failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}
