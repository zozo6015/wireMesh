// spike/keyrot/src/main.rs
//
// Generic "bring up one embedded-boringtun WireGuard device on <ifname>" process,
// identical in spirit to spike/tunnel's binary. The key-rotation choreography
// (which keys, which ports, which routes, when) lives entirely in the test so it
// can drive a make-before-break rotation across FOUR of these devices (two per
// gateway during the overlap window). Each device opens its OWN tun (<ifname>)
// and its OWN UAPI socket (/var/run/wireguard/<ifname>.sock) and is configured
// externally via `wg set <ifname> ...` — see tests/rotate.rs.
use anyhow::Result;
use boringtun::device::{DeviceConfig, DeviceHandle};

fn main() -> Result<()> {
    let ifname = std::env::args().nth(1).expect("usage: keyrot-dev <ifname>");
    let mut cfg = DeviceConfig::default();
    cfg.n_threads = 2;
    let mut handle = DeviceHandle::new(&ifname, cfg)
        .map_err(|e| anyhow::anyhow!("failed to create device {ifname}: {e:?}"))?;
    eprintln!("keyrot-dev: device {ifname} up; configure via `wg set {ifname} ...`");
    handle.wait(); // blocks until the process is killed (DeviceHandle drop tears down the tun)
    Ok(())
}
