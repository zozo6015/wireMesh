// spike/tunnel/src/main.rs
use anyhow::Result;
use boringtun::device::{DeviceConfig, DeviceHandle};

fn main() -> Result<()> {
    let ifname = std::env::args().nth(1).expect("usage: spike-tunnel <ifname>");
    let mut cfg = DeviceConfig::default();
    cfg.n_threads = 2;
    let mut handle = DeviceHandle::new(&ifname, cfg)
        .map_err(|e| anyhow::anyhow!("failed to create device {ifname}: {e:?}"))?;
    eprintln!("spike-tunnel: device {ifname} up; configure with `wg set {ifname} ...`");
    handle.wait(); // blocks until the device is torn down
    Ok(())
}
