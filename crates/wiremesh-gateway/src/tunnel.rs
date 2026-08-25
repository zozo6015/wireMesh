//! Embedded boringtun tunnel manager (spec §5.2). Owns the WG device; applies
//! the desired peer set through the in-process UAPI writer.
use crate::reconcile;
use crate::routes;
use crate::state::DesiredState;
use crate::uapi;
use anyhow::{anyhow, Context};
use boringtun::device::{DeviceConfig as BtDeviceConfig, DeviceHandle};
use std::path::Path;
use std::time::{Duration, Instant};

pub struct Tunnel {
    _handle: DeviceHandle,
    pub ifname: String,
    pub private_key_b64: String,
    pub listen_port: u16,
}

impl Tunnel {
    pub fn up(
        ifname: &str,
        private_key_b64: &str,
        listen_port: u16,
        mtu: u32,
    ) -> anyhow::Result<Tunnel> {
        // `..Default::default()` is required, not decorative: `DeviceConfig` has
        // `#[cfg(target_os = "linux")]` fields (`use_multi_queue`, `uapi_fd`),
        // so the set of fields is platform-dependent and cannot be written out.
        let cfg = BtDeviceConfig {
            n_threads: 2,
            ..Default::default()
        };
        let handle = DeviceHandle::new(ifname, cfg)
            .map_err(|e| anyhow!("creating boringtun device {ifname}: {e:?}"))?;

        // Wait for the UAPI socket to appear before configuring.
        let sock = format!("/var/run/wireguard/{ifname}.sock");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !Path::new(&sock).exists() {
            if Instant::now() > deadline {
                return Err(anyhow!("WG UAPI socket {sock} did not appear"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        routes::set_link_up_mtu(ifname, mtu).context("bringing tun up at MTU")?;

        Ok(Tunnel {
            _handle: handle,
            ifname: ifname.to_string(),
            private_key_b64: private_key_b64.to_string(),
            listen_port,
        })
    }

    /// Apply the desired peer set. The steady-state keepalive
    /// (`uapi::PERSISTENT_KEEPALIVE_SECS`) is baked into
    /// `reconcile::device_config` rather than passed through here
    /// (mesh-convergence fix T1 — see that builder's doc for the finding §5
    /// rationale), so no caller can reconcile a device without it.
    pub fn reconcile(&self, ds: &DesiredState) -> anyhow::Result<()> {
        let dev = reconcile::device_config(ds, &self.private_key_b64, self.listen_port);
        uapi::apply(&self.ifname, &dev)
    }
}
