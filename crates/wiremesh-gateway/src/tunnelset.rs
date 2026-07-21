//! A set of simultaneous boringtun `Device`s, one per own-epoch
//! (key-rotation Task 6). Each epoch is a full [`crate::tunnel::Tunnel`] —
//! the proven per-Device unit is reused verbatim, never re-implemented.
//! boringtun's UAPI control socket is keyed by the fixed path
//! `/var/run/wireguard/<ifname>.sock`, so each epoch's `Tunnel` MUST use a
//! distinct ifname (e.g. `wge0`, `wge1`): distinct ifnames give distinct
//! sockets, letting multiple Devices coexist in a single network+mount
//! namespace with no extra juggling.
//!
//! This module is purely additive: nothing in `main.rs`/`apply_state`
//! constructs or drives a `TunnelSet` yet. Wiring it into the boot/rotation
//! path (bringing up epoch n+1's Device, then flipping peer routes from the
//! old tun to the new one once the new session is live) is Task 8's job.
use crate::state::DesiredState;
use crate::tunnel::Tunnel;
use crate::uapi::{self, DeviceConfig};
use std::collections::HashMap;

#[derive(Default)]
pub struct TunnelSet {
    tunnels: HashMap<u32, Tunnel>,
}

impl TunnelSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bring up epoch `epoch`'s Device and insert it into the set. Bails if
    /// `epoch` is already present — callers must `tear_down` the existing
    /// entry first rather than silently clobbering a live Device.
    ///
    /// `Tunnel::up` only creates the boringtun `DeviceHandle` and brings the
    /// tun link up at `mtu` — it never touches UAPI (that's `Tunnel::reconcile`'s
    /// job, driven by a `DesiredState`). A freshly-created Device is otherwise
    /// unconfigured: no private key, and listening on whatever ephemeral port
    /// the kernel happened to pick. Since a new epoch's identity (private key,
    /// listen port) is known and fixed at `bring_up` time — independent of any
    /// peer set — apply it immediately via one no-peers UAPI `set`, so the
    /// Device is a real, addressable WG endpoint (`wg show` reports the right
    /// port + pubkey) as soon as `bring_up` returns, even before the first
    /// `reconcile` populates peers.
    pub fn bring_up(
        &mut self,
        epoch: u32,
        ifname: &str,
        private_key_b64: &str,
        listen_port: u16,
        mtu: u32,
    ) -> anyhow::Result<()> {
        if self.tunnels.contains_key(&epoch) {
            anyhow::bail!("epoch {epoch} already has a tunnel up; tear it down first");
        }
        let tunnel = Tunnel::up(ifname, private_key_b64, listen_port, mtu)?;
        uapi::apply(
            ifname,
            &DeviceConfig {
                private_key_b64: private_key_b64.to_string(),
                listen_port,
                peers: vec![],
            },
        )?;
        self.tunnels.insert(epoch, tunnel);
        Ok(())
    }

    /// Tear down epoch `epoch`: remove it from the map first — dropping the
    /// `Tunnel` (and its `DeviceHandle`) stops boringtun's device threads —
    /// then best-effort `ip link del <ifname>` so the tun interface doesn't
    /// linger (dropping the handle stops the device but may not delete the
    /// netlink interface itself). A missing epoch is a no-op success: tearing
    /// down something that was never up isn't an error for the caller.
    pub fn tear_down(&mut self, epoch: u32) -> anyhow::Result<()> {
        let Some(tunnel) = self.tunnels.remove(&epoch) else {
            return Ok(());
        };
        let ifname = tunnel.ifname.clone();
        drop(tunnel);
        let status = std::process::Command::new("ip")
            .args(["link", "del", &ifname])
            .status();
        if let Err(e) = status {
            eprintln!("wiremesh-gateway: best-effort `ip link del {ifname}` failed to spawn: {e}");
        }
        Ok(())
    }

    pub fn get(&self, epoch: u32) -> Option<&Tunnel> {
        self.tunnels.get(&epoch)
    }

    /// Present epochs, sorted ascending.
    pub fn epochs(&self) -> Vec<u32> {
        let mut epochs: Vec<u32> = self.tunnels.keys().copied().collect();
        epochs.sort_unstable();
        epochs
    }

    /// Apply the desired peer set to epoch `epoch`'s tun. Bails if the epoch
    /// is absent.
    pub fn reconcile(&self, epoch: u32, ds: &DesiredState, keepalive_secs: u16) -> anyhow::Result<()> {
        let tunnel = self
            .tunnels
            .get(&epoch)
            .ok_or_else(|| anyhow::anyhow!("no tunnel up for epoch {epoch}"))?;
        tunnel.reconcile(ds, keepalive_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let set = TunnelSet::new();
        assert!(set.epochs().is_empty());
        assert!(set.get(0).is_none());
    }
}
