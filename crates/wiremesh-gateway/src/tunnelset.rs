//! A set of simultaneous boringtun `Device`s, one per live [`TunnelId`]
//! (key-rotation Task 6, re-keyed by T3). Each entry is a full
//! [`crate::tunnel::Tunnel`] — the proven per-Device unit is reused verbatim,
//! never re-implemented. boringtun's UAPI control socket is keyed by the fixed
//! path `/var/run/wireguard/<ifname>.sock`, so each Device MUST use a distinct
//! ifname: distinct ifnames give distinct sockets, letting multiple Devices
//! coexist in a single network+mount namespace with no extra juggling.
//!
//! # Why the key is a [`TunnelId`] and not a bare epoch number (T3)
//!
//! Until T3 this map was keyed by `u32` — and that number meant **two
//! different things**. Role A (this gateway rotating its own key) inserted
//! under *its own* new epoch; Role B (an overlap Device toward a rotating
//! PEER) inserted under the *peer's pending* epoch. Both derived the ifname
//! (`{base}e{n}`) and the listen port (`base + delta`) from that same number,
//! so all three axes collided the moment the two epoch numbers coincided —
//! which the controller's `initiate_due_rotations` makes the DEFAULT case, not
//! an edge case: it walks every active gateway off one global 30-day timer, so
//! the whole fabric marches N -> N+1 in the same tick. `bring_up` then bailed
//! on the duplicate and the caller's `?` aborted its whole peer loop: neither
//! side overlapped, neither acked, neither flipped, and the controller
//! grace-promoted a dead key anyway. See
//! `docs/research/key-rotation-plan-verification.md` (headline + F3/F8).
//!
//! Jitter is not a mitigation — the defect is one number meaning two things,
//! so an in-step fabric collides regardless of timing. [`TunnelId`] makes the
//! two meanings distinct kinds of key, and [`plan_tunnel`] derives the ifname
//! and the listen port from that id together, so a plan cannot come out
//! half-de-collided (distinct key, shared port).
//!
//! Role A's `{base}e{n}` naming survives unchanged — an own-epoch number was
//! always unique among our own tuns, so it was never the broken half. It is
//! the overlap side that moves, into its own `{base}o{slot}` namespace.
use crate::state::DesiredState;
use crate::tunnel::Tunnel;
use crate::uapi::{self, DeviceConfig};
use anyhow::Context;
use std::collections::HashMap;

/// Identity of one live Device in a [`TunnelSet`]. Replaces the bare `u32`
/// epoch, which conflated our own epochs with peers' pending epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TunnelId {
    /// This gateway's own key epoch (the boot/active tun, or Role A's new one).
    Own { epoch: u32 },
    /// A transient Role-B overlap Device toward peer `gateway_id`'s pending
    /// epoch `epoch`. Runs OUR active key; the epoch is THEIRS.
    Overlap { gateway_id: u64, epoch: u32 },
}

/// The three per-Device resources a tun needs, derived together by
/// [`plan_tunnel`] so they cannot drift apart: map key, interface name, WG
/// listen port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPlan {
    pub id: TunnelId,
    pub ifname: String,
    pub listen_port: u16,
}

/// Suffix marker for one of THIS gateway's own epochs: `wg0` + `e` + the
/// epoch number, i.e. `wg0e1` — the pre-T3 convention, kept verbatim. It was
/// never the broken half: an own-epoch number is unique among our own tuns by
/// construction.
const OWN_MARK: char = 'e';

/// Suffix marker for a Role-B overlap: `wg0` + `o` + a slot index, i.e.
/// `wg0o0`. A DIFFERENT letter from [`OWN_MARK`], which is the whole
/// de-collision on the name axis — the two kinds of tun now live in literally
/// disjoint namespaces, so `Own { epoch: 2 }` and `Overlap { .., epoch: 2 }`
/// cannot produce the same name no matter what the epoch numbers do.
const OVERLAP_MARK: char = 'o';

/// Upper bound on both the overlap-slot search and the rotation port window
/// (`base_port + 1 ..= base_port + MAX_ROTATION_TUNS`). A slot is only
/// occupied while a rotation Device is LIVE, and the live set is at most "our
/// own new tun + one overlap per rotating peer", so 64 is far beyond any
/// plausible fan-out for a single gateway while keeping the port range small
/// enough to stay inside a conventional firewall allowance. Exhausting it is a
/// hard error, never a silent wrap onto an in-use port.
const MAX_ROTATION_TUNS: u16 = 64;

/// Derive the plan for `id` against everything already live (`live`), which
/// the returned plan must not collide with on ANY of the three axes. Pure: no
/// I/O, no devices, safe to call anywhere.
///
/// # The scheme (owner decision E)
///
/// **Name: disjoint namespaces per kind. Port: allocated from what is free.**
///
///  - `Own { epoch: n }` keeps the shipped `{base}e{n}` — an own-epoch number
///    is already unique among our own tuns, the name stays self-describing in
///    `ip link`/logs/runbooks, and Role A's field behaviour is unchanged.
///  - `Overlap { .. }` becomes `{base}o{slot}`, the lowest slot index free in
///    `live`. The `o`/`e` split is what makes the two kinds structurally
///    incapable of sharing a name, rather than merely unlikely to.
///  - The listen port is the lowest value in `base_port + 1 ..=
///    base_port + MAX_ROTATION_TUNS` that no live plan holds.
///
/// The shipped scheme derived ALL THREE axes from a bare epoch number that
/// meant our own epoch for Role A and the peer's pending epoch for Role B, so
/// an in-step fabric collided on all three at once. Note that neither half of
/// the fix could be a pure derivation from the identity:
///
///  - **The name could not carry the peer id.** The kernel's `IFNAMSIZ` is 15
///    bytes + NUL ([`wiremesh_enforcer::validate_iface`]). A `{base}p{gid}e{n}`
///    form spends 3 + 1 + 3 + 1 + 2 = 10 bytes on the conventional `wg0` for
///    just a three-digit gateway id and a two-digit epoch — and `gateway_id`
///    is a `u64` the gateway does not choose. The slot index is bounded by the
///    number of *simultaneously live* overlaps instead, which is small by
///    construction: `wg0o0` is 5 bytes and the worst case here is 7.
///  - **The port could not be derived at all.** It would need an injection
///    from `(u64, u32)` into the handful of `u16` values near the base port;
///    no such function exists. Any correct port scheme is an allocator, and an
///    allocator has to be told what is taken.
///
/// That is why `live` is load-bearing rather than decorative: the boot tun is
/// NOT planned (it is `base_tun` at `base_port` by definition, `main.rs`'s
/// boot `bring_up`, OD-1), so being told what is up is the only way to honour
/// F8's "don't collide with the active tun".
///
/// Returns `Err` rather than emitting an ifname the kernel or `validate_iface`
/// would reject (a too-long name otherwise surfaces only as a late, opaque
/// tc-attach failure, after the Device is half-built), and `Err` rather than
/// wrapping when the slot or port window is exhausted.
///
/// **Plan once, keep the plan.** Re-planning an `id` that is already in `live`
/// is a caller bug and is reported as one for `Own` (its name is already
/// taken); callers hold onto the plan they were given
/// (`RoleA::new_tun`/`RoleB::new_tun`) rather than re-deriving it, which is
/// also what keeps teardown addressing the Device that was actually brought up.
pub fn plan_tunnel(
    id: TunnelId,
    base_tun: &str,
    base_port: u16,
    live: &[TunnelPlan],
) -> anyhow::Result<TunnelPlan> {
    let ifname = plan_ifname(id, base_tun, live)?;
    let listen_port = plan_port(base_port, live).ok_or_else(|| {
        anyhow::anyhow!(
            "no free rotation listen port for {id:?}: every port in {}..={} is held by one of \
             the {} live tun(s) (rotation tuns are not being torn down), or the window overflows \
             u16",
            base_port.saturating_add(1),
            base_port.saturating_add(MAX_ROTATION_TUNS),
            live.len(),
        )
    })?;
    Ok(TunnelPlan { id, ifname, listen_port })
}

/// The name axis of [`plan_tunnel`]. Every returned name is
/// `validate_iface`-clean, distinct from `base_tun`, and distinct from every
/// name in `live`.
fn plan_ifname(id: TunnelId, base_tun: &str, live: &[TunnelPlan]) -> anyhow::Result<String> {
    let taken = |name: &str| live.iter().any(|p| p.ifname == name);
    match id {
        TunnelId::Own { epoch } => {
            let ifname = format!("{base_tun}{OWN_MARK}{epoch}");
            wiremesh_enforcer::validate_iface(&ifname).with_context(|| {
                format!(
                    "deriving an own-epoch tun name for epoch {epoch} from base tun \
                     {base_tun:?} (shorten --tun)"
                )
            })?;
            if taken(&ifname) {
                anyhow::bail!(
                    "own-epoch tun name {ifname:?} is already live — {id:?} has already been \
                     planned and brought up; keep the original plan rather than re-deriving it"
                );
            }
            Ok(ifname)
        }
        TunnelId::Overlap { .. } => {
            for slot in 0..MAX_ROTATION_TUNS {
                let ifname = format!("{base_tun}{OVERLAP_MARK}{slot}");
                // Names only get LONGER as the slot index grows, and an
                // invalid base is invalid at every slot, so no later slot can
                // recover from a rejection here.
                if let Err(e) = wiremesh_enforcer::validate_iface(&ifname) {
                    return Err(e).with_context(|| {
                        format!(
                            "deriving an overlap tun name for {id:?} from base tun {base_tun:?} \
                             (shorten --tun)"
                        )
                    });
                }
                if !taken(&ifname) {
                    return Ok(ifname);
                }
            }
            anyhow::bail!(
                "all {MAX_ROTATION_TUNS} overlap tun slots on base tun {base_tun:?} are occupied; \
                 cannot name an overlap for {id:?} (overlap Devices are not being torn down)"
            )
        }
    }
}

/// The port axis of [`plan_tunnel`]: the lowest port above `base_port`, within
/// the rotation window, that no live plan holds. `None` when the window is
/// exhausted or overflows `u16`.
fn plan_port(base_port: u16, live: &[TunnelPlan]) -> Option<u16> {
    (1..=MAX_ROTATION_TUNS)
        .filter_map(|off| base_port.checked_add(off))
        .find(|port| !live.iter().any(|p| p.listen_port == *port))
}

#[derive(Default)]
pub struct TunnelSet {
    tunnels: HashMap<TunnelId, Tunnel>,
}

impl TunnelSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bring `id`'s Device up and insert it into the set. Bails if `id` is
    /// already present, or if `ifname`/`listen_port` are already taken by a
    /// DIFFERENT live entry — callers must `tear_down` the existing entry
    /// first rather than silently clobbering a live Device. All three axes are
    /// checked, not just the key: a caller that de-collided the key but reused
    /// a name or a port would otherwise get an opaque failure from netlink (or
    /// worse, a second Device quietly fighting the first over a UDP port).
    ///
    /// `Tunnel::up` only creates the boringtun `DeviceHandle` and brings the
    /// tun link up at `mtu` — it never touches UAPI (that's `Tunnel::reconcile`'s
    /// job, driven by a `DesiredState`). A freshly-created Device is otherwise
    /// unconfigured: no private key, and listening on whatever ephemeral port
    /// the kernel happened to pick. Since a new Device's identity (private key,
    /// listen port) is known and fixed at `bring_up` time — independent of any
    /// peer set — apply it immediately via one no-peers UAPI `set`, so the
    /// Device is a real, addressable WG endpoint (`wg show` reports the right
    /// port + pubkey) as soon as `bring_up` returns, even before the first
    /// `reconcile` populates peers.
    pub fn bring_up(
        &mut self,
        id: TunnelId,
        ifname: &str,
        private_key_b64: &str,
        listen_port: u16,
        mtu: u32,
    ) -> anyhow::Result<()> {
        if self.tunnels.contains_key(&id) {
            anyhow::bail!("{id:?} already has a tunnel up; tear it down first");
        }
        if let Some((other, t)) = self
            .tunnels
            .iter()
            .find(|(_, t)| t.ifname == ifname || t.listen_port == listen_port)
        {
            anyhow::bail!(
                "{id:?} would collide with the live {other:?} ({} on port {}): requested ifname \
                 {ifname:?} on port {listen_port}",
                t.ifname,
                t.listen_port
            );
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
        self.tunnels.insert(id, tunnel);
        Ok(())
    }

    /// Tear `id` down: remove it from the map first — dropping the `Tunnel`
    /// (and its `DeviceHandle`) stops boringtun's device threads — then
    /// best-effort `ip link del <ifname>` so the tun interface doesn't linger
    /// (dropping the handle stops the device but may not delete the netlink
    /// interface itself). A missing `id` is a no-op success: tearing down
    /// something that was never up isn't an error for the caller.
    pub fn tear_down(&mut self, id: TunnelId) -> anyhow::Result<()> {
        let Some(tunnel) = self.tunnels.remove(&id) else {
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

    pub fn get(&self, id: TunnelId) -> Option<&Tunnel> {
        self.tunnels.get(&id)
    }

    /// Present ids, sorted (`Own` before `Overlap`, then by epoch / peer).
    pub fn ids(&self) -> Vec<TunnelId> {
        let mut ids: Vec<TunnelId> = self.tunnels.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// What is currently live, in the shape [`plan_tunnel`] consumes — the
    /// authoritative "don't collide with these" input. Includes the boot tun
    /// (`base_tun` at `base_port`), which is never itself planned, which is
    /// exactly why the planner has to be handed this rather than deriving it.
    /// Sorted by id so the allocation is deterministic for a given live set.
    pub fn plans(&self) -> Vec<TunnelPlan> {
        let mut plans: Vec<TunnelPlan> = self
            .tunnels
            .iter()
            .map(|(id, t)| TunnelPlan {
                id: *id,
                ifname: t.ifname.clone(),
                listen_port: t.listen_port,
            })
            .collect();
        plans.sort_unstable_by_key(|p| p.id);
        plans
    }

    /// Apply the desired peer set to `id`'s tun. Bails if it is absent.
    /// Keepalive is not a parameter — `Tunnel::reconcile` builds via
    /// `reconcile::device_config`, which emits the always-on
    /// `uapi::PERSISTENT_KEEPALIVE_SECS` on every peer (fix T1).
    pub fn reconcile(&self, id: TunnelId, ds: &DesiredState) -> anyhow::Result<()> {
        let tunnel = self
            .tunnels
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("no tunnel up for {id:?}"))?;
        tunnel.reconcile(ds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let set = TunnelSet::new();
        assert!(set.ids().is_empty());
        assert!(set.get(TunnelId::Own { epoch: 0 }).is_none());
    }
}
