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
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

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
///
/// # How the reserved own-epoch slot divides the window (piece 3)
///
/// The window holds at most `MAX_ROTATION_TUNS` rotation tuns, which is exactly
/// what the paragraph above describes ("our own new tun + one overlap per
/// rotating peer"): ONE of those 64 ports is [`OWN_TUN_PORT_OFFSET`], reserved
/// for the own-epoch tun and never free-listed, and the remaining 63 —
/// `base_port + 2 ..= base_port + MAX_ROTATION_TUNS` — are the overlap
/// free-list. The port axis is therefore the binding constraint one overlap
/// EARLIER than the name axis ([`plan_ifname`] still searches 64 slots): with
/// 63 overlaps live, a 64th gets a free NAME and then fails on the port. That
/// is a hard error with an explicit message, not a wrap, so the ordering costs
/// a clearer diagnostic and nothing else — and shrinking the name search to 63
/// to match would be the strictly worse trade, since it would report a
/// name-space exhaustion for what is really a port-window exhaustion.
const MAX_ROTATION_TUNS: u16 = 64;

/// The offset from the base WireGuard port at which THIS gateway's own
/// new-epoch tun ([`TunnelId::Own`]) always listens. **Reserved, not
/// allocated** — the whole of piece 3 of the port-authority fix
/// (`docs/research/port-authority-verification-the-shape-was-wrong.md`).
///
/// # Why a reservation and not the lowest free port
///
/// A rotating gateway's peer has to write down an endpoint for the gateway's
/// in-flight new epoch (`reconcile::pending_peer_configs`) and CANNOT ask where
/// it is: the roster carries a pubkey and the peer's advertised candidate, not
/// a per-epoch port. So the two sides can only meet on a value both compute
/// from the same rule. Before this, one side free-listed (`plan_port`'s lowest
/// free) and the other computed `active_port + (pending_epoch - active_epoch)`;
/// they agreed on rotation 0 -> 1 and on nothing after that (bug 5).
///
/// With piece 2's renormalization holding — the active key is back on the base
/// port before any next rotation is planned — a reserved offset makes the
/// answer EPOCH-INDEPENDENT and identical on both sides: the new-epoch tun is
/// at `base + 1`, and a peer dials `candidate_port + 1`. That is why
/// `pending_peer_configs` imports this very constant rather than re-deriving
/// the number: one definition, two readers, no formula to drift.
///
/// # Why this is allowed to be a hard failure
///
/// If the reserved port is not free, the new epoch would have to listen
/// somewhere no peer can predict — i.e. an unreachable new epoch, which is bug
/// 5 exactly. [`plan_port`] therefore refuses rather than falling back, so a
/// broken invariant aborts the rotation loudly instead of completing a rotation
/// nobody can reach. The one case that reaches it in practice is a
/// renormalization that failed (logged CRITICAL at the time), which leaves the
/// active key sitting on this very port.
///
/// # Interaction with [`QUARANTINE`]
///
/// Nothing on the healthy path ever quarantines this port. `service_retire`
/// tears down the OLD epoch's Device, which by the invariant is on the BASE
/// port, and then `TunnelSet::set_listen_port` moves the survivor off
/// `base + 1` by REBINDING it — a live rebind, so the vacated port is
/// deliberately NOT quarantined (there is no link deletion or UAPI-socket
/// unlink to race, which is the only thing [`QUARANTINE`] exists to cover), and
/// it is free for the next rotation immediately. The sole path that can
/// quarantine it is a rotation whose own-epoch tun was brought up and then torn
/// straight back down by `handle_rotate`'s fail-closed unwind; that holds the
/// port for at most [`QUARANTINE`] and expires on its own, so a reserved slot
/// and the quarantine cannot wedge each other.
pub const OWN_TUN_PORT_OFFSET: u16 = 1;

/// How long a torn-down rotation tun's ifname AND listen port stay reserved
/// against re-allocation (F6).
///
/// # Why a freed slot cannot be handed straight back
///
/// [`plan_ifname`] hands back the LOWEST free overlap slot and [`plan_port`]
/// the lowest free port, so before this existed a teardown followed by an
/// allocation returned the very name and port that had just been released. On
/// the [`crate::rotation::RoleBDecision::Restart`] path those two run
/// back-to-back with no `.await` between them (`retire_stale_overlap` ->
/// `plan_tunnel` -> `bring_up`), i.e. microseconds apart, and neither half of
/// the teardown is synchronous:
///
///  - dropping the `Tunnel` stops boringtun's device threads, but the UAPI
///    socket `/var/run/wireguard/<ifname>.sock` is not necessarily unlinked by
///    the time the next `Tunnel::up` starts POLLING FOR THAT EXACT PATH to
///    appear — a stale socket satisfies that wait instantly, and the caller
///    then talks UAPI to a dead listener;
///  - `ip link del` is spawned best-effort and the kernel may still be
///    tearing the tun down (or the command may have failed outright, which is
///    only logged), so `DeviceHandle::new` on the same name races a device
///    that still exists.
///
/// Five seconds is far longer than either the kernel's link deletion or
/// boringtun's socket cleanup, and 25x the 200ms rotation tick, so a reused
/// name/port is always separated from its predecessor by many ticks rather
/// than by microseconds.
const QUARANTINE: Duration = Duration::from_secs(5);

/// Hard ceiling on simultaneously-quarantined entries, so the quarantine can
/// never eat the allocation window that [`MAX_ROTATION_TUNS`] bounds. At half
/// the window, at least 32 slots and 32 ports are always allocatable no matter
/// how hard the gateway churns; the OLDEST entry is evicted first, i.e. the one
/// whose Device has been down longest and is therefore likeliest to be gone.
/// Expiry does the work in every realistic case (a burst would have to tear
/// down more than 32 rotation tuns inside [`QUARANTINE`]); this only ensures
/// the failure mode of an implausible burst is "reuse sooner" rather than
/// "cannot allocate at all".
const MAX_QUARANTINE: usize = (MAX_ROTATION_TUNS / 2) as usize;

/// Derive the plan for `id` against everything already reserved (`live`), which
/// the returned plan must not collide with on ANY of the three axes. Pure: no
/// I/O, no devices, safe to call anywhere.
///
/// `live` is whatever the caller declares reserved. In production that is
/// [`TunnelSet::plans`], which reports live Devices AND recently torn-down ones
/// still inside [`QUARANTINE`] — so this allocator never needs to know about
/// time to stop handing a just-freed ifname/port straight back (F6).
///
/// # The scheme (owner decision E)
///
/// **Name: disjoint namespaces per kind. Port: disjoint RANGES per kind.**
///
///  - `Own { epoch: n }` keeps the shipped `{base}e{n}` — an own-epoch number
///    is already unique among our own tuns, the name stays self-describing in
///    `ip link`/logs/runbooks, and Role A's field behaviour is unchanged.
///  - `Overlap { .. }` becomes `{base}o{slot}`, the lowest slot index free in
///    `live`. The `o`/`e` split is what makes the two kinds structurally
///    incapable of sharing a name, rather than merely unlikely to.
///  - `Own`'s listen port is the RESERVED `base_port + OWN_TUN_PORT_OFFSET` —
///    never free-listed, because a rotating peer has to compute it without
///    being told (piece 3; see [`OWN_TUN_PORT_OFFSET`]). `Overlap`'s is the
///    lowest value in `base_port + OWN_TUN_PORT_OFFSET + 1 ..= base_port +
///    MAX_ROTATION_TUNS` that no live plan holds. The two ranges are disjoint,
///    so an overlap can never occupy the port a peer will dial our new epoch
///    at — which as ONE shared free list it could, and did.
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
///  - **An OVERLAP's port could not be derived at all.** It would need an
///    injection from `(u64, u32)` into the handful of `u16` values near the
///    base port; no such function exists. Any correct overlap port scheme is
///    an allocator, and an allocator has to be told what is taken. (An OWN
///    tun's port is a different problem with a different answer: there is at
///    most one own new-epoch tun at a time, so it needs no injection — just a
///    reserved constant. That asymmetry is why the two kinds get two ranges.)
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
    let listen_port = plan_port(id, base_port, live).ok_or_else(|| match id {
        // The own-epoch slot is RESERVED, so its failure is never "the window
        // filled up" — it is "the one port a peer will dial our new epoch at is
        // occupied", which is a different (and much more serious) fault and
        // must not be reported as capacity pressure.
        TunnelId::Own { .. } => anyhow::anyhow!(
            "the reserved own-epoch listen port for {id:?} (base {base_port} + \
             {OWN_TUN_PORT_OFFSET}) is not available: it is held by one of the {} reserved \
             tun(s), or it overflows u16. This port is NOT free-listed — a rotating peer \
             computes it as `candidate_port + {OWN_TUN_PORT_OFFSET}` and cannot be told any \
             other value, so a new epoch anywhere else would be unreachable. The usual cause is \
             a listen-port renormalization that failed at the previous retire (logged CRITICAL \
             at the time), leaving the ACTIVE key parked on this port",
            live.len(),
        ),
        TunnelId::Overlap { .. } => anyhow::anyhow!(
            "no free overlap listen port for {id:?}: every port in {}..={} is held by one of \
             the {} reserved tun(s) (overlap Devices are not being torn down, or too many are \
             in post-teardown quarantine), or the window overflows u16. Note {} is reserved for \
             this gateway's own new-epoch tun and is never handed to an overlap",
            base_port.saturating_add(OWN_TUN_PORT_OFFSET + 1),
            base_port.saturating_add(MAX_ROTATION_TUNS),
            live.len(),
            base_port.saturating_add(OWN_TUN_PORT_OFFSET),
        ),
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
                    "own-epoch tun name {ifname:?} is already reserved — {id:?} has already been \
                     planned and brought up (or was torn down so recently that its name is still \
                     quarantined); keep the original plan rather than re-deriving it"
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
                "all {MAX_ROTATION_TUNS} overlap tun slots on base tun {base_tun:?} are reserved; \
                 cannot name an overlap for {id:?} (overlap Devices are not being torn down, or \
                 more than half the window is in post-teardown quarantine)"
            )
        }
    }
}

/// The port axis of [`plan_tunnel`]. **Two disjoint ranges, one per kind of
/// tun** (piece 3) — deliberately not one shared free list:
///
///  - [`TunnelId::Own`] takes the RESERVED `base_port + OWN_TUN_PORT_OFFSET`,
///    always, or fails. See [`OWN_TUN_PORT_OFFSET`] for why a peer has to be
///    able to compute this without being told, and why a fallback would be
///    worse than a refusal.
///  - [`TunnelId::Overlap`] free-lists the lowest free port from
///    `base_port + OWN_TUN_PORT_OFFSET + 1` up to `base_port +
///    MAX_ROTATION_TUNS`, exactly as before minus the reserved slot.
///
/// Sharing one free list is what made the two sides' agreement a coincidence
/// rather than a property: on rotation 1 -> 2 the own tun got `base + 1` only
/// while no overlap had taken it first, and an overlap taking it first is
/// ordinary (a peer that rotates before we do). Splitting the ranges is what
/// makes an overlap structurally incapable of standing on the port a peer will
/// dial our new epoch at.
///
/// `None` when the range is exhausted or the port would overflow `u16`.
fn plan_port(id: TunnelId, base_port: u16, live: &[TunnelPlan]) -> Option<u16> {
    let taken = |port: u16| live.iter().any(|p| p.listen_port == port);
    match id {
        TunnelId::Own { .. } => {
            let port = base_port.checked_add(OWN_TUN_PORT_OFFSET)?;
            (!taken(port)).then_some(port)
        }
        TunnelId::Overlap { .. } => (OWN_TUN_PORT_OFFSET + 1..=MAX_ROTATION_TUNS)
            .filter_map(|off| base_port.checked_add(off))
            .find(|port| !taken(*port)),
    }
}

#[derive(Default)]
pub struct TunnelSet {
    tunnels: HashMap<TunnelId, Tunnel>,
    /// Recently torn-down rotation tuns, oldest first, each with the instant it
    /// was released. [`Self::plans`] reports them alongside the live set so the
    /// planner treats their ifname and port as taken for [`QUARANTINE`] — see
    /// that constant for why an immediately-reused name/port is a real defect
    /// rather than an aesthetic one.
    quarantine: VecDeque<(TunnelPlan, Instant)>,
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
        // Whatever this Device now holds is LIVE, so any quarantine reservation
        // that named the same id, ifname or port is stale and must not keep
        // being reported as taken on top of the live entry. (A caller reaching
        // here with a quarantined name did not get it from `plan_tunnel` — the
        // boot tun, or a test — but the bookkeeping has to stay honest either
        // way, or `plans()` would report the same resource twice.)
        self.quarantine
            .retain(|(p, _)| p.id != id && p.ifname != ifname && p.listen_port != listen_port);
        self.tunnels.insert(id, tunnel);
        Ok(())
    }

    /// Drop quarantine entries whose [`QUARANTINE`] window has elapsed, then
    /// evict oldest-first down to [`MAX_QUARANTINE`].
    fn prune_quarantine(&mut self) {
        let now = Instant::now();
        self.quarantine
            .retain(|(_, freed)| now.duration_since(*freed) < QUARANTINE);
        while self.quarantine.len() > MAX_QUARANTINE {
            self.quarantine.pop_front();
        }
    }

    /// Tear `id` down: remove it from the map first — dropping the `Tunnel`
    /// (and its `DeviceHandle`) stops boringtun's device threads — then
    /// best-effort `ip link del <ifname>` so the tun interface doesn't linger
    /// (dropping the handle stops the device but may not delete the netlink
    /// interface itself). A missing `id` is a no-op success: tearing down
    /// something that was never up isn't an error for the caller.
    ///
    /// The released ifname + port then enter [`QUARANTINE`], so the next
    /// allocation cannot hand them straight back while the kernel is still
    /// deleting the link and boringtun is still unlinking the UAPI socket (F6).
    /// The quarantine is what makes `ip link del`'s best-effort posture
    /// tolerable: a delete that fails, or that has not finished, no longer
    /// hands the very next allocation a name that is still occupied.
    pub fn tear_down(&mut self, id: TunnelId) -> anyhow::Result<()> {
        let Some(tunnel) = self.tunnels.remove(&id) else {
            return Ok(());
        };
        let ifname = tunnel.ifname.clone();
        let listen_port = tunnel.listen_port;
        drop(tunnel);
        match std::process::Command::new("ip")
            .args(["link", "del", &ifname])
            .status()
        {
            Err(e) => eprintln!(
                "wiremesh-gateway: best-effort `ip link del {ifname}` failed to spawn: {e} — the \
                 link may linger; its name and port stay quarantined"
            ),
            // A non-zero exit was previously discarded entirely. It is still
            // not fatal (the interface may already be gone), but it is the
            // exact condition under which the name is still occupied, so it
            // must at least be visible.
            Ok(st) if !st.success() => eprintln!(
                "wiremesh-gateway: best-effort `ip link del {ifname}` exited {st} — the link may \
                 linger; its name and port stay quarantined"
            ),
            Ok(_) => {}
        }
        self.quarantine
            .push_back((TunnelPlan { id, ifname, listen_port }, Instant::now()));
        self.prune_quarantine();
        Ok(())
    }

    /// Move a LIVE Device's WireGuard listen port — on the device AND in this
    /// set's bookkeeping, in one call, so the two cannot drift.
    ///
    /// # Why this exists (port-authority fix, piece 2)
    ///
    /// After a Role-A cutover the surviving active Device sits on a rotation
    /// offset port permanently (OD-1) and every durable way the fabric
    /// addresses this gateway is base-port by construction. `service_retire`
    /// calls this the moment the old epoch's Device is gone, putting the
    /// survivor back on the base port — which is what makes a peer's in-flight
    /// new-epoch tun land at a predictable offset again instead of drifting one
    /// port further away on every rotation. See
    /// `docs/research/port-authority-verification-the-shape-was-wrong.md`.
    ///
    /// # Why the bookkeeping half is not optional
    ///
    /// [`Self::plans`] is the ONLY input [`plan_tunnel`] has about what is
    /// taken, and [`Tunnel::reconcile`] renders `listen_port` into a FULL
    /// (`replace_peers=true`, session-destructive) device config. A recorded
    /// port left describing a port the Device no longer holds would therefore
    /// both misdirect the next rotation's allocation and arm a rebuild that
    /// silently moves the Device back.
    ///
    /// The device write goes first: if it fails, the record is left untouched
    /// and the caller can decline to publish the new port anywhere else. Note
    /// that "untouched" is a bookkeeping guarantee only — a failed
    /// [`uapi::set_listen_port`] can leave the Device bound to NO port at all
    /// (see its failure-posture section), so the retained record is not a
    /// promise the Device is still reachable on it. A no-op when the Device is
    /// already on `port`; an error (with the record untouched) when `id` is
    /// absent or a DIFFERENT live entry already holds `port` — this never
    /// silently evicts another Device from a port.
    pub fn set_listen_port(&mut self, id: TunnelId, port: u16) -> anyhow::Result<()> {
        let (ifname, current) = {
            let tunnel = self.tunnels.get(&id).ok_or_else(|| {
                anyhow::anyhow!("no tunnel up for {id:?}; cannot move it to listen port {port}")
            })?;
            (tunnel.ifname.clone(), tunnel.listen_port)
        };
        if current == port {
            return Ok(());
        }
        if let Some((other, t)) =
            self.tunnels.iter().find(|(k, t)| **k != id && t.listen_port == port)
        {
            anyhow::bail!(
                "cannot move {id:?} ({ifname}) to listen port {port}: the live {other:?} ({}) \
                 already holds it",
                t.ifname
            );
        }
        uapi::set_listen_port(&ifname, port)?;
        self.tunnels
            .get_mut(&id)
            .expect("presence checked immediately above, and &mut self excludes concurrent removal")
            .listen_port = port;
        // The port is LIVE again, so a quarantine entry still reserving it is
        // stale — exactly the hygiene `bring_up` performs for the same reason.
        // Releasing that entry's IFNAME claim alongside it is harmless: every
        // name `plan_ifname` can hand out is `{base}e{n}` or `{base}o{slot}`,
        // and the entry being dropped here is the tun that just VACATED this
        // port, i.e. a retired own-epoch tun whose epoch number is never
        // re-planned.
        self.quarantine.retain(|(p, _)| p.listen_port != port);
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

    /// What is currently RESERVED, in the shape [`plan_tunnel`] consumes — the
    /// authoritative "don't collide with these" input. Includes the boot tun
    /// (`base_tun` at `base_port`), which is never itself planned, which is
    /// exactly why the planner has to be handed this rather than deriving it.
    /// Sorted so the allocation is deterministic for a given reserved set.
    ///
    /// Reserved is deliberately WIDER than live: it is the live Devices PLUS
    /// every still-quarantined teardown ([`QUARANTINE`], F6). The planner is a
    /// pure lowest-free-index allocator over exactly this list, so putting the
    /// quarantine in here — rather than teaching the planner about time — is
    /// what keeps a just-freed ifname and port out of the very next plan while
    /// [`plan_tunnel`] stays a pure function of its arguments.
    ///
    /// Expired entries are filtered on read rather than pruned, since this
    /// takes `&self`; `tear_down` prunes for real.
    pub fn plans(&self) -> Vec<TunnelPlan> {
        let now = Instant::now();
        let mut plans: Vec<TunnelPlan> = self
            .tunnels
            .iter()
            .map(|(id, t)| TunnelPlan {
                id: *id,
                ifname: t.ifname.clone(),
                listen_port: t.listen_port,
            })
            .chain(
                self.quarantine
                    .iter()
                    .filter(|(_, freed)| now.duration_since(*freed) < QUARANTINE)
                    .map(|(p, _)| p.clone()),
            )
            .collect();
        // By (id, ifname, port), not id alone: a quarantined entry and a live
        // one can share an id only transiently, but the order must still be
        // total or the allocation would not be reproducible.
        plans.sort_unstable_by(|a, b| {
            (a.id, &a.ifname, a.listen_port).cmp(&(b.id, &b.ifname, b.listen_port))
        });
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
