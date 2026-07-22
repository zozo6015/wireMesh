# Key-rotation old-epoch teardown — known limitations (Step 2/3)

Status: the epoch-aware device unification + old-epoch teardown is implemented and
proven by `crates/wiremesh-gateway/tests/key_rotation.rs::old_epoch_device_is_torn_down_after_rotation`
(commit `a538967`): after a Role-A gateway rotates and every peer is rx-corroborated
live on the new tun for `RETIRE_GRACE` (= `2 * ROTATION_KEEPALIVE`), the old epoch's
boringtun `Device` is torn down (`TunnelSet::tear_down`, dropping the old private key
from memory before the `ip link del`) and its enforcer evicted. Make-before-break is
preserved (teardown only from `CutOver`, only after full-peer grace; the OLD epoch is
retired, never the live one). Full non-regression green (lib 76, key_rotation 4/4,
mesh_milestone, nat_matrix 4/4, relay_matrix 2/2).

The following are KNOWN LIMITATIONS in scenarios the done-bar does NOT exercise. None
is a regression; each is a focused fast-follow. Recorded per the cycle's
documented-limitation discipline (cf. the one-way-UDP divergence and the boringtun
`own_public_key` finding).

## A. (TOP must-fix) Post-cutover DEVICE churn applies base-port peer endpoints to the offset-port tun
The new tun is brought up (`handle_rotate`) with `reconcile::device_config_at_port` —
peer endpoints rewritten to the OFFSET port. But the active-tun apply path
(`apply_state`, `set_peer_endpoint`, the cutover change-guard seed) recomputes
`reconcile::device_config_pinned`, whose peer endpoints come from `primary_endpoint()`
= the peer's BASE port. The change-guard seed at cutover masks this for the UNCHANGED
config (the byte-identical recompute is a no-op, so the live offset-port session is not
disturbed). But a LEGITIMATE post-cutover device change — a peer CIDR add/remove, an
`EndpointObserved` candidate change, or a punch/relay `set_peer_endpoint` — recomputes a
DIFFERENT `device_config_pinned` and DOES apply, pushing BASE-port peer endpoints onto
the live OFFSET-port tun → the WG session silently black-holes (no crash, no assertion).
The done-bar's post-teardown change is policy-only (the enforcer loop, correctly reaching
the active tun via Step 1), so it never triggers this.
FIX: thread the offset-port endpoint rewrite through the active-tun apply path — the
apply sites must build peer configs with the active epoch's port offset (like
`device_config_at_port`/`pending_peer_configs` do), not `device_config_pinned` (base
port). Needs a post-cutover endpoint/CIDR-change test. Until then: post-cutover device/peer
churn on a rotated gateway is UNSUPPORTED.

## B. Post-rotation NAT re-punch binds the wrong port
`PathCtx` uses a fixed `base_wg_port` for the SO_REUSEPORT punch socket (correct: binding
the active/offset port would let the punch socket steal the live new-tun's inbound
datagrams — the real regression this fix avoided; non-regressive for no-rotation since
base == active, nat_matrix green). But post-cutover the live session is on the OFFSET
port while the punch binds the BASE (idle/retired) port, so a Degraded NAT'd peer that
needs a re-punch AFTER a rotation opens a hole on the wrong port and can't restore the
direct path. Rotation × NAT-repunch is untested and unhandled; relay is the fallback.
Acceptable edge case for now; fix alongside A (the active-port punch needs the same
active-tun awareness).

## C. Retirement is process-local; a reboot resurrects the retired epoch
`EpochKeys::promote()`/`retire()` are never called in `main.rs` (only `generate_next()`),
and boot ALWAYS brings up epoch 0 from `id.wg_private_key_b64` (hardcoded epoch 0),
independent of the persisted store. So after a rotation the store still reads
`epoch 0 = active, epoch 1 = pending` (diverged from the live Devices), and after a
rotation + REBOOT the gateway comes back on the RETIRED epoch-0 key as its live device.
The Step-2/3 security goal ("old private key gone from any LIVE Device") is met for the
RUNNING process — and robustly (the boringtun Device is dropped before the best-effort
`ip link del`, so even an `ip link del` failure doesn't leave the key live). But the
retirement is NOT durable: it is process-local until rotation PERSISTENCE lands
(`EpochKeys::promote/retire` wired at cutover/retire + the boot identity swapped to the
active epoch's key + the controller-side promote reconciled with the boot key). Track as
a fast-follow; qualify the security claim as "process-local until rotation persistence."

## D. (Minor) Role-B post-cutover CIDR churn routes via wg0
Role B deliberately never flips `active` (it isn't rotating its own key; flipping would
mis-apply its `wg0` pin) — correct. Consequence: a NEW CIDR added to an already-rotated
peer on the Role-B side, post-cutover, routes via `wg0` (active) rather than the overlap
tun; a removed CIDR's `del_route(cidr, wg0)` no-ops and can leak the route on the overlap
tun. Existing peer CIDRs ARE explicitly flipped onto the overlap tun at cutover, so this
is a narrow untested churn scenario. Low impact; fold into the multi-peer overlap work.

---
## Concrete implementation plan for Fast-follow A (worked out 2026-07-22, ready for a fresh session)
Exact code sites (main.rs / reconcile.rs on branch worktree-key-rotation @ a530c33):
1. `reconcile.rs`: add `pub fn device_config_pinned_offset(ds, private_key_b64, listen_port, keepalive_secs, pinned_pubkeys, port_offset: u16) -> DeviceConfig` — identical to `device_config_pinned` (reconcile.rs:76) EXCEPT each peer's `endpoint` is the peer's `primary_endpoint()` with its port SHIFTED by `port_offset` (parse `ip:port` via rsplit_once(':'), `port.checked_add(port_offset)`, skip peer on malformed/overflow). When `port_offset == 0` this is byte-identical to `device_config_pinned` (a peer at `ip:51820` → `ip:51820`) → NON-REGRESSIVE BY CONSTRUCTION. (Mirrors the relative-offset logic already in `pending_peer_configs`.)
2. `main.rs` `ActiveTunInfo` (struct at ~main.rs:94): add field `port_offset: u16`. Set it: boot (~main.rs:171) `port_offset: 0`; cutover (~main.rs:1859, the `*rot.active.lock() = ActiveTunInfo{...}` in run_rotation_ticks Role-A FlipRoutes) `port_offset: new_port - rot.base_wg_port` (the same `offset` already computed in handle_rotate; recompute as `a_new_port.saturating_sub(rot.base_wg_port)`); test-ctx (~main.rs:1983) `port_offset: 0`.
3. Replace the 3 active-tun `reconcile::device_config_pinned(...)` calls with `device_config_pinned_offset(..., active_port_offset)`, reading `port_offset` from the `active` lock alongside ifname/priv_key/wg_port: `set_peer_endpoint` (~main.rs:825), `apply_state` (~main.rs:1317), and the cutover SEED (~main.rs:1850). The seed MUST use the same offset so its fingerprint matches what apply_state/set_peer_endpoint will recompute (keeps the no-op-on-unchanged property) while a real change now applies OFFSET-port endpoints.
NON-REGRESSION: every non-rotation gateway keeps `active.port_offset == 0` → identical to today (nat/relay/mesh green by construction). NAT'd peers post-rotation remain Finding B (the relative offset is wrong behind NAT) — still unsupported, still documented.
TEST (Finding-A repro): `post_rotation_device_change_keeps_session_alive` — direct mesh + netem; rotate gwA to completion; then `h.apply(fabric_v2)` adding a 2nd CIDR to seg-b (changes gwA's peer allowed_ips → a device re-apply); assert the ORIGINAL wlA→wlB flow (ICMP + tcp/8080) STILL crosses. RED without the fix (base-port endpoints black-hole the offset-port session); GREEN with it. Verify + full non-regression (nat/relay the gate) as in the Step-2 brief.
