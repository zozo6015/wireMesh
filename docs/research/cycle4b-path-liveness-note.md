# Cycle 4b Task 10 — path-liveness note (rx_bytes as keepalive-visible signal)

## Finding

The Task 10 path-state driver (`run_path_ticks` in `crates/wiremesh-gateway/
src/main.rs`) polled the WG UAPI every ~1s and called `Path::on_handshake`
only. That's an incomplete liveness signal: WireGuard only advances
`last_handshake_time` on its own rekey cadence (~every 120s), not on every
packet. The 15s `persistent_keepalive_interval` (spec §6.1, `path::KEEPALIVE`)
keeps the tunnel alive but does **not** move the handshake timestamp between
rekeys.

`Path::tick`'s `Direct -> Degraded` transition fires when neither
`last_inbound` nor `last_handshake` has advanced for `DEGRADED_AFTER` (45s,
`path.rs`). With only `on_handshake` feeding `last_inbound`, a perfectly
healthy Direct path — receiving keepalives every 15s the whole time — still
looks silent after 45s and degrades, which fires `PathAction::StartPunch` /
`Retry` and re-runs `punch_and_apply` (a full `replace_peers` UAPI apply) on a
path that was never actually broken. Roughly 75s of every ~120s handshake-
rekey window would sit in spurious `Degraded`, i.e. the majority of the time.

## Fix

`Path` already exposes the right primitive: `on_authenticated_inbound(now)`
advances `last_inbound` without forcing a state change (a stray keepalive
shouldn't jump `Degraded` straight back to `Direct` — only a real handshake
recovery does that). What was missing was a keepalive-visible trigger to call
it from.

The UAPI `get=1` response already carries `rx_bytes` per peer
(`uapi::PeerGetInfo::rx_bytes`, parsed since Task 9) — cumulative bytes
received, which a keepalive datagram bumps just like any other authenticated
inbound traffic. The fix:

- `uapi.rs` gained `get_peer_liveness(ifname) -> {pubkey_hex -> (Option
  <SystemTime> /* latest handshake, absent if never-handshaked */, u64 /*
  rx_bytes */)}`, built on the same `parse_get_response` as the existing
  `get_latest_handshakes`/`handshake_times_from` (kept, for the epoch-
  ambiguity rationale already documented there) — one UAPI round-trip instead
  of two.
- `run_path_ticks` now tracks each peer's previous `rx_bytes` tick-to-tick;
  when it has strictly increased since the last poll (and the tick didn't
  already see a handshake advance, which itself refreshes `last_inbound`), it
  calls `path.on_authenticated_inbound(now)`. A healthy path's `rx_bytes` now
  visibly climbs every ~15s, so `last_inbound` never goes stale enough to
  trip `DEGRADED_AFTER` — no more spurious `Direct -> Degraded` oscillation or
  the re-punch churn that came with it.

## Verification

- New unit test `uapi::tests::peer_liveness_from_preserves_rx_bytes_for_both_
  peers` (pure, against the existing two-peer `get=1` fixture): confirms
  `rx_bytes` survives the reduction for both the handshaked and the
  never-handshaked peer.
- `cargo test -p wiremesh-gateway --lib` (inside the container, per
  `CLAUDE.md`'s execution rules) — see Task 10 report for the run.
