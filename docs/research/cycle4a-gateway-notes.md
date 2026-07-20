# Cycle 4a — direct-only gateway: notes & fast-follow carries

Cycle 4a delivered the real `wiremesh-gateway` binary and a four-assertion netns
mesh milestone (allowed / denied+counter / fail-static / policy-update), all
passing with two real gateway processes. This file records the deliberate scope
decisions and the fast-follow carries surfaced by the per-task and whole-branch
reviews, so the next cycle inherits them explicitly rather than as assumed-solved.

## Deliberate scope decisions (this cycle)

- **Key rotation deferred** to a fast-follow. 4a ships static single-epoch
  per-gateway WireGuard keys.
- **Proto change made (approved 2026-07-20):** `EnrollRequest.wg_pubkey` (field 4).
  The Cycle-2/3 controller stored only placeholder WG pubkeys; there was no path
  for a gateway's real, locally-generated WireGuard public key to reach peers
  (that path was coupled to the deferred key rotation, design §4.4). A gateway
  now registers its real pubkey as its epoch-0 baseline key at enrollment; empty
  `wg_pubkey` falls back to the Cycle-2 placeholder (back-compat). See spec §2
  amendment.
- **Additive controller `Config.bind_ip`** (default `127.0.0.1`) + testkit
  `TestController::start_on`, so the netns milestone's gateway processes can reach
  the in-process controller over a routable underlay. Cert SAN unchanged.
- **G-2 (≥1 Gbps on 4-vCPU) deferred** to a real cloud VM run. The bench exists
  (`crates/wiremesh-gateway/bench.md`); the number is unmeasured (container
  numbers are harness-only). See `docs/research/phase0-results.md`.
- **Data-path hardening split:** MTU 1280 + nft MSS clamp landed in 4a; the two
  enforcer/testkit Cycle-4 carries (IPv4 fragment handling on both backends;
  conformance harness-error vs policy-drop) remain a separate enforcer-hardening
  pass.

## Fast-follow carries (none merge-blocking; ranked)

1. **`apply_state(...).await?` is fail-CLOSED on a transient local error.** In
   `crates/wiremesh-gateway/src/main.rs`, a failed apply (transient `ip route
   replace`, UAPI hiccup, malformed peer key) propagates out of `run()` and
   exits the process, taking the data plane down — in tension with the cycle's
   fail-static goal. It is *not* on the controller-outage path (that arm never
   touches the data plane), and `state.json` is saved only after a successful
   apply so a supervised restart replays last-good state. Fix: log + `break` to
   the reconnect loop instead of `?`. **Top priority fast-follow.**
2. **`sync::report()` failure silently discarded** (`main.rs`) — advisory in 4a;
   add a log line.
3. **`wg_pubkey` stored unvalidated at the controller** (`db.rs`) — a malformed
   key surfaces only at the peer's `uapi::apply` 32-byte guard (and today, via
   #1, exits that peer). A cheap base64/32-byte check at enrollment would fail
   loudly at the right end.
4. **Gateway mTLS `domain_name("127.0.0.1")` is hardcoded** (`sync.rs`) — a real
   routable-controller deployment needs this configurable (and a matching cert
   SAN). Track with the enrollment-on-boot follow-up.
5. **Test-coverage top-ups:** direct unit tests for `uapi::base64_encode/decode`,
   `key_b64_to_hex` length guard, and `base64_pub_from_priv` (happy + reject);
   `base64_decode` silently accepts `len % 4 == 1` (unreachable behind the
   32-byte guard today); `sync::next_desired` empty-body and
   delta-before-snapshot error branches; a combined `save`/`load`-after-
   `apply_delta` round-trip.
6. **Fail-static milestone tests a *fresh* post-outage connection**, not
   established-flow-table survival across the controller kill. The
   controller-independence property is proven; a held-flow variant would
   strengthen it toward the literal done-bar wording.
7. **SO_REUSEPORT observation sidecar window (~2s/20s)** can drop a WG data packet
   (masked by TCP retransmit). The same-socket precision rides with 4b (spec
   §5.4/§7-B).
8. **`DesiredState.relays` uses replace-if-nonempty** — inert in 4a (no relay
   deltas exist yet); revisit additive/guarded semantics when 4c adds the first
   relay-bearing delta.
9. **`fabricctl` enrollment should carry `wg_pubkey`** for production
   provisioning (the mesh milestone uses the testkit enrollment path).
10. **`Lab::drop` umount "not mounted" stderr noise** during netns teardown —
    cosmetic, pre-existing.

## Next cycles

Key-rotation fast-follow → Cycle 4b (controller-brokered NAT hole punching +
`Connecting→Direct/Relayed/Degraded` path state machine + same-socket
observation) → Cycle 4c (`wiremesh-relay` + gateway relay transport + relay
advertisement + failover). Gateway runtime deps: `iproute2` + `nftables`
(alongside the existing nftables-backend `conntrack-tools` requirement).
