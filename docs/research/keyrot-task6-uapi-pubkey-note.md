# Task 6 (TunnelSet) — `wg show`/`wg pubkey` cannot see a boringtun device's own public key

**Task:** key-rotation Task 6, `crates/wiremesh-gateway/src/tunnelset.rs`
(`TunnelSet`, additive multi-Device primitive; test file
`crates/wiremesh-gateway/tests/tunnelset_netns.rs`, committed by the
test-authoring agent at `e3fe666`).

**STATUS: confirmed pre-existing environment/dependency incompatibility, not a
`TunnelSet` bug.** One sub-assertion of the netns acceptance test
(`two_epoch_tunnels_coexist_and_tear_down`) cannot pass as written, with any
implementation of `bring_up`, given this repo's pinned `boringtun = "0.6"` and
the real system `wg` (wireguard-tools) CLI. Everything else about the test —
port, coexistence, route programming, `tear_down` — passes.

## The assertion that fails

```rust
let show0_text = String::from_utf8_lossy(&show0.stdout);
assert!(show0_text.contains("listening port: 51820"), ...); // PASSES
assert!(show0_text.contains(&k0_pub), "wge0 output missing expected pubkey: {show0_text}"); // FAILS
```

`wg show wge0`'s actual stdout is:

```
interface: wge0
  listening port: 51820
```

There is no `public key:` line at all, on either epoch's device, regardless of
what `bring_up` writes to the device.

## Root cause

The official WireGuard cross-platform userspace API
(<https://www.wireguard.com/xplatform/>) specifies that a `get=1` response
includes `private_key=<hex>` for the device (if one is set), and the `wg`
CLI derives and prints the public key itself from that private key — the
protocol has no separate "public key of self" field, by design.

`boringtun 0.6.0` deliberately does not follow that part of the spec, for
what looks like a private-key-exfiltration-hardening reason. Its `get=1`
handler (`boringtun-0.6.0/src/device/api.rs::api_get`):

```rust
if let Some(ref k) = d.key_pair {
    writeln!(writer, "own_public_key={}", encode_hex(k.1.as_bytes()));
}
```

emits a **non-standard** `own_public_key=<hex>` line instead of
`private_key=<hex>`. Confirmed by connecting directly to a live device's UAPI
socket and issuing a raw `get=1`:

```
own_public_key=4e1088f42893a6dfe637e21f545c1cb3f29d1c8de7c8f6234261683c56d96e41
listen_port=51999
errno=0
```

— note: no `private_key=` line, and the key material shown IS the
public key (hex), just under a field name real `wg` has never heard of.

`strings /usr/bin/wg` (this container's wireguard-tools v1.0.20210914)
confirms the client's vocabulary is exactly `private_key`/`public_key` and
nothing else — no `own_public_key` token anywhere in the binary. Its parser
silently ignores unrecognized `key=value` lines (the `listening port:` line
still renders fine from the `listen_port=` field it DOES recognize). Verified
across all three ways to ask `wg` for a device's own public key, all with a
correctly-`uapi::apply`'d private key already live on the device:

| command                       | output           |
|--------------------------------|------------------|
| `wg show wged`                 | no "public key:" line at all |
| `wg show wged public-key`      | `(none)`         |
| `wg show wged dump`            | `(none)\t(none)\t51999\toff` (both key columns `(none)`) |

This is unconditional and independent of how the key was configured (raw
UAPI `set=1` via `uapi::apply`, or the real `wg set … private-key <file>` CLI
— both write the identical wire format; the deviation is entirely on the
`get=1` response side, which `TunnelSet::bring_up` cannot influence).

## Why this wasn't caught earlier

Nothing else in this repo asserts on a boringtun device's *own* public key via
`wg show`. `spike/keyrot/tests/rotate.rs` and the Cycle 4b/4c netns suites use
`wg show <iface> latest-handshakes` (per-*peer* state, a different, standards-
compliant field boringtun does implement correctly) — never the device's own
key. `tunnelset_netns.rs` is the first test in the codebase to check it.

## Why it isn't fixable within Task 6's scope

- `tunnel.rs`/`main.rs`/`apply_state` are explicitly off-limits for this
  additive task, but wouldn't help anyway — the deviation lives entirely
  inside the vendored `boringtun` crate's `get=1` handler, not in anything
  this repo's `Tunnel`/`uapi` modules write.
- Bumping/patching the vendored `boringtun` dependency to alter its UAPI
  `get` behavior is out of scope for an additive primitive task and would be
  a cross-cutting change affecting every other cycle that depends on
  `Tunnel`.
- There is no legitimate way to make `k0_pub`'s base64 string appear anywhere
  in `wg show`'s output without gaming the assertion (e.g. injecting a fake
  self-peer) rather than actually proving device identity.

## What `TunnelSet::bring_up` does instead (and does correctly)

`bring_up` applies the device's identity (private key + listen port, no
peers) via one `uapi::apply` call immediately after `Tunnel::up`, so the
Device is a real, addressable WG endpoint on the right port as soon as
`bring_up` returns (this is what fixed the `listening port:` assertion,
which initially showed a random kernel-assigned port because `Tunnel::up`
itself never touches UAPI — that's `Tunnel::reconcile`'s job, and it needs a
`DesiredState` this call site doesn't have yet). The device's actual
identity is independently verifiable: `base64_pub_from_priv(&priv_b64)` is a
pure, already-tested (`uapi.rs`) local computation from the exact same key
material handed to `bring_up`, so the "right pubkey per tun" property does
hold — it just isn't observable through the real `wg` CLI against this
boringtun version.

## Recommendation

Whoever owns `tunnelset_netns.rs`/the Task 6 plan should decide between:
1. Drop the `wg show … contains(&k_pub)` sub-assertion (keep the port + route
   + coexistence + tear-down assertions, which are all boringtun-CLI-
   compatible and already pass), or
2. Replace it with a check that doesn't route through the real `wg` binary,
   e.g. a raw UAPI `get=1` parsed for `own_public_key=<hex>` (mirroring
   `uapi::parse_get_response`'s pattern) compared against the hex form of
   `k0_pub`, or
3. Accept the finding as a ratified, documented divergence (same pattern as
   `docs/research/cycle3-policy-notes.md`'s one-way-UDP divergence) and treat
   this one line as an expected/ignored failure.

This implementer did not choose for them — the test file is owned by a
different agent per the workflow rule, and none of the above is a "fix the
code" action within `tunnelset.rs`'s legitimate surface.
