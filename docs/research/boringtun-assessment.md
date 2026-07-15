# boringtun 0.6 assessment scratch notes (Task 3, Bet 1)

## What was checked

boringtun 0.6's `device` feature, embedded via `boringtun::device::{DeviceConfig,
DeviceHandle}`, configured externally via the standard `wg` UAPI socket — the
embedding mode the future gateway will use.

## API match vs. the brief's sketch

The brief's Step 2 sketch (`DeviceConfig::default()`, `cfg.n_threads = 2`,
`DeviceHandle::new(&ifname, cfg)`, `handle.wait()`) matched boringtun 0.6.0's real
API **verbatim** — no field renames were needed. Confirmed against source at
`/usr/local/cargo/registry/src/index.crates.io-*/boringtun-0.6.0/src/device/mod.rs`:

- `DeviceConfig { n_threads, use_connected_socket, use_multi_queue, uapi_fd }`
  implements `Default` exactly as sketched.
- `DeviceHandle::new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error>`
  synchronously creates the TUN device and registers the UAPI handler (when
  `uapi_fd < 0`, the default) before returning — so by the time `DeviceHandle::new`
  returns `Ok`, `/var/run/wireguard/<ifname>.sock` already exists and `wg` can talk
  to it immediately.

No corrections to the sketch were required for the binary itself. The `Result<_,
boringtun::device::Error>` needed converting to `anyhow::Error` at the call site
(`.map_err(|e| anyhow::anyhow!(...))`), a minor ergonomics point, not an API break.

## Real finding: UAPI socket is mount-namespace-scoped, not network-namespace-scoped

This is the substantive discovery, and it did not come from a field-name mismatch —
it came from the integration test failing intermittently/deterministically at the
`wg set` / `ip addr add` / `ping` stage even after the device came up correctly on
both sides.

**Root cause** (confirmed via `boringtun-0.6.0/src/device/api.rs::register_api_handler`):

```rust
const SOCK_DIR: &str = "/var/run/wireguard/";
...
let path = format!("{}/{}.sock", SOCK_DIR, self.iface.name()?);
create_sock_dir();
let _ = remove_file(&path);              // unlinks any existing socket at that path
let api_listener = UnixListener::bind(&path)...;
```

The UAPI control socket path is derived **only from the interface name** and lives
in the process's *mount* namespace. It is **not** scoped by the *network*
namespace the device's TUN interface actually lives in. Real kernel WireGuard
avoids this because kernel-side configuration goes over generic netlink, which
*is* network-namespace-aware; boringtun's userspace fallback protocol (the
original wg-quick/wireguard-go UAPI convention) predates that and is a plain
Unix domain socket at a fixed path.

`ip netns exec <ns> <cmd>` (used throughout `natlab`, and by the test's own `wg`
invocations) isolates the **network** namespace only. It does *not* give each
namespace a private `/run`: `ip netns exec`'s own internal `unshare(CLONE_NEWNS)`
clones the *mount table*, but `/run` is normally an existing tmpfs *instance*
shared by the whole container, so the clone still points at the same underlying
filesystem. Verified directly:

```
ip netns exec dbg-a sh -c 'echo FROM_A > /var/run/wireguard/marker'
ip netns exec dbg-b cat /var/run/wireguard/marker   # => FROM_A (visible!)
```

**Consequence for this test:** the test's two `spike-tunnel` processes both use
interface name `wg0` (required — the test's own `wg`/`ip` commands hardcode
`wg0` in both namespaces, mirroring how a real gateway would name its interface).
Both processes' `register_api_handler()` calls race to bind
`/var/run/wireguard/wg0.sock`; whichever binds *last* silently deletes
(`remove_file`) the other's socket file and takes over the path. Every subsequent
`wg set`/`wg show wg0` call from *either* namespace then talks to whichever
device most recently won that race — regardless of which network namespace
issued the command. Observed symptom: `wg show wg0` in both namespaces showed
**identical** state (both peers configured on one device), while the other
device silently received zero configuration, so the "overlay ping" had no
working WireGuard session on one end and failed with 100% packet loss. This
reproduced consistently under manual, non-cargo-test reproduction, ruling out a
cargo-test-specific timing fluke.

**This is a structural incompatibility, not a fixable code bug** in the binary:
no ordering, retry, or delay logic inside `spike-tunnel` can avoid it, because
exactly one inode can exist at `/var/run/wireguard/wg0.sock` at a time in a
shared mount namespace, and the stock `wg` CLI hardcodes that path from the
ifname argument with no override. It only doesn't bite in production because a
real gateway is its own process on its own host/pod — i.e. it already has a
private mount namespace by construction. It only surfaces here because the test
lab (`natlab`) puts two same-named interfaces in one shared mount namespace.

## Fix applied (in `spike/natlab`, not `spike/tunnel`)

Gave each `natlab::Ns` its own **persistent, private mount namespace** (created
via `unshare --mount=<pin-file>`, a util-linux ≥ 2.33 feature — confirmed present,
util-linux 2.38.1 in the dev container) with a private `tmpfs` mounted at
`/var/run/wireguard`. `Ns::exec`/`Ns::spawn` now do
`nsenter --mount=<pin> -- ip netns exec <name> <cmd>` instead of bare
`ip netns exec <name> <cmd>`. Validated in isolation (outside cargo test) that:
writes to one Ns's private `/var/run/wireguard` are invisible from the other Ns
and from the root mount namespace, and that with this in place both `wg show`
outputs correctly diverge (one peer each) and the ping succeeds with 0% loss.

This is a `natlab` API-surface-preserving change (no signature changes to
`Ns`/`Lab` public methods), so `tests/tunnel_ping.rs` required zero changes.
Verified no regression: `spike/natlab`'s own `veth_ping.rs` test still passes.

## Assessment input for Task 5

- boringtun 0.6's embedded `device` feature works exactly as documented for the
  single-instance-per-host case the real gateway will use — Bet 1 (embed +
  external `wg`-UAPI config) is **validated**.
- The UAPI socket's mount-namespace scoping (vs. network-namespace scoping) is a
  real, load-bearing property worth flagging for the actual gateway design: if
  the gateway ever runs multiple logical interfaces with the same name in the
  same mount namespace (e.g. multiple gateway processes on one host sharing a
  container), they will collide exactly like this test did. Not a concern for
  the current one-gateway-per-segment/pod model, but worth a design note if that
  assumption ever changes.
- This finding, and the `natlab` fix, should be reused verbatim by Tasks 6–9 and
  14, which copy the same lab pattern — otherwise they will hit the identical
  collision as soon as they spin up two same-named tunnel interfaces.
