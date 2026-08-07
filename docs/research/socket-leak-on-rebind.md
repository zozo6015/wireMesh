# boringtun leaks a UDP socket pair on every `open_listen_socket`

**Observed:** 2026-08-07, with `ss -lunpe` inside the netns during the rotate-twice done-bar.
**Status:** confirmed, not fixed. **Does not currently cause a failure** — see "Why it is
green". Task #26.

Predicted by review during the v0.7.2 port-authority work and carried since as "the last
blocker to re-enabling rotation". Nobody had looked. This is what looking found.

## The mechanism

`register_udp_handler` registers the epoll event against a `try_clone()` of the socket.
`try_clone()` is `dup()`, so the original and the clone are **two fds on one kernel socket**.
`open_listen_socket` then clears by the **original's** fd:

```rust
if let Some(s) = self.udp4.take() { clear_event_by_fd(s.as_raw_fd()) }
```

`events[]` is indexed by fd, so `events[original_fd]` is `None` and the clear is a no-op. The
clone stays in the epoll set, still bound, its handler closure still owning the socket.

**Reading key for the dumps below:** an inode with **2 fds** is live (boringtun's `self.udp4`
plus the registered clone). An inode with **1 fd** is leaked — the original was dropped, the
clone survived.

## What is actually bound

gwA, one gateway process, from the rotate-twice done-bar. Counts are v4+v6 pairs.

| point | total UDP socks | :51820 | :51821 | ephemeral |
|---|---|---|---|---|
| A0 pre-rotation | 6 | 1 live + **1 leaked** | — | 1 leaked |
| B1 after retire 1 | 8 | 1 live (`wg0e1`) | **2 leaked** | 1 leaked |
| C2 rotation-2 tun up | 14 | 1 live (`wg0e1`) | 1 live (`wg0e2`) + **3 leaked** | 2 leaked |
| D3 after retire 2 | 8 | 1 live (`wg0e2`) | **2 leaked** | 1 leaked |

Three things the prediction missed:

1. **The gateway leaks before any rotation happens** (row A0) — boot plus one full apply is
   enough. This is not a rotation bug; rotation just makes it visible.
2. **Every `open_listen_socket` leaks**, not only the port-changing one. `wg0e1` rebinds
   51821 twice (device create → UAPI `listen_port=` → a later full apply also carrying
   `listen_port=`) before renormalization moves it, hence *two* leaked pairs, not one.
3. At C2 there are **four** sockets on 51821, and **two of them belong to the retiring
   epoch-1 Device** — i.e. bound, epoll-registered, and holding the *wrong static key*.

Raw, at C2 (`wg0e2` live on 51821, `wg0e1` still up on 51820):

```
:51821 users:(("wiremesh-gatewa",pid=6406,fd=94),(...,fd=30)) ino:10312236 sk:2001  <- LIVE  wg0e2
:51821 users:(("wiremesh-gatewa",pid=6406,fd=37))             ino:10315160 sk:2002  <- leaked wg0e2
:51821 users:(("wiremesh-gatewa",pid=6406,fd=85))             ino:10313982 sk:1002  <- leaked wg0e1 (WRONG KEY)
:51821 users:(("wiremesh-gatewa",pid=6406,fd=64))             ino:10313977 sk:1003  <- leaked wg0e1 (WRONG KEY)
```

Had the kernel steered gwB's epoch-2 handshake to `sk:1002` or `sk:1003`, it would have been
mac1-checked against the epoch-1 static key and silently dropped — the stall the review
described. Nothing in WireMesh chooses the winner.

## Why it is green

Linux `udp_lib_get_port` **head-inserts** into the port hash and `udp4_lib_lookup2` compares
scores with a strict `>`, so among equal-scoring sockets the **most recently bound wins**.
Measured on the container kernel (6.12.76-linuxkit), four `SO_REUSEADDR` sockets on one port:

```
after binding S0 -> ['S0(bound #0)']
after binding S1 -> ['S1(bound #1)']
after binding S2 -> ['S2(bound #2)']
after binding S3 -> ['S3(bound #3)']
closed S3       -> ['S2(bound #2)']
after binding S9 -> ['S9(newest)']
```

The one tie-breaker that could plausibly beat insertion order is `compute_score()`'s `+1` for
`sk_incoming_cpu == raw_smp_processor_id()` — and a leaked socket is genuinely *warm*, having
really received the previous rotation's handshakes. Warm-then-bind-newer, 20 sends per trial,
5 trials, unpinned and again under `taskset -c 0`: **`{'old': 0, 'new': 20}` every time.** The
leaked socket could not be made to win.

The ordering is also structurally on our side rather than lucky: `wg0e1`'s 51821 sockets are
always bound before `wg0e2`'s; the survivor only ever rebinds at *base*, never back at
`base+1`; and if renormalization fails, `TunnelSet` bookkeeping still shows `Own{n}` on
`base+1`, so `plan_port(Own)` hard-fails loudly rather than double-binding.

## What the residual exposure actually is

Not "rotation may stall". Two other things:

1. **An undocumented dependency on kernel implementation detail.** Newest-wins is real and
   deterministic, but it is not an API contract. Nothing in the test suite observes it.
2. **An unbounded fd/socket leak** — 2 fds per `open_listen_socket`, i.e. per rotation *and
   per full UAPI apply*, freed only when the Device is torn down.

## It also makes a doc claim in this repo wrong — twice over

`uapi::set_listen_port`'s failure-posture section has now been wrong in two different ways,
both times reasoned from boringtun's source without observing a running device:

- v1: "leaves the gateway exactly where it was — on the offset port."
- v2 (2026-08-06): "deaf and mute on every port, receiving nothing."

Neither holds. Because the leaked clone stays bound **and epoll-registered**, a failed rebind
leaves the Device **receiving on the old port while unable to send** — half-open, not dead.
Corrected 2026-08-07 against this observation.

## Fix options, in the investigator's preference order

**(c) Close the leak.** The bug is entirely `open_listen_socket` clearing by the original's
fd; the clone's fd is available at registration time. A vendored/patched boringtun that
records the registered fd and clears *that* removes the double-bind, the fd growth, and the
kernel-ordering dependency in one change. Cost: vendoring boringtun is not free.

**(b) Reserve two ports.** Composes with the reserved-not-free-listed model —
`OWN_TUN_PORT_OFFSET` is a constant, so making it two is small. Costs another port from the
`base+1..base+64` window, needs a documented invariant about which one the peer computes, and
does nothing about fd growth.

**(a) Alternate the offset by `pending_epoch % 2`.** Cheap, and both sides can compute it —
but it only guarantees the *immediately preceding* rotation's leak is not underfoot. Rotation
N+2 lands on rotation N's leaks again. That is safe only while Device teardown always
completes, and gwB's overlap Device is already documented as leaking permanently on the
currently-green path. Do not build on that.

**Worth doing regardless, and cheap:** a metric counting UDP sockets the process holds on
`base+1`. This condition is completely invisible in production today.
