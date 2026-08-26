# `rotation_survives_gateway_restart_on_new_epoch` gates one step too early

**Date:** 2026-08-26
**Status:** finding — test synchronisation defect, NOT a key-durability defect
**Trigger:** #96's first `ci.yml` `netns-rotation` run (`f857fde`) failed
`key_rotation` 5/7. One of the two failures was
`rotation_survives_gateway_restart_on_new_epoch` at `key_rotation.rs:1891`:

```
SECURITY: the retired epoch-0 PRIVATE key is still in gwA's epoch_keys.json
after retire + restart — retirement never durably destroyed it
```

The message names a security defect. It is not one. The test gates on an event
that happens *before* the scrub it asserts, and a loaded runner can land its
`SIGKILL` in between.

---

## The retire is a four-step sequence

`crates/wiremesh-gateway/src/main.rs:4305-4340`:

```
  1  tunnels.tear_down(id)                    ← wg0 DISAPPEARS HERE
  2  enforcers.lock().await.remove(&id)
  3  renormalize_active_listen_port(..).await ← awaits ctx.endpoint_commit
  4  ek.retire(epoch) + ek.persist(..)        ← THE KEY SCRUB
```

The test's pre-crash gate waits for **`wg0` gone AND `wg0e1` present** — which
is step 1 — and then, after the restart, asserts on the outcome of step 4. Its
comment, as it stood before the fix below, stated a premise the code does not
support:

> Waiting for gwA's `wg0` to be GONE (and `wg0e1` present) proves
> `service_retire` has run — so the durable-retire assertion (b) below is
> judged only after the point the ratified fix says the private key must have
> been scrubbed from disk.

`wg0` vanishing is observable at step 1. The scrub is step 4. Between them sits
an `.await` on a contended mutex. (An earlier draft of this note said step 3
"shells out to `ip`" — it does not: `renormalize_active_listen_port` ->
`TunnelSet::set_listen_port` -> `uapi::set_listen_port` is a `set=1` write over
the WireGuard UAPI's unix socket, `/var/run/wireguard/<if>.sock`. The mechanism
is the lock and a blocking socket round-trip inside an `async fn`, not a
process spawn — which matters, because "it's slow because it forks" would
predict a window that closes on an idle host, and the real one does not.) The
source is explicit that the two are decoupled —
`renormalize_active_listen_port` is best-effort and

> must not hold up the key scrub below, which is the security half of the
> retire.

**What actually bounds the window.** Step 3 is not merely slow-under-load: it
takes `ctx.endpoint_commit.lock().await` (`main.rs:4199`). So the interval
between `wg0` disappearing and the scrub landing is bounded by whoever else
holds that mutex — the observe/punch commit path — not by CPU scheduling alone.
That matters two ways. It explains why a busy runner widens the window far more
than a proportional slowdown would suggest; and it means the window can open on
an otherwise idle host if a punch/observe commit happens to be in flight. The
race is not purely a function of load.

**The test is not naive about ordering.** If the gate times out it panics with
`SETUP FAILED … cannot test restart durability of a retire that hasn't
happened`. That guard is why this needed a closer look rather than a dismissal:
CI got the SECURITY message, so the gate *passed*. The gate is simply not the
event the assertion needs.

---

## Two corroborations that the scrub never ran, rather than ran and failed

Both come from the CI artifact itself, and together they distinguish a race
from a genuine durability defect.

**1. The dumped row is in state `retiring`.**

```json
{ "epoch": 0, "private_key_b64": "KLr3x9JF7/…", "state": "retiring" }
```

`EpochKeys::retire()` (`epochkeys.rs:304`) does not flip a flag — it
**removes** the entry:

> Removal (not a state flip) is the scrub mechanism: once the caller
> `persist`s, the retired PRIVATE key is gone from `epoch_keys.json`'s bytes
> entirely.

A store where the scrub ran has **no epoch-0 row at all**. `retiring` is
precisely the pre-scrub state.

**2. Zero `CRITICAL` lines in the entire CI log.**

Both failure paths log loudly and unmissably:

```
CRITICAL: persisting retire of epoch {n} failed: … — the retired PRIVATE key is still on disk
CRITICAL: retiring epoch {n} in the key store failed: … — its private key remains in epoch_keys.json
```

`grep -c` over the whole log returns **0** for both. Had the scrub executed and
failed, one of them would be present.

Conclusion: `pkill -KILL` landed between step 1 and step 4. The key was
legitimately still on disk at that instant.

---

## Reproduction attempts

Root `main` @ `1f70ef6`, uncontended, exclusive volume:

```
RUN_1  ok. 1 passed; 0 failed   15.29s   PRE-CRASH: retire landed
RUN_2  ok. 1 passed; 0 failed   14.67s   PRE-CRASH: retire landed
RUN_3  ok. 1 passed; 0 failed   14.02s   PRE-CRASH: retire landed
```

(`PRE-CRASH: retire landed` is the pre-fix log line, quoted verbatim from these
runs. `f3f743a` renamed it: the retire is now two gates, so it prints
`PRE-CRASH: teardown landed …` and then `PRE-CRASH: key scrub landed …`. Anyone
grepping a log from `f3f743a` onward wants the new names.)

3/3 green. This is consistent with a race but **does not by itself prove one** —
the CI runner was loaded and this host was not. The load-bearing evidence is
the code ordering plus the two corroborations above, not the green runs.

### Deliberate-load attempt (3 runs, also green)

To try to widen the window on purpose: `nproc` = 8, and **24 busy loops**
(`sha256sum /dev/zero`, 3× oversubscription) were started immediately before
each run and killed after. The test binary was built **first, unloaded**, so
the load fell on the test rather than on compilation.

```
LOAD_RUN_1  ok. 1 passed   28.93s   (unloaded baseline ≈ 15.29s)
LOAD_RUN_2  ok. 1 passed   28.14s   (unloaded baseline ≈ 14.67s)
LOAD_RUN_3  ok. 1 passed   26.86s   (unloaded baseline ≈ 14.02s)
```

The load unambiguously bit — wall-clock roughly **doubled** — and the window
still never opened. That is not a null result: it is positive evidence that
**CPU starvation alone is insufficient** to reproduce this, which is what the
`ctx.endpoint_commit` explanation predicts and a naive "slow machine" account
does not. The window is opened by *contention on that mutex* from the
observe/punch commit path, and a busy-loop workload does not contend for it.

Reproducing it deliberately would mean holding `endpoint_commit` across the
retire — i.e. instrumenting the product — which is out of scope for a test-side
finding. The ordering argument and the two corroborations stand on their own.

**Premise check on the reproduction.** The tasking said "gateway code unchanged
since `941ed5f`". Not literally true — #94 merged in between, touching four
gateway `src/` files. The reproduction is still valid: those four files total
18 lines, all B10 version-field additions plus one comment reword, with zero
matches for `retire|epoch_key|rotation|discard|scrub|zeroiz`, and
`tests/key_rotation.rs` is byte-identical.

---

## The fix, as landed (test-side; no product change)

Implemented in `f3f743a` on `test/keyrot-restart-gate-on-scrub`, alongside this
note. Described below as it was designed; what landed matches, and the
differences from this section's original wording are called out at the end.

Keep the existing teardown gate, then add a bounded wait on the **scrub** as a
second gate before the kill: poll `EpochKeys::load(state_dir)` until
`by_epoch(0).is_none()` — removal being the scrub, that is the exact
post-condition — with a 60s bound and a `SETUP FAILED`-class message naming
step 4 rather than the teardown. Only then `pkill -KILL`.

`by_epoch(0).is_none()` is the correct predicate precisely because
`EpochKeys::retire` is `self.epochs.retain(|k| k.epoch != epoch)` — a removal,
not a state flip. Testing for "no epoch-0 entry" therefore cannot be satisfied
by a half-done retire, which is what makes this gate strictly stronger than the
teardown one.

Assertions stay unchanged. The result remains fully sensitive to a genuine
durability defect: if retirement never removes the row, the new gate times out
and fails with a message that names the actual missing step; if the row is
removed but resurrects across the restart, the existing SECURITY assertion
still fires exactly as written. What it stops being sensitive to is *when the
kill happens to land*, which was never the property under test.

### What landed, precisely

`f3f743a` matches the shape above — teardown gate unchanged, new scrub gate
after it, 60s, store API (`Ok(Some(s))` with `s.by_epoch(0).is_none()`; any
other load result is "not yet"), `SETUP FAILED:` naming `service_retire` step 4
by symbol — plus four things this section did not spell out:

- The new gate sits **before** the `pre_crash_store` load, so that load is now
  guaranteed post-scrub. Harmless: only epoch 0 is removed, and its `by_epoch(1)`
  read is unaffected.
- The failure message carries the last `EpochKeys::load` result, `Err` text
  included, so a timeout says *why* the store could not be read if that is the
  reason.
- The gate comment, and the test's doc header three screens above it, both
  carried the false premise quoted earlier; both are corrected to say what each
  gate proves. The raw byte-grep stays in assertion (b) so the gate and the
  assertion remain different checks.
- Assertion (b)'s subject is now narrower and its comment says so: with the
  scrub pinned pre-crash, (b) pins that the crash + restart must not **re-add**
  the retired key — `EpochKeys::boot_key`'s legacy branch synthesizes epoch 0
  from `identity.json`/`wg_private.key` when no `active` entry exists, which is
  the same path assertion (a) is RED for. Assertion text itself is unchanged.

One property this fix stops covering: whether step 4 completes within *any*
bound. A gate that waits it out cannot also fail on it. That is a product
property rather than a restart-durability one, and it is independently pinned by
`crates/wiremesh-gateway/tests/epoch_persistence.rs`'s
`retire_then_reload_scrubs_retired_private_key_from_disk`, so nothing is left
uncovered by the change — but the *timing* of it is now nobody's assertion, and
that is deliberate.

---

## Why this went unnoticed

The gate and the assertion were written together and read as consistent: "the
retire landed" and "the key is gone" feel like the same event. They are two
ends of a four-step sequence with an `.await` in the middle. On an unloaded
developer host the window is small enough that the test passes indefinitely —
it passed 7/7 three times during PR0b — and only a loaded CI runner widens it
enough to lose the race.

This is the same class as the `#[expect]` that never fired and the guard that
scanned test code: a check whose *stated* premise and *actual* premise differ,
which stays green until conditions change and then reports the wrong defect.
