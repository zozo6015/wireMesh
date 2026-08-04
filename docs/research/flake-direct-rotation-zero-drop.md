# Latent flake: `direct_rotation_is_zero_drop` sits at its tolerance limit

**Found:** 2026-08-04, during the backlog item 1 (policy-apply worker) verification runs.
**Status:** pre-existing, NOT caused by item 1. Not fixed. Recorded so the next person to
see it red has the distribution rather than a single data point.

## What happened

`crates/wiremesh-gateway/tests/key_rotation.rs`'s `direct_rotation_is_zero_drop` failed
once in roughly a dozen runs across the session:

```text
ZERO-DROP FAILED: ping flood during rotation dropped too many packets
(transmitted=13, received=9, allowed gap=3)
```

It was noticed during a sabotage run (the gauge reverted to `store(ds.policy_version)`),
but the runner correctly declined to report it as detection: that gauge is report-only
and cannot influence packet loss.

## The distribution

Characterised deliberately rather than retried until green:

| Configuration | Observed gap (tolerance 3) |
|---|---|
| clean, isolated ×4 | 2, 2, 2, 2 — pass |
| clean, full suite (`ca218cf`) | **3** — pass, at the exact limit |
| clean, full suite (`bd7ec44`) | 2 — pass |
| sabotage, isolated | 3 — pass, at the limit |
| sabotage, full suite | **4** — FAIL |

The sabotage is not the variable; the same distribution appears with and without it. What
moves the number is running inside the full suite rather than in isolation — presumably
container load, since the assertion counts ICMP replies across a make-before-break
cutover.

## Why it matters

The margin is one packet. In full-suite configuration the test sits at gap 3 of an
allowed 3, so any single extra dropped ICMP reply reds it. That is a CI flake waiting to
happen on a busier machine, and it will look like a rotation regression when it fires.

## What NOT to do

Do not widen the tolerance to make it green. The assertion is the Cycle-4b done-bar for
make-before-break rotation being lossless, and a 4-packet gap during a cutover may well
be a real regression rather than noise — the point of the bar is that it is tight. If it
fires, characterise it the way the table above does (isolated vs full suite, several
runs) before touching anything.

## Plausible directions, unvalidated

- Establish whether the gap scales with container load; if so, the flood rate or the
  measurement window is the lever, not the tolerance.
- Check whether the drops cluster at the cutover instant or are spread — the former is a
  real property of the handover, the latter is scheduling noise.

## Second sighting, 2026-08-04 (same day, later) — UNCLASSIFIED

`key_rotation.rs` failed **once** during item-2 verification. Deliberately left
unattributed, because the evidence does not support attributing it:

- The failing test name was **not captured** (the runner's grep filter dropped the
  `failures:` block).
- It occurred in a run under an **unrelated sabotage** (`send_epoch_ack`'s
  `local_endpoints` reverted), and did **not** reproduce in two further runs of that same
  sabotage.

`direct_rotation_is_zero_drop` lives in `key_rotation.rs`, so it is a *candidate* — but so
is every other test in that file. Do not fold this into the distribution below without a
captured name.

## Observations, kept separate

**Clean HEAD, full suite:** gap 2, gap 3, gap 2 — all passing, margin as low as zero.
**Clean HEAD, isolated:** gap 2 ×4 — all passing.
**Under unrelated sabotage:** one gap-4 failure (2026-08-04, item-1 verification), plus
one uncaptured `key_rotation` failure (2026-08-04, item-2 verification).

Only the clean-HEAD rows characterise the flake. The sabotage rows are recorded so nobody
re-derives them as new sightings, not as evidence about the margin.
