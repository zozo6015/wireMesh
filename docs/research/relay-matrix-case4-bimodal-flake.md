# Latent flake: `relay_matrix` case 4 is bimodal — it recovers in ~66s, or not within the bound

**Found:** 2026-08-26, during PR5's (`0bab69d`) verification runs for Phase B.
**Status:** pre-existing, NOT caused by PR5. Not fixed. Recorded so the next person to see
it red has the distribution and the signature rather than a single data point.
**Same class as** [`flake-direct-rotation-zero-drop.md`](flake-direct-rotation-zero-drop.md):
a tight done-bar sitting on a real product fragility that surfaces under timing pressure.

## What happened

`crates/wiremesh-gateway/tests/relay_matrix.rs`'s
`case4_relay_leg_death_unwedges_direct_punch` failed in a full-suite run on PR5, then
passed twice and failed once more when run alone on a **provably uncontended** host.

Attribution rests on a runtime observation, not a hunch: the only executable change in PR5's
range is the `endpoint.parse()` `Err` arm, and it **never executed** — zero `unparseable`
lines across every run. So **no direct runtime mechanism by which PR5 could have caused this
was observed.**

That is deliberately narrower than "PR5 cannot have caused it". A change can in principle
perturb a build without its new branch executing — codegen, inlining decisions, instruction
layout, timing. Ruling that out would need a comparison of the PR5 and baseline **binaries**,
which was not done. What is claimed here is what was measured.

## The distribution

Three different quantities appear below and are kept apart deliberately, because
conflating them is what makes this flake look like a slowness problem:

* **recovery time** — severance instant to a real direct path, the thing the assertion
  actually bounds;
* **test time** — the whole case, including the ~30s of pre-severance setup (note there are
  **two** distinct ~30s intervals in this case and they are not the same thing: this setup
  phase, which precedes the severance and sits *outside* the recovery window, and the
  idle-timeout **detection** phase, which follows the severance and sits *inside* it);
* **suite wall time** — the full `relay_matrix` run, a host-load indicator only.

| Configuration | Result | Recovery (severance → direct) | Test time |
|---|---|---|---|
| `case4` alone, repeat 1 | PASS | 65.98s | 97.07s |
| `case4` alone, repeat 2 | **FAIL** | **none within the bound** | 156.47s |
| `case4` alone, repeat 3 | PASS | 66.50s | 97.51s |
| case 4 within the `f7adf2c` suite run (same execution as the suite row below) | PASS | 66.74s | 96.06s |

| Full-suite run | Result | Suite wall time |
|---|---|---|
| `0bab69d` | **FAIL** | 277.83s |
| `f7adf2c` (same host; its case-4 component is the last row above) | PASS | 219.94s — **+26% on the red run** |

**1 of 3 controlled repeats; 2 of 5 distinct case-4 executions (40%)** that day. (Six rows
appear above: the `f7adf2c` case-4 figures and the `f7adf2c` suite row are the same execution
seen twice — its case-4 component and its suite wall time.)

That is the same order as `direct_rotation_is_zero_drop`'s measured ~42% under load — and
unlike that one, **this fired on a host proven uncontended**: 18 container samples during the
repeats all showed count = 1.

That last point is what makes this note worth writing. The rotation flake is a load story.
This one is not, or not only.

## The signature is bimodal, not a margin

`direct_rotation_is_zero_drop` degrades continuously — gap 2, 3, 4 — and fails when it
crosses a threshold. Case 4 does not degrade. It lands in one of two states:

| | green | red |
|---|---|---|
| recovery | **~66s** (65.98 / 66.50 / 66.74) | **none within the bound** — budget exhausted |
| test time | ~97s (96.06 / 97.07 / 97.51) | 156.47s |
| `deferring direct punch` lines | **0** | **11** on the one red where lines were counted (n=1) |
| post-severance defers (gwA/gwB) | **0 / 0** | **3 / 3** on both reds (n=2) |
| final path states | direct (endpoints routable, per the assertion — `198.51.100.3:51820` / `198.51.100.2:51820`) | gwA `connecting`, gwB `disconnected` |

**No middle outcome was observed in these five executions.** Either the first punch window
after death-detection is clean and the pair recovers in ~66s, or **no clean recovery window
is observed before the 125s budget
(`CASE4_DEATH_DETECTION_BUDGET` 35s + `CASE4_RECOVERY_BUDGET` 90s) expires**. Note the
scoping: everything observed here ends at the budget, so "never recovers" is shorthand for
"had not recovered within the bound", and nothing here says what a longer-running pair
would do.

The three green recoveries land within 0.8s of each other across two commits. **Hypothesis,
not measurement:** that tightness is what a *fixed ladder* would look like — a deterministic
sequence of timeouts — rather than a race that happens to finish in time. Three points is
thin support for it, and nothing here distinguishes a fixed ladder from a race with a narrow
spread; it is offered as the reading that best fits, not as a result.

**On the recovery-after-detection figure, and where it comes from.** Taking the observed ~66s
from severance and the ~30s of idle-timeout detection the test reports, recovery-after-
detection is **~36s** — above the documented single-cycle range of 14–26s (backoff 4–16s +
`CONNECT_TIMEOUT` 10s), and well above the "~10-15s nominal" the same comment quotes. (The
budget *constant* is 35s; using it instead gives ~31s. Either way the figure exceeds one
documented cycle.)

The two numbers are worth keeping apart: **~36s is sourced from an observation** — the test's
own green output — while **~31s is sourced from a constant** subtracted from an observation.
An earlier draft of this note quoted only the constant-derived figure, which reads as
measured and is not. Neither changes the conclusion, and both exceed a single cycle, so the
gap below stands either way.

**I have labelled the figure as observed rather than extending the timing model**, deliberately:
inventing an extra term to make ~36s come out right would be fitting a model to three points,
and the reason the greens cluster so tightly is exactly what would make such a fit look
convincing. The gap is recorded as an open question, not resolved. It does not affect any
conclusion here — every argument below rests on the *bimodality*, not on the green mode's
absolute duration — but whoever investigates the red mode should know the green mode is not
fully explained either.

**A budget increase would very likely not convert a red into a green** — within the bound
the red mode does not look slow, it looks stuck. **Inferred, not tested:** the inference is
from the sawtooth signature — the red mode reaches and defers repeated punch windows rather
than approaching success — and no run was made against a longer budget to confirm it.

## What the code says (measured from source, not inferred)

- The defer line is emitted from `main.rs`'s in-trial preemption check when
  `state.is_some() && directive_should_punch(state, pointed)` is **false**.
  `path.rs::directive_should_punch` is
  `matches!(state, None | Some(PathState::Connecting)) && !relay_pointed`.
  So a defer means **either** the peer's `relay_pointed` pin is still set **or** the local
  path state has left `Connecting`.
- On the relay-death path the pin *is* cleared: `path.rs`'s `Relayed` arm emits
  `PathAction::RelayDied` (not `MarkRelayNeeded`) precisely so the driver tears down the
  dead transport **and clears `relay_pointed`** before the next punch window.
- `CASE4_RECOVERY_BUDGET`'s own doc states the expected shape: "one or two
  `Disconnected -> Connecting -> StartPunch` cycles (backoff 4-16s + `CONNECT_TIMEOUT` 10s
  each)" — i.e. **14–26s** for one cycle. The greens are the right *shape* (detection, then
  one recovery ladder) but **not an exact match**: see below.

## Open question for Phase C — hypothesis, explicitly not measured

**Why does the relay-leg-death path sometimes fail to get a clean punch window within the
125s bound?**

The assertion's own panic text attributes a red to the pre-fix mechanism: *"a relay leg
dead of silence (TimedOut) never clears `relay_pointed`, so every StartPunch cycle defers
its punch trial"*. On post-fix code that attribution looks **incomplete**, because
`RelayDied` clears the pin. The other disjunct in `directive_should_punch` is then the
candidate: the local state has left `Connecting`.

**Hypothesis (NOT measured): the two sides' recovery cycles fall out of phase.** A direct
punch is a simultaneous-open — it needs both ends punchable at overlapping instants. The
red signature is asymmetric (gwA `connecting` while gwB `disconnected`), which is what an
out-of-phase sawtooth looks like: gwA opens a window while gwB is in backoff; gwA's trial
finds nobody, times out, re-enters backoff; by the time gwB is `Connecting`, gwA is not.
Each spawned-then-yielded trial emits one defer line, which fits 11 lines / 3 defers per
side over ~90s of recovery budget. Nothing here rules out a residual pin on one side; both
disjuncts remain open.

**What would settle it** (for whoever picks this up — none of this was run):
1. Log or assert `relay_pointed` per side at each defer, separating the two disjuncts. If
   the pin is always clear, the phase hypothesis survives and the panic text needs
   rewording.
2. Record both sides' `PathState` transitions with timestamps across the recovery window
   and check whether `Connecting` spells ever overlap in the red runs.
3. If they never overlap, the lever is de-correlating the two sides' backoff (jitter, or
   an explicit rendezvous), **not** a longer budget.

**A documentation consequence regardless of which disjunct wins, and note precisely where it
lives:** the *doc comment* above the assertion tells the story correctly, in the past tense —
it describes what pre-fix code did. The *panic text* states it in the **present** tense, as
the explanation for the failure now being reported, and names **only one of the two disjuncts
in `directive_should_punch`** — the stale `relay_pointed` pin. So a reader hitting this red
today is handed one candidate cause by the failure itself, with no hint that a second exists.

**The correction is to name both, not to substitute the other.** It would be equally wrong to
rewrite the panic text around the phase hypothesis: `RelayDied` clearing the pin on the
current code is verified, but **whether the RED mode involves a residual pin on one side is
precisely the open question** — the instrumentation that would separate the disjuncts
(item 1 above) has not been run. Until it has, the honest panic text says the punch was
deferred and that either a residual relay pin or a path state that has left `Connecting`
can cause it.

Correct the panic text only; the past-tense doc comment above it is accurate and should be
left alone.

## What NOT to do

**Do not widen `CASE4_RECOVERY_BUDGET`, and do not add retries.** Two independent reasons:

1. The failure is **not** a near-miss. Greens recover at ~66s against a 125s bound —
   roughly half the budget unused — and the red mode shows no sign of approaching success:
   it spends the budget deferring repeated punch windows. So raising the number most likely
   changes nothing except how long CI waits to tell you. (Inferred from the signature; no
   longer-budget run was made. If someone wants to close that gap cheaply, a single red
   reproduced against a doubled `CASE4_RECOVERY_BUDGET` would settle it.)
2. The assertion is the aether-prod-fi-01 wedge's regression bar. It requires the
   `path_state=direct` LABEL and not merely a flowing ping, deliberately: on wedged code a
   stale pin routes every corroborated handshake away from the Direct cutover, so
   accidental data-plane luck can never fake it. Loosening any part of that gives back the
   only thing standing between the fabric and a repeat of that incident.

The standing rule from the sibling note applies verbatim: **characterise, do not widen.**

## Operational consequence in the meantime

At roughly a third to a half, **a single red run of case 4 is not sufficient evidence of a
regression** — and symmetrically, a single green is not sufficient evidence that a change is
innocent. One run evidences its own result; it does not attribute that result to a change.
Observing and attributing are different acts, and this case's failure rate is high enough
that a single observation supports neither direction.

The asymmetry people naturally apply here — a red demands investigation, a green closes the
question — is exactly backwards for a bimodal case: the green mode is the common one, so a
green is the *less* informative of the two.

Judge it over several runs, and prefer isolated repeats to full-suite runs when
attributing — the isolated repeats here are what proved the host was uncontended and
turned "the suite was slow" into a real bimodality. And attribute on mechanism where you
can: this case was cleared for PR5 not by counting runs but by showing the only executable
change in the range never executed.
