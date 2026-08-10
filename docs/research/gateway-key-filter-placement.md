# Where the active-pubkey filter belongs (backlog item 23) — and why the 6
# gateway test failures were fixture rot, not a design defect

**Date:** 2026-08-10
**Trigger:** items 23/24 landed clean against their own new tests but broke 6
pre-existing tests in `cargo test -p wiremesh-gateway --lib` (107 passed, 6
failed). This note investigates and records the finding per the project's
"a failing behaviour test may be a real design finding — investigate before
touching anything" rule.

## The two groups, and why they are different

**Group 1** — `state::tests::{from_snapshot_picks_active_key_and_endpoint,
active_pubkey_b64_still_populated, apply_delta_upserts_and_removes}`. All
three construct a `Peer`/`Delta` with a placeholder **active** pubkey
("PUBA", "KA", "PUBA2") and assert `PeerState::from_proto`/`apply_delta`
copies it through verbatim into `active_pubkey_b64`. Item 23 added
`.filter(|pubkey| uapi::pubkey_b64_to_hex(pubkey).is_some())` to that
derivation, so a placeholder that was never valid WireGuard key material
(never valid base64 of exactly 32 bytes) now becomes `None`.

**Group 2** — `reconcile::tests::{pending_endpoint_does_not_read_the_epoch_
numbers_at_all, pending_endpoint_is_the_reserved_offset_at_every_epoch_
distance, the_port_a_peer_dials_is_the_port_the_allocator_reserves}`. All
three construct a peer with a placeholder **pending** pubkey ("KP") and call
`pending_peer_configs`, which item 23 also touched — but at a different
site: `pending_peer_configs`'s own body now does
`crate::uapi::pubkey_b64_to_hex(&pending.pubkey_b64)?` after `pending_key()`.

**Both groups are fixture rot, not a design defect**, but the reason
requires looking at what each field's decodability actually gates —
`active_pubkey_b64` gates nothing but "does the peer go on the device";
`pending.pubkey_b64` gates an actual branch in `rotation::decide_role_b`.
That asymmetry is why the two checks correctly live in different places, and
is the crux of the finding below.

## Why the ingest filter (not a builder filter) is correct for `active_pubkey_b64`

The predecessor's PR message argued the ingest filter in
`PeerState::from_proto` is misplaced because it changes
`rotation::decide_role_b`'s outcome by turning `peer.active_key()` into
`None`. **That specific claim does not hold up: it was investigated and
found to be incorrect.**

`decide_role_b` (`rotation.rs:162-176`) reads `peer.active_key()`, which
searches `PeerState::keys` (`self.keys.iter().find(|k| k.state ==
"active")`). `PeerState::keys` is populated **unconditionally** in
`from_proto` — every advertised key/epoch/state triple is kept verbatim,
with no decodability filter applied to it at all:

```rust
let keys = p.keys.iter().map(|k| PeerKeyInfo { epoch: k.epoch, pubkey_b64: k.pubkey.clone(), state: k.state.clone() }).collect();
```

So `active_key()`'s presence check is **entirely independent** of whether
`active_pubkey_b64` (a separately-derived convenience field) is filtered.
Nulling an undecodable `active_pubkey_b64` at ingest cannot flip
`decide_role_b`'s `Skip`/`Start`/`Restart`/`Unusable` outcome, because that
function never reads `active_pubkey_b64` — only `_active` is bound (and
discarded) from `peer.active_key()`, and only the **pending** key's
decodability is checked (`RoleBDecision::Unusable`). Moving the
`active_pubkey_b64` filter to the encode builders would not change
`decide_role_b`'s behaviour one bit.

**The real (and different) place `active_pubkey_b64`-vs-`keys` filtering
divergence bites is `rotation::new_epoch_watch_keys`, not `decide_role_b`.**
That function's post-cutover branch reads `peer.active_pubkey_b64.as_deref()`
directly and has a *documented, still-unit-tested* fallback for the case
where that value decodes to `Some(<undecodable string>)`:
`post_cutover_undecodable_active_key_falls_back_to_the_snapshot`
(`tests/epoch_watch_keys.rs:243`) asserts an undecodable active key must
watch the directive-time snapshot hex, **not** immediately report
`EpochWatch::Gone` — because the same undecodable key would also make
`uapi::encode_set` fail, so the device still holds whatever it last held,
and watching the (correct, still-live) snapshot hex avoids stalling the
retire-grace timer.

With the ingest filter in `PeerState::from_proto` (and its mirrored
`deserialize_with` shim on `state.json`) in place, `active_pubkey_b64` can
**never** actually be `Some(<undecodable>)` for a `PeerState` that arrived
through either real door — both doors already collapse "undecodable" into
`None` before `new_epoch_watch_keys` ever sees it. So that documented,
tested fallback branch is real code, still exercised by a test that builds
`PeerState` by hand, but **unreachable from any real Sync snapshot/delta or
persisted `state.json`** in this build. That is a legitimate, if minor,
inconsistency worth flagging — see "Left as-is" below — but it does not
argue for moving the filter, and it is not what broke the 6 tests.

## Why moving the filter to the builders is disqualified

The predecessor's proposed fix was to strip the ingest filter and instead
check `uapi::pubkey_b64_to_hex(..).is_some()` at every builder that consumes
`active_pubkey_b64` (`peer_configs`, `device_config_pinned`,
`device_config_at_port`). This was checked against the whole crate, not
guessed, and it is **disqualified**: it would fix the 3 Group-1 tests while
breaking a much larger number of *currently-passing* tests elsewhere.

`crates/wiremesh-gateway/tests/apply_make_before_break.rs` and
`crates/wiremesh-gateway/tests/keepalive_emission.rs` construct `PeerState`
directly (bypassing `from_proto` entirely, so today's ingest filter never
touches them) with placeholder active pubkeys — `"K2"`, `"K3"`, `"K4"`,
`"K4-new"`, `"K2-promoted"` (22 occurrences across the two files) — and feed
them straight into `device_config_pinned`/`peer_configs`, asserting the
peer **is** retained in the resulting `DeviceConfig`. None of those literals
are valid base64-of-32-bytes. Adding a decodability check at those builders
would silently drop every peer in both suites, failing roughly a dozen
tests covering make-before-break endpoint pinning and the T1 persistent-
keepalive fix — for a net regression far larger than the 3 tests the move
was meant to fix.

This is exactly the blast-radius reason `PeerState::candidates`'
(item 1) and `PeerState::allowed_ips`' (item 24) filters are *also* placed
at the single Sync-ingest door rather than at each builder — see
`from_proto`'s own comment: "deliberately not per-builder checks, which
would be three chances to add a fourth builder without one." `active_pubkey_
b64` is the same shape of problem: one derived field, several consumers
(`reconcile::{peer_configs, device_config_pinned, device_config_at_port}`,
and `main.rs`'s scoped `apply_peer_endpoint_scoped` target-pubkey
resolution), and a single door that must not be reopened by a future
consumer added later.

## Why an identity field (`active_pubkey_b64`) is not `candidates`/`allowed_ips`

`candidates` and `allowed_ips` are filtered **per-entry** — a bad entry
costs only itself, the peer keeps every other entry, and per-builder
filtering was never on the table because the filter never had to choose
"keep or drop the whole peer." `active_pubkey_b64` is different in kind: it
is not a list, it is the peer's identity for `PeerConfig.public_key_b64`
(a bare `String`, not `Option`), so there is no "keyless" WG peer block —
undecodable is peer-fatal, full stop. The filter's JOB there is "does this
peer exist on the device," which is exactly the kind of single global
answer that belongs at one door, not re-derived per builder. `pending`'s
key is different again (see next section), which is why it alone is
checked at the builder.

## Why `pending_key`'s check correctly lives at the builder, unlike `active`'s

Item 23's own comment in `pending_peer_configs` (reconcile.rs:76-87)
explains this precisely: `pending_key()` only screens the controller's
`"awaiting-submission"` sentinel; a real-but-undecodable pending pubkey
reaches the builder unfiltered on purpose, **because
`rotation::decide_role_b` needs to distinguish "unusable pending key"
(`RoleBDecision::Unusable`) from "no pending key at all" (`Skip`) using that
same `pubkey_b64_to_hex` check** — dropping the entry at ingest would
collapse a real decision branch. `decide_role_b` has no equivalent branch
for the *active* key's decodability (as shown above, it only checks
presence), so there is no distinction to preserve there, and no reason not
to filter it once at the single door instead of at N builders. The
predecessor's framing — "the exact same class of problem ... introduced for
active ones" — treated the two keys as symmetric because both feed
`PeerConfig.public_key_b64`, but they are not symmetric in what
`decide_role_b` needs from them, which is the actual reason for the
placement difference.

## Fixes applied

- **Group 1** (`crates/wiremesh-gateway/src/state.rs`): `PeerState::from_
  proto`'s active-key ingest filter and its `deserialize_valid_active_
  pubkey` shim are **left exactly as they are** (confirmed correctly
  placed, not moved). The 3 failing tests' placeholder active pubkeys were
  replaced with real 32-byte-base64 WG-shaped key material (`VALID_KEY_AA/
  BB/CC`, base64 of 32 repeated bytes) — same literal convention already
  used in `tests/peer_key_and_allowedips_validation.rs`. No assertion, test
  name, or logic changed; only the identity value flowing through an
  identity-passthrough assertion was corrected to a value that assertion
  can actually observe post-filter.
- **Group 2** (`crates/wiremesh-gateway/src/reconcile.rs`): `pending_peer_
  configs`'s builder-level decodability check is **left exactly as it is**
  (confirmed correctly placed). The 3 failing tests' placeholder pending
  pubkeys ("KP") were replaced with `VALID_PENDING_KEY` (base64 of 32 bytes
  of `0xDD`). Same rule: no assertion/logic changed, only the fixture value.
- No production code was changed by this fix — item 23/24's actual
  filtering logic in `state.rs`/`reconcile.rs` was correct as shipped. The
  regression was entirely pre-existing fixtures using pubkey placeholders
  that could never occur in production, now correctly rejected by
  decodability checks that didn't exist when those fixtures were written.

## Left as-is (not a required change, flagged for awareness)

`rotation::new_epoch_watch_keys`'s "undecodable-`Some`-falls-back-to-
snapshot" branch (see above) is currently unreachable from any real
production data path, only from a test that constructs `PeerState`
directly. This is not a bug — the peer-drop outcome the ingest filter
produces instead (`EpochWatch::Gone`) is *more* conservative, not less safe,
and controller-side `Enroll` validation (this branch, item 23/24's sibling
work) means an undecodable *advertised* active key should now be rare to
impossible in practice, not a live path. Flagging only so a future cleanup
doesn't mistake the still-green `post_cutover_undecodable_active_key_falls_
back_to_the_snapshot` test for dead weight and delete the defensive
fallback it protects — it remains correct defense-in-depth for any future
code path that constructs `PeerState` without going through the two
filtered doors (`from_proto`/`deserialize_with`).

## The wrong turn, and the lesson

The investigation that led to this note started from a specific hypothesis
(recorded here rather than silently corrected, because a note that keeps
only the right answer loses the more useful part): that ingest-filtering
`active_pubkey_b64` in `PeerState::from_proto` was itself the bug, because
it would flip `rotation::decide_role_b`'s presence check on `peer.active_
key()` from `Some` to `None` — the same class of silent rotation-behaviour
change the project had already refused to accept for `pending` keys, now
supposedly reintroduced for `active` ones.

That hypothesis does not survive reading `active_key()`'s body:

```rust
pub fn active_key(&self) -> Option<&PeerKeyInfo> {
    self.keys.iter().find(|k| k.state == "active")
}
```

It searches `PeerState::keys`, not `PeerState::active_pubkey_b64`. Those are
two different fields, populated by two different lines in `from_proto`:
`keys` unconditionally, `active_pubkey_b64` filtered. They both start from
the same controller-advertised `Peer.keys`, they are named similarly enough
to read as "the same fact stored twice," and for exactly this reason it is
easy to reason about one while actually looking at code that reads the
other. `decide_role_b` is built entirely on `keys` (`active_key()`,
`pending_key()`) — it is the *authoritative* representation rotation state
machines decide from. `active_pubkey_b64` is a *derived* convenience field
that exists only so the encode builders (and `apply_peer_endpoint_scoped`)
don't each have to re-run "find the active entry in `keys`" themselves, and
it is allowed to be lossier than `keys` (collapsing "undecodable" to
"absent") precisely because nothing decision-making reads it.

**The general lesson:** when a struct carries two fields that look like
restatements of the same fact, check which one a given consumer actually
reads before reasoning about what filtering either of them changes. Here
that check reversed the conclusion entirely — the field the failing tests
exercised (`active_pubkey_b64`) is not the field the suspected consumer
(`decide_role_b`) reads at all. The genuine analogous risk (`new_epoch_
watch_keys`, previous section) was found only by doing that same check for
every other reader of `active_pubkey_b64` in the crate, not by re-trusting
the first hypothesis.

## Fixture-rot precedent

This is the same class of problem `SubmitEpochKey`'s controller-side
deferral turned up: pre-existing test fixtures across this codebase use
placeholder pubkeys ("PUBA", "K2", "KA", ...) that were never valid
WireGuard key material and could never occur against a real controller/
peer. They were harmless as long as nothing checked decodability; item
23/24 is the first code to actually call `uapi::pubkey_b64_to_hex` on
these fields at these specific doors, and it correctly flagged them.
`apply_make_before_break.rs` and `keepalive_emission.rs` still carry ~22
such placeholders (`"K2"`/`"K3"`/`"K4"`/`"K4-new"`/`"K2-promoted"`) — they
are currently safe only because they bypass `from_proto` by constructing
`PeerState` directly and the builders they call (`device_config_pinned`,
`peer_configs`) do not independently check decodability. Worth a future
pass to migrate them to real key material for realism, but out of scope
here: doing so is a pure fixture change with no code impact, is not part of
what item 23/24 broke, and touching it now would expand this fix's diff
into two files "another lane" was not asked to review.
