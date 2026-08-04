# Owner decision: defer the OpenBao reference driver out of the backlog program

**Date:** 2026-08-04. **Decided by:** owner, during the post-v0.4.0 backlog program.
**Status:** deferred, not cancelled. The spec is unamended.

## What was deferred

Cycle 2b's OpenBao `SecretStore`/`CertificateIssuer` driver and its containerized
conformance arm — item 6 of the six-item backlog program, scoped in
`backlog-program-notes.md` §B12 (8 tasks).

## Why it was in the backlog at all

Not a product decision to adopt a secrets manager. It comes from **D6** in the approved
engineering design (`2026-07-15-wiremesh-engineering-design.md:33`, marked "extends PRD"),
which commits v1 to shipping *the seams plus one reference provider proving them*:

> v1 ships the traits, the embedded defaults, and one full reference provider:
> Vault/OpenBao (KV + PKI engine)… Embedded remains the zero-dependency default — the
> quickstart never requires an external manager.

Reaffirmed as P0 at spec:484, scheduled as a fast-follow by D-C2-3 in the controller-core
design, and carried in CLAUDE.md's pending list.

## Why deferring is safe

- **The seams already exist and are exercised.** `wiremesh-trust` defines the traits,
  `EmbeddedTrust` implements them, and `tests/conformance.rs` is already parameterized over
  a provider with the embedded arm green. Nothing ships broken or half-built.
- **Embedded is the documented default** and the quickstart never requires an external
  manager, so no user-facing capability is missing.
- The driver's cost is real and front-loaded: a `bao` binary in the dev container, a new
  feature-gated conformance suite with no CI to run it, and — the riskiest single task in
  the whole program — an **enrollment transaction reorder**, forced because OpenBao cannot
  stamp caller-supplied serials, so `CertProfile::serial: Some(_)` must be rejected and the
  flow becomes txn-1 token-spend → sign → txn-2 cert row, with a compensating mark-failed
  and an orphan sweep.

## The argument for building it anyway, recorded for whoever revisits

A seam with exactly one implementation is an untested abstraction. The B12 scoping already
found one place where the trait shape does not survive contact with a real backend (the
serial-stamping assumption above), which is precisely the class of defect a second driver
exists to surface. Deferring means that class stays undiscovered until someone integrates
for real.

The counter-argument, which carried: better to learn that shape from an actual integration
requirement than from a guess at what Vault users need.

## When to revisit

When someone asks for external PKI/secrets integration. At that point the driver's shape is
informed by a real deployment rather than inferred, and the B12 scoping in
`backlog-program-notes.md` is still valid as a starting point — it was verified against the
code, not written from the spec alone.

The spec was **not** amended. D6 still stands; this is a schedule decision, not a scope
reduction. If v1 ships without any reference driver, D6 should be amended explicitly at that
point rather than left silently unmet.
