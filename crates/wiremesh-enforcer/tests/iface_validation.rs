//! Backlog 10 PR-A (Cycle-3 hardening trio), test author — Item 3:
//! interface-name validation at the `probe()`/`probe_with()` boundary
//! (`src/lib.rs:141,166`).
//!
//! Today NEITHER entry point validates `iface` at all. The name flows
//! verbatim into:
//!  - `nft.rs` codegen (`table ip wiremesh_<iface>` and
//!    `iifname "<iface>"` — a name containing `"` / `}` / `#` is a raw
//!    nft-script injection vector at `apply()` time),
//!  - shelled-out `nft`/`conntrack` invocations and bpffs pin PATHS
//!    (`a/../../x` traverses out of the intended pin directory),
//!  - tc attach (where the kernel's own IFNAMSIZ limit — 15 bytes + NUL —
//!    surfaces only as a late, opaque attach failure).
//!
//! Expected fix: a `validate_iface()` check applied at the `probe_with`
//! boundary (before EITHER backend's constructor runs): non-empty, ≤ 15
//! bytes, charset `[A-Za-z0-9_.-]`, no leading `-` or `.`; rejection is an
//! immediate `Err` whose message contains `"invalid interface name"`.
//! These tests deliberately drive the existing PUBLIC `probe_with` surface
//! rather than referencing `validate_iface` directly, so the file is
//! **runtime-red** (it compiles today) and doesn't over-pin the helper's
//! name/signature — only the boundary behavior.
//!
//! RED evidence, verified against today's code:
//!  - `Nftables` arm: `NftEnforcer::new` is documented side-effect-free and
//!    returns `Ok` for ANY string — so every reject-case below currently
//!    gets `Ok(..)` from the nftables arm: a genuine, unambiguous red.
//!  - `Ebpf` arm: `EbpfEnforcer::new` fails for these names (no such
//!    iface / no privilege in an unprivileged run), but with a
//!    load/attach/permission error — NOT the `"invalid interface name"`
//!    message these tests require, so that half is red today too, and
//!    stays meaningful in both privileged and unprivileged environments.
//!
//! No test here needs root/netns: the nftables constructor never touches
//! the kernel before `apply()`, and the eBPF assertions only require that
//! the returned error be the VALIDATION error, which must fire before any
//! privileged work is attempted.

use wiremesh_enforcer::{probe_with, BackendKind, EnforcerConfig};

const VALIDATION_MSG: &str = "invalid interface name";

/// Asserts `probe_with` rejects `iface` IMMEDIATELY — on BOTH backends —
/// with the boundary-validation error, regardless of privilege or of
/// whether the interface exists.
fn assert_rejected(iface: &str, why: &str) {
    for kind in [BackendKind::Nftables, BackendKind::Ebpf] {
        match probe_with(kind, iface, EnforcerConfig::default()) {
            Ok(_) => panic!(
                "probe_with({kind:?}, {iface:?}) returned Ok — {why}; the name \
                 must be rejected at the boundary with an {VALIDATION_MSG:?} error"
            ),
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains(VALIDATION_MSG),
                    "probe_with({kind:?}, {iface:?}) must fail with the boundary \
                     validation error (containing {VALIDATION_MSG:?}), not a \
                     later backend error — {why}; got: {msg}"
                );
            }
        }
    }
}

/// Asserts iface validation does NOT reject `iface` (a legitimate Linux
/// interface name). In an unprivileged environment the probe may still
/// fail LATER for other reasons (eBPF load/attach needs privilege; the
/// interface may not exist) — the ONLY pin here is that any such failure
/// is not the boundary-validation error. Uses the nftables arm, whose
/// constructor is side-effect-free, so in practice this is `Ok` both today
/// and after the fix — the test exists to catch an over-restrictive
/// validator (e.g. one rejecting `.` in `eth0.100`).
fn assert_name_accepted(iface: &str) {
    match probe_with(BackendKind::Nftables, iface, EnforcerConfig::default()) {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e:#}");
            assert!(
                !msg.contains(VALIDATION_MSG),
                "{iface:?} is a valid Linux interface name and must NOT be \
                 rejected by iface validation; got: {msg}"
            );
        }
    }
}

/// nft-script injection: `"` closes the `iifname "<iface>"` string, `}`
/// closes a block, `#` comments out the rest of the line — a name like
/// this reaching `ruleset()`/`apply_script()` is an arbitrary-ruleset
/// injection. Must die at the probe boundary instead.
#[test]
fn probe_with_rejects_nft_injection_shaped_iface_name() {
    assert_rejected(
        "evil\" } accept #",
        "quote/brace/comment characters inject into nft codegen",
    );
}

/// Path traversal: the iface name is interpolated into bpffs pin paths;
/// `/` (and `..`) must be rejected outright.
#[test]
fn probe_with_rejects_path_traversal_iface_name() {
    assert_rejected("a/../../x", "'/' traverses bpffs pin paths");
}

/// IFNAMSIZ: Linux interface names are at most 15 bytes; a 16-byte name
/// can never exist and today only fails as a late, opaque attach error.
#[test]
fn probe_with_rejects_sixteen_byte_iface_name() {
    let name = "abcdefghijklmnop"; // 16 bytes, one over the 15-byte limit
    assert_eq!(name.len(), 16);
    assert_rejected(name, "16 bytes exceeds the kernel's 15-byte IFNAMSIZ limit");
}

/// Fifteen bytes is exactly at the limit — the length check must be
/// `> 15`, not `>= 15`. (Charset-valid, so only length is in play.)
#[test]
fn probe_with_accepts_fifteen_byte_iface_name() {
    let name = "abcdefghijklmno"; // 15 bytes, exactly at the limit
    assert_eq!(name.len(), 15);
    assert_name_accepted(name);
}

/// The empty name is not a valid interface and must be rejected
/// explicitly, not passed through to whatever a backend does with "".
#[test]
fn probe_with_rejects_empty_iface_name() {
    assert_rejected("", "the empty string is not an interface name");
}

/// A leading `-` reads as an option flag by every CLI the name is shelled
/// out to (`ip`, `nft`, `conntrack`); a leading `.` produces hidden/
/// relative path components in pin paths. Both are in the audited
/// validation spec.
#[test]
fn probe_with_rejects_leading_dash_and_leading_dot_iface_names() {
    assert_rejected("-wg0", "a leading '-' is an option-injection hazard");
    assert_rejected(".wg0", "a leading '.' is a hidden-path hazard");
}

/// The three audited legitimate shapes: plain (`wg0`), alphanumeric
/// (`wg0e12`), and VLAN dotted (`eth0.100` — `.` is valid when not
/// leading). None may trip iface validation.
#[test]
fn probe_with_accepts_legitimate_iface_names() {
    assert_name_accepted("wg0");
    assert_name_accepted("wg0e12");
    assert_name_accepted("eth0.100");
}
