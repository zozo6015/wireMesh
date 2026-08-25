//! FAILING tests (test-author, operator review round) — MAJOR:
//! `wiremesh-relay-enroll` is NOT idempotent. Runtime-RED (every API used here
//! exists today; the behavior is what must change).
//!
//! # The bug
//!
//! `wiremesh_relay::enroll::run_enroll` (src/enroll.rs:51-83) ALWAYS redeems:
//! it reads the CA, calls `wiremesh_enroll::enroll(..)`, and writes the identity
//! — with no check for an identity already on disk. `src/bin/enroll.rs:27-31`
//! drives it unconditionally on every invocation. The gateway fixed exactly
//! this (src/enroll.rs:48-55, `Identity::probe` → skip), which is what makes its
//! K8s init-container safe to run on EVERY boot once the identity lives on a
//! PVC. The relay has no such skip, so once its identity is persisted (the
//! relay PVC this same round adds), the next pod start re-redeems the SPENT
//! single-use token and Init:Errors — the identical wedge the PVC was meant to
//! cure.
//!
//! # Expected fix (mirror the gateway, including its logging)
//!
//! Before reading the CA / dialing the controller, classify the on-disk identity
//! in `certdir`:
//!   * `ca.pem` AND `relay.pem` AND `relay.key` all present and non-empty
//!       → SKIP: log the gateway's line shape
//!         (`wiremesh-relay: already enrolled (identity present in <certdir>), skipping`)
//!         to stderr and return `Ok(())` WITHOUT reading the CA or dialing.
//!   * any of the three missing/empty (a partial or truncated identity — e.g. a
//!     crash mid-write) → fall through to the real enrollment, unchanged.
//!   * any OTHER io error while probing (EACCES/EIO/…) → PROPAGATE as `Err`,
//!     never enroll (an unreadable-but-possibly-present identity must not be
//!     clobbered by spending the single-use token) — the gateway's third arm.
//!
//! Suggested seam, mirroring `Identity::probe`:
//! ```ignore
//! /// Ok(true) = complete identity present; Ok(false) = absent/partial;
//! /// Err = other IO failure.
//! pub fn probe_identity(certdir: &Path) -> anyhow::Result<bool>;
//! ```
//! `run_enroll`'s signature is unchanged — the skip is observable behaviorally,
//! which is exactly how the gateway's `tests/enroll_idempotent.rs` proves it and
//! how these tests do too.

// The doc comment above column-aligns its continuation lines under the list
// item they belong to. Clippy wants them at the minimum indent, which
// ragged-edges a table a human laid out on purpose, so the disagreement is
// recorded here rather than resolved against the reader.
#![allow(clippy::doc_overindented_list_items)]

use std::os::unix::fs::PermissionsExt;
use wiremesh_proto::v1::MintTokenRequest;
use wiremesh_relay::enroll::{run_enroll, EnrollArgs};

const IDENTITY_FILES: [&str; 3] = ["ca.pem", "relay.pem", "relay.key"];

/// An address with no listener: any controller dial from here fails, so a run
/// that returns `Ok` PROVES no dial happened.
const UNREACHABLE: &str = "127.0.0.1:1";

/// Write a complete, plausible relay identity into `certdir` (as a prior enroll
/// would have left it on the PVC).
fn write_complete_identity(certdir: &std::path::Path) {
    std::fs::create_dir_all(certdir).unwrap();
    std::fs::write(
        certdir.join("ca.pem"),
        "-----BEGIN CERTIFICATE-----\nCC\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        certdir.join("relay.pem"),
        "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        certdir.join("relay.key"),
        "-----BEGIN PRIVATE KEY-----\nBB\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    for f in IDENTITY_FILES {
        std::fs::set_permissions(certdir.join(f), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn snapshot(certdir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    IDENTITY_FILES
        .iter()
        .map(|f| (f.to_string(), std::fs::read(certdir.join(f)).unwrap()))
        .collect()
}

/// Mint a fresh relay token against a live test controller.
async fn mint_relay_token(h: &wiremesh_testkit::TestController) -> String {
    let mut admin = h.admin_client().await;
    admin
        .mint_token(MintTokenRequest {
            kind: "relay".into(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token
}

#[tokio::test]
async fn enroll_skips_when_complete_identity_present_and_issues_no_rpc() {
    // THE fix's core guarantee, proven the same way the gateway's is: point
    // `--controller` at an address with no listener. A correct idempotent enroll
    // returns Ok purely from the on-disk identity; the current always-redeems
    // code dials and returns Err (connection refused).
    let dir = tempfile::tempdir().unwrap();
    let certdir = dir.path().join("relay-id");
    write_complete_identity(&certdir);
    let before = snapshot(&certdir);

    // A CA file that EXISTS, so that even if the skip check runs after the CA
    // read, the read succeeds and the only operation left that could fail is the
    // controller dial — which a correct idempotent enroll must never perform.
    let ca_path = dir.path().join("controller-ca.pem");
    std::fs::write(
        &ca_path,
        "-----BEGIN CERTIFICATE-----\nCC\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    let res = run_enroll(EnrollArgs {
        token: "wiremesh://unused-token".into(),
        controller: UNREACHABLE.into(),
        ca_path,
        certdir: certdir.clone(),
        endpoint: "203.0.113.10:51820".into(),
    })
    .await;

    assert!(
        res.is_ok(),
        "relay enroll must SKIP (exit 0) when a complete identity is already present, \
         without dialing the controller; got {res:?}"
    );

    // The existing identity must be left byte-for-byte untouched — not
    // re-enrolled, not re-keyed.
    assert_eq!(
        snapshot(&certdir),
        before,
        "the pre-existing relay identity must be left byte-for-byte untouched on skip"
    );
    for f in IDENTITY_FILES {
        assert_eq!(
            std::fs::metadata(certdir.join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "{f} must still be mode 0600 after the skip"
        );
    }
}

#[tokio::test]
async fn enroll_skip_precedes_the_ca_read() {
    // The gateway's skip returns BEFORE generating a keypair, reading the CA, or
    // dialing. Pin the same ordering for the relay: with a complete identity, a
    // NON-EXISTENT `--ca` path must still skip successfully — proving the probe
    // runs first. (Today `run_enroll` reads the CA at its very first line, so
    // this fails with "reading CA bundle ...".)
    let dir = tempfile::tempdir().unwrap();
    let certdir = dir.path().join("relay-id");
    write_complete_identity(&certdir);

    let res = run_enroll(EnrollArgs {
        token: "wiremesh://unused-token".into(),
        controller: UNREACHABLE.into(),
        ca_path: dir.path().join("does-not-exist-ca.pem"),
        certdir,
        endpoint: "203.0.113.10:51820".into(),
    })
    .await;

    assert!(
        res.is_ok(),
        "the identity probe must run BEFORE the CA read (mirroring the gateway's skip, \
         which precedes keypair gen / CA read / dial); got {res:?}"
    );
}

#[tokio::test]
async fn enroll_does_not_skip_on_a_partial_identity() {
    // Regression guard (expected GREEN today, must STAY green): a partial
    // identity is NOT a skip. With one of the three files missing and an
    // unreachable controller, enroll must still attempt enrollment → Err. If a
    // future "skip" were keyed off, say, ca.pem alone, this would wrongly pass
    // through as Ok and the relay would boot with an unusable identity.
    for missing in IDENTITY_FILES {
        let dir = tempfile::tempdir().unwrap();
        let certdir = dir.path().join("relay-id");
        write_complete_identity(&certdir);
        std::fs::remove_file(certdir.join(missing)).unwrap();

        let ca_path = dir.path().join("controller-ca.pem");
        std::fs::write(
            &ca_path,
            "-----BEGIN CERTIFICATE-----\nCC\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let res = run_enroll(EnrollArgs {
            token: "wiremesh://unused-token".into(),
            controller: UNREACHABLE.into(),
            ca_path,
            certdir,
            endpoint: "203.0.113.10:51820".into(),
        })
        .await;

        assert!(
            res.is_err(),
            "a partial identity (missing {missing}) must NOT be treated as enrolled — \
             enroll must proceed (and here fail on the unreachable controller); got {res:?}"
        );
    }
}

#[tokio::test]
async fn partial_identity_reenrolls_against_a_live_controller() {
    // The positive half of the previous test: with a real controller, a partial
    // identity falls through to a REAL enrollment that completes and writes all
    // three files at 0600 (the existing `enroll_cmd.rs` guarantee, preserved on
    // the partial-identity path).
    let h = wiremesh_testkit::TestController::start().await;
    let token = mint_relay_token(&h).await;

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("controller-ca.pem");
    std::fs::write(&ca_path, h.ca_bundle_pem()).unwrap();
    let certdir = dir.path().join("relay-id");
    write_complete_identity(&certdir);
    // Only relay.key is missing → the identity is incomplete.
    std::fs::remove_file(certdir.join("relay.key")).unwrap();

    run_enroll(EnrollArgs {
        token,
        controller: h.tcp_addr().to_string(),
        ca_path,
        certdir: certdir.clone(),
        endpoint: "203.0.113.10:51820".into(),
    })
    .await
    .expect("a partial identity must fall through to a real enrollment");

    for f in IDENTITY_FILES {
        let meta = std::fs::metadata(certdir.join(f)).unwrap_or_else(|_| panic!("{f} must exist"));
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "{f} must be mode 0600"
        );
    }
    let relay_pem = std::fs::read_to_string(certdir.join("relay.pem")).unwrap();
    assert!(
        relay_pem.contains("BEGIN CERTIFICATE"),
        "relay.pem must be the freshly issued leaf certificate"
    );
}

#[tokio::test]
async fn truncated_identity_file_is_not_a_complete_identity() {
    // "Complete" must mean usable, not merely present — mirroring the gateway,
    // whose probe is a structural parse of identity.json (an empty file fails it
    // and falls through). A zero-length relay.key is what a crash mid-write
    // leaves behind; skipping on it would boot the relay with an unusable
    // identity and no path to recovery.
    let h = wiremesh_testkit::TestController::start().await;
    let token = mint_relay_token(&h).await;

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("controller-ca.pem");
    std::fs::write(&ca_path, h.ca_bundle_pem()).unwrap();
    let certdir = dir.path().join("relay-id");
    write_complete_identity(&certdir);
    std::fs::write(certdir.join("relay.key"), b"").unwrap();

    run_enroll(EnrollArgs {
        token,
        controller: h.tcp_addr().to_string(),
        ca_path,
        certdir: certdir.clone(),
        endpoint: "203.0.113.10:51820".into(),
    })
    .await
    .expect("a zero-length identity file must NOT count as enrolled; enroll must proceed");

    let key = std::fs::read(certdir.join("relay.key")).unwrap();
    assert!(
        !key.is_empty(),
        "the re-enroll must have written a real private key"
    );
}
