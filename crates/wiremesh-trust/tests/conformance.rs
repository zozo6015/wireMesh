// crates/wiremesh-trust/tests/conformance.rs
//
// Provider-conformance suite (Task 17, Step 1): a single generic
// `run_conformance` that any `CertificateIssuer + SecretStore` backend must
// pass. Cycle 2 wires up only the embedded default
// (`embedded_default_passes_conformance`); the OpenBao-backed arm is the
// cycle-2b fast-follow and will call the same `run_conformance` against that
// provider once it exists.
//
// Idioms (CSR generation, `verify_chains`) are duplicated from
// `tests/embedded.rs` rather than shared, per the brief — duplication in a
// test file is acceptable here.
use std::time::Duration;

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use time::OffsetDateTime;
use wiremesh_trust::{CertProfile, CertificateIssuer, EmbeddedTrust, SecretStore};

/// The reusable conformance suite. Any backend implementing both traits must
/// pass every assertion here.
async fn run_conformance<C: CertificateIssuer + SecretStore>(p: &C) {
    // -----------------------------------------------------------------
    // 1. Issuance: sign a CSR -> leaf chains to trust_bundle().
    // -----------------------------------------------------------------
    let issued = p
        .sign(&gateway_csr("conformance-issuance"), profile_with_ttl(90 * 24 * 3600))
        .await
        .expect("issuance: sign must succeed for a valid CSR + profile");
    assert!(
        issued.cert_pem.contains("BEGIN CERTIFICATE"),
        "issuance: cert_pem must be a PEM certificate"
    );
    assert!(!issued.serial.is_empty(), "issuance: serial must be non-empty");

    let bundle = p
        .trust_bundle()
        .await
        .expect("issuance: trust_bundle must be readable");
    assert!(
        verify_chains(&issued.cert_pem, &bundle),
        "issuance: leaf must chain to the trust bundle"
    );

    // -----------------------------------------------------------------
    // 2a. Renewal-follows-TTL: a 90-day TTL yields not_after ~ now + 90d.
    // -----------------------------------------------------------------
    let ttl_90d = Duration::from_secs(90 * 24 * 3600);
    let before = OffsetDateTime::now_utc();
    let issued_90d = p
        .sign(&gateway_csr("conformance-ttl-90d"), CertProfile {
            subject_cn: "conformance-ttl-90d".into(),
            ttl: ttl_90d,
        })
        .await
        .expect("renewal-follows-ttl: a 90-day TTL must be accepted");
    let expected_not_after = before + time::Duration::seconds(90 * 24 * 3600);
    let tolerance = time::Duration::days(1);
    assert!(
        (issued_90d.not_after - expected_not_after).abs() <= tolerance,
        "renewal-follows-ttl: not_after {} must be within {:?} of now+90d ({})",
        issued_90d.not_after,
        tolerance,
        expected_not_after
    );

    // -----------------------------------------------------------------
    // 2b. Min-TTL refusal: a sub-24h TTL (here: 1 hour) must be REFUSED.
    // This is the key new assertion for cycle 2 — the embedded issuer must
    // enforce a 24h TTL floor rather than silently issuing a short-lived
    // leaf.
    // -----------------------------------------------------------------
    let sub_floor_ttl = Duration::from_secs(60 * 60); // 1 hour, below the 24h floor.
    let result = p
        .sign(&gateway_csr("conformance-ttl-too-short"), CertProfile {
            subject_cn: "conformance-ttl-too-short".into(),
            ttl: sub_floor_ttl,
        })
        .await;
    assert!(
        result.is_err(),
        "min-ttl-refusal: sign() with a 1-hour TTL (below the 24h floor) must return Err, got Ok"
    );

    // -----------------------------------------------------------------
    // 3. Revoke: revoke(handle) succeeds and is idempotent.
    // -----------------------------------------------------------------
    let issued_for_revoke = p
        .sign(&gateway_csr("conformance-revoke"), profile_with_ttl(90 * 24 * 3600))
        .await
        .expect("revoke: sign must succeed before revoking");
    p.revoke(&issued_for_revoke.handle)
        .await
        .expect("revoke: first revoke() call must succeed");
    p.revoke(&issued_for_revoke.handle)
        .await
        .expect("revoke: second revoke() call on the same handle must also succeed (idempotent)");

    // -----------------------------------------------------------------
    // 4. SecretStore: put/get roundtrip; monotonically increasing version.
    // -----------------------------------------------------------------
    let key = "conformance.secret";
    let v1 = p
        .put(key, b"first-value".to_vec())
        .await
        .expect("secretstore: first put must succeed");
    let got1 = p
        .get(key)
        .await
        .expect("secretstore: get must succeed")
        .expect("secretstore: key just written must be present");
    assert_eq!(got1.value, b"first-value".to_vec(), "secretstore: get must return exactly what was put");
    assert_eq!(got1.version, v1, "secretstore: get must report the version put() returned");

    let v2 = p
        .put(key, b"second-value".to_vec())
        .await
        .expect("secretstore: second put must succeed");
    let v3 = p
        .put(key, b"third-value".to_vec())
        .await
        .expect("secretstore: third put must succeed");
    assert!(
        v1 < v2 && v2 < v3,
        "secretstore: versions must strictly increase across puts, got {v1}, {v2}, {v3}"
    );

    let got3 = p
        .get(key)
        .await
        .expect("secretstore: get must succeed")
        .expect("secretstore: key must still be present");
    assert_eq!(got3.value, b"third-value".to_vec(), "secretstore: get must return the latest value");
    assert_eq!(got3.version, v3, "secretstore: get must report the latest version");
}

#[tokio::test]
async fn embedded_default_passes_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let p = EmbeddedTrust::open(dir.path()).unwrap();
    run_conformance(&p).await;
}

// ---------------------------------------------------------------------------
// Shared test idioms, duplicated from tests/embedded.rs.
// ---------------------------------------------------------------------------

fn profile_with_ttl(ttl_secs: i64) -> CertProfile {
    CertProfile {
        subject_cn: "conformance".into(),
        ttl: Duration::from_secs(ttl_secs as u64),
    }
}

/// A gateway generates its own keypair and a CSR for `cn`, returning the CSR
/// PEM. Mirrors `tests/embedded.rs::gateway_csr`.
fn gateway_csr(cn: &str) -> String {
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.serialize_request(&kp).unwrap().pem().unwrap()
}

/// Real chain verification: does `leaf_pem` verify as having been issued by
/// (and only by) a CA in `bundle_pem`? Mirrors `tests/embedded.rs::verify_chains`.
fn verify_chains(leaf_pem: &str, bundle_pem: &str) -> bool {
    let leaf_der = match first_cert_der(leaf_pem) {
        Some(d) => d,
        None => return false,
    };
    let anchor_ders = all_cert_ders(bundle_pem);
    if anchor_ders.is_empty() {
        return false;
    }

    let anchors: Vec<TrustAnchor<'_>> = anchor_ders
        .iter()
        .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
        .collect();
    if anchors.is_empty() {
        return false;
    }

    let end_entity = match webpki::EndEntityCert::try_from(&leaf_der) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let now = UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap(),
    );

    end_entity
        .verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            &anchors,
            &[],
            now,
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .is_ok()
}

fn first_cert_der(pem: &str) -> Option<CertificateDer<'static>> {
    all_cert_ders(pem).into_iter().next()
}

fn all_cert_ders(pem: &str) -> Vec<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .filter_map(Result::ok)
        .map(|der| der.into_owned())
        .collect()
}
