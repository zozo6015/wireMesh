// crates/wiremesh-trust/tests/embedded.rs
//
// RED test for Task 2: the embedded default CertificateIssuer must sign a
// gateway-generated CSR into a leaf that (a) is a real cert PEM, (b) chains
// to the CA's `trust_bundle()`, (c) whose bundle contains no private key,
// and (d) whose `ca.key` on disk is mode 0600.
//
// `verify_chains` performs *real* cryptographic chain verification (via
// rustls-webpki) — it is not a substring/string check. It parses both PEMs,
// builds a trust anchor from the CA cert, and asks webpki to verify the
// leaf's signature and validity against that anchor.
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use wiremesh_trust::{CertProfile, CertificateIssuer, EmbeddedTrust};

#[tokio::test]
async fn embedded_ca_signs_a_csr_that_chains_to_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let trust = EmbeddedTrust::open(dir.path()).unwrap();

    // A gateway generates its own keypair + CSR (rcgen) — the trust provider
    // never sees the gateway's private key, only the CSR PEM.
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "gw-aws");
    let csr = params.serialize_request(&kp).unwrap().pem().unwrap();

    let issued = trust
        .sign(
            &csr,
            CertProfile {
                subject_cn: "gw-aws".into(),
                ttl: Duration::from_secs(90 * 24 * 3600),
            },
        )
        .await
        .unwrap();
    assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(!issued.serial.is_empty());

    // The leaf verifies against the trust bundle.
    let bundle = trust.trust_bundle().await.unwrap();
    assert!(
        verify_chains(&issued.cert_pem, &bundle),
        "leaf must chain to CA bundle"
    );
    // CA private key must NOT be inside the bundle.
    assert!(!bundle.contains("PRIVATE KEY"));
    // CA key file is 0600.
    let mode = std::fs::metadata(dir.path().join("ca.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "ca.key must be 0600");
}

/// Real chain verification: does `leaf_pem` verify as having been issued by
/// (and only by) a CA in `bundle_pem`? This parses both PEMs to DER, treats
/// every certificate in `bundle_pem` as a trust anchor, and asks
/// rustls-webpki to build+validate the path — including the leaf's
/// signature over its TBS bytes against the CA's public key, and the
/// validity window. A leaf that is merely well-formed PEM but signed by an
/// unrelated key, or not signed at all, must fail this check.
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

    // Accept the current time as "now" — issued certs use a 90-day TTL in
    // this test, so there is no meaningful clock-skew risk here.
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
