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
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use wiremesh_trust::{CertProfile, CertificateIssuer, EmbeddedTrust, SecretStore};

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
                subject_alt_names: vec![],
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

// ---------------------------------------------------------------------------
// Coverage additions (Task 2 review): SecretStore round-trip / versioning /
// concurrency, and CA reload-across-restart. These exercise load-bearing
// behavior the first test didn't touch.
// ---------------------------------------------------------------------------

/// A gateway generates its own keypair and a CSR for `cn`, returning the CSR
/// PEM — mirrors what the first test does inline.
fn gateway_csr(cn: &str) -> String {
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.serialize_request(&kp).unwrap().pem().unwrap()
}

fn profile(cn: &str) -> CertProfile {
    CertProfile {
        subject_cn: cn.into(),
        ttl: Duration::from_secs(90 * 24 * 3600),
        subject_alt_names: vec![],
    }
}

#[tokio::test]
async fn secret_store_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let trust = EmbeddedTrust::open(dir.path()).unwrap();

    let value = b"super-secret-wireguard-key".to_vec();
    let version = trust.put("gw1.wgkey", value.clone()).await.unwrap();
    // Documented base: versions start at 1 (see SecretStore::put docs).
    assert_eq!(version, 1, "first put must return version 1");

    let got = trust
        .get("gw1.wgkey")
        .await
        .unwrap()
        .expect("key just written must be present");
    assert_eq!(got.value, value, "get must return exactly what was put");
    assert_eq!(got.version, 1, "get must report the stored version");

    // A never-written key is absent, not an error.
    assert!(trust.get("gw1.never-written").await.unwrap().is_none());
}

#[tokio::test]
async fn secret_store_versions_increase_monotonically() {
    let dir = tempfile::tempdir().unwrap();
    let trust = EmbeddedTrust::open(dir.path()).unwrap();

    let v1 = trust.put("gw1.token", b"v-one".to_vec()).await.unwrap();
    let v2 = trust.put("gw1.token", b"v-two".to_vec()).await.unwrap();
    let v3 = trust.put("gw1.token", b"v-three".to_vec()).await.unwrap();

    assert!(
        v1 < v2 && v2 < v3,
        "versions must strictly increase, got {v1}, {v2}, {v3}"
    );
    assert_eq!((v1, v2, v3), (1, 2, 3), "expected 1,2,3 from a fresh key");

    // The latest value/version is what a reader sees.
    let got = trust.get("gw1.token").await.unwrap().unwrap();
    assert_eq!(got.value, b"v-three".to_vec());
    assert_eq!(got.version, 3);
}

/// Bug-catcher: two keys that share the stem before the final dot
/// (`gw1.wgkey` / `gw1.token`) must not clobber each other. The current impl
/// writes each secret through a temp file named `path.with_extension("tmp")`,
/// which collapses BOTH keys onto `secrets/gw1.tmp` — so genuinely concurrent
/// puts race on the same temp path and either cross-contaminate (one key ends
/// up holding the other's value) or a `rename` fails outright with ENOENT
/// because the sibling task already moved the shared temp file away.
///
/// This is a plain `#[test]` driving TWO OS threads (not `#[tokio::test]`):
/// `put` has no `.await` yield points between its file write and its rename,
/// so under a single-threaded runtime two spawned tasks would run to
/// completion one-after-another and the race would never surface (a false
/// green). Real threads with a per-round barrier make the two `put`s execute
/// simultaneously, so the shared-temp collision actually fires. Each key must
/// round-trip to its OWN value every round.
#[test]
fn secret_store_concurrent_puts_to_distinct_dotted_keys_do_not_collide() {
    use std::sync::Barrier;

    let dir = tempfile::tempdir().unwrap();
    let trust = Arc::new(EmbeddedTrust::open(dir.path()).unwrap());
    let verify_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    const ROUNDS: u32 = 200;
    for round in 0..ROUNDS {
        let wg_value = format!("wgkey-round-{round}").into_bytes();
        let tok_value = format!("token-round-{round}").into_bytes();
        // Fresh barrier per round so both threads enter `put` at the same
        // instant, maximizing overlap of the write+rename critical section.
        let barrier = Arc::new(Barrier::new(2));

        let wg_handle = {
            let trust = Arc::clone(&trust);
            let barrier = Arc::clone(&barrier);
            let value = wg_value.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                barrier.wait();
                rt.block_on(trust.put("gw1.wgkey", value))
            })
        };
        let tok_handle = {
            let trust = Arc::clone(&trust);
            let barrier = Arc::clone(&barrier);
            let value = tok_value.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                barrier.wait();
                rt.block_on(trust.put("gw1.token", value))
            })
        };

        // A failed rename (the shared temp file was moved out from under this
        // task by the sibling) surfaces here as an Err → panic → RED.
        wg_handle
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("round {round}: put gw1.wgkey failed: {e:#}"));
        tok_handle
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("round {round}: put gw1.token failed: {e:#}"));

        let wg_got = verify_rt.block_on(trust.get("gw1.wgkey")).unwrap().unwrap();
        let tok_got = verify_rt.block_on(trust.get("gw1.token")).unwrap().unwrap();
        assert_eq!(
            wg_got.value, wg_value,
            "round {round}: gw1.wgkey must hold its own value, not gw1.token's"
        );
        assert_eq!(
            tok_got.value, tok_value,
            "round {round}: gw1.token must hold its own value, not gw1.wgkey's"
        );
    }
}

/// Regression guard for the reload path (Task 9 depends on it): reopening
/// `EmbeddedTrust` on the same dir must reuse the persisted CA verbatim, so a
/// leaf signed before the restart still chains to the reopened bundle.
#[tokio::test]
async fn ca_reload_across_restart_keeps_trust_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let ca_pem_path = dir.path().join("ca.pem");
    let ca_key_path = dir.path().join("ca.key");

    let leaf1 = {
        let trust = EmbeddedTrust::open(dir.path()).unwrap();
        let issued = trust.sign(&gateway_csr("gw-aws"), profile("gw-aws")).await.unwrap();
        issued.cert_pem
        // trust dropped here — simulates process exit.
    };
    let ca_pem_before = std::fs::read(&ca_pem_path).unwrap();
    let ca_key_before = std::fs::read(&ca_key_path).unwrap();

    // Restart: same data dir.
    let trust2 = EmbeddedTrust::open(dir.path()).unwrap();

    // On-disk CA material must be byte-identical — no new CA minted, no
    // rewrite of the existing files.
    assert_eq!(
        std::fs::read(&ca_pem_path).unwrap(),
        ca_pem_before,
        "ca.pem must be unchanged across restart"
    );
    assert_eq!(
        std::fs::read(&ca_key_path).unwrap(),
        ca_key_before,
        "ca.key must be unchanged across restart"
    );

    // The pre-restart leaf still chains to the reopened bundle.
    let bundle2 = trust2.trust_bundle().await.unwrap();
    assert!(
        verify_chains(&leaf1, &bundle2),
        "leaf issued before restart must still chain to the reopened CA"
    );

    // And a freshly signed leaf also chains to it.
    let leaf2 = trust2
        .sign(&gateway_csr("gw-gcp"), profile("gw-gcp"))
        .await
        .unwrap()
        .cert_pem;
    assert!(
        verify_chains(&leaf2, &bundle2),
        "leaf issued after restart must chain to the reopened CA"
    );
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
