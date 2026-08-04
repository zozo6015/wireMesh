// crates/wiremesh-trust/tests/ca_legacy_guard.rs
//
// Guard tests for the "silent CA re-mint" outage class.
//
// THE INCIDENT THIS PINS
// ----------------------
// `load_or_create_ca` has three branches: both `ca.pem`+`ca.key` present ->
// load; exactly one present -> bail (already correct, and previously untested
// anywhere in the repo — see `half_ca_*` below); NEITHER present -> mint a
// brand-new self-signed CA. That last branch is right for a genuine first run
// and catastrophic for a misconfigured one: two independent reviews of the
// controller state-dir split each found a path where the controller boots
// against an EMPTY data dir while its real state still sits in the legacy
// shared `/var/lib/wiremesh`. It then mints a new trust anchor, every enrolled
// gateway's certificate stops validating, and the fabric goes down silently —
// nothing errors, the controller just comes up "healthy" with a new CA.
//
// The guard: data_dir has no CA, but the legacy dir has a `ca.key` (i.e. real
// controller state is sitting over there) -> refuse to mint, and tell the
// operator both paths.
//
// HERMETICITY — WHY THESE TESTS INJECT THE LEGACY PATH
// ----------------------------------------------------
// `/var/lib/wiremesh` is a real absolute path on the machine running the
// suite. A test that exercised the production constant directly would be
// non-deterministic by construction: green on a dev container with no
// `/var/lib/wiremesh/ca.key`, red on a real controller host that has one (or
// the reverse, for the negative cases), and it would need root to arrange
// either state. So every test here drives
// `EmbeddedTrust::open_with_legacy_dir(data_dir, legacy_dir)` with BOTH
// directories inside `tempfile::tempdir()`. Nothing under `/var` is read,
// written, or even stat'd, and no test requires privileges.
//
// The one thing injection cannot cover is that the production entry point
// actually passes the right constant. `legacy_shared_data_dir_constant_is_the_
// historic_path` pins the constant's VALUE (a typo there would silently
// disable the guard in production while leaving every injected test green);
// the single delegation line inside `open()` is left to review.
//
// Idioms (`gateway_csr`, `verify_chains`) are duplicated from
// `tests/embedded.rs` / `tests/conformance.rs` rather than shared, matching
// the convention already established in this crate's test dir.
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use wiremesh_trust::{CertProfile, CertificateIssuer, EmbeddedTrust, LEGACY_SHARED_DATA_DIR};

// ---------------------------------------------------------------------------
// 1. Genuine first run — the case the guard must NOT break.
// ---------------------------------------------------------------------------

/// Empty `data_dir`, and a legacy dir that does not exist at all: this is a
/// clean install, and it must still mint. Asserted end to end — both files
/// land on disk, `trust_bundle()` returns exactly the `ca.pem` bytes that
/// landed (not a re-serialization that merely looks similar), `ca.key` is
/// 0600, and the minted CA can actually sign a leaf that chains to that
/// bundle. A guard that fires too eagerly (e.g. keying off "legacy dir is
/// absent" with an inverted test, or bailing whenever `data_dir` is empty)
/// turns every fresh install into a boot failure; this test goes red for all
/// of those.
#[tokio::test]
async fn first_run_with_no_legacy_ca_mints_a_working_ca() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    // Deliberately never created: models a host that has never had a
    // pre-split WireMesh installation.
    let legacy_dir = tmp.path().join("legacy-absent");
    assert!(!legacy_dir.exists(), "precondition: legacy dir must not exist");

    let trust = EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir)
        .expect("a genuine first run with no legacy state must mint, not bail");

    let ca_pem_path = data_dir.join("ca.pem");
    let ca_key_path = data_dir.join("ca.key");
    assert!(ca_pem_path.is_file(), "first run must persist ca.pem");
    assert!(ca_key_path.is_file(), "first run must persist ca.key");

    // The in-memory bundle must be byte-identical to what is on disk — a
    // restart reads the file, so any divergence here is a trust anchor that
    // changes across a restart.
    let bundle = trust.trust_bundle().await.unwrap();
    assert_eq!(
        bundle,
        std::fs::read_to_string(&ca_pem_path).unwrap(),
        "trust_bundle() must return exactly the ca.pem bytes that were persisted"
    );
    assert!(
        !bundle.contains("PRIVATE KEY"),
        "trust bundle must never carry private key material"
    );
    assert_eq!(file_mode(&ca_key_path), 0o600, "ca.key must be 0600");

    // The minted CA is a real, usable issuer — not just two well-formed files.
    let leaf = trust
        .sign(&gateway_csr("gw-first-run"), profile("gw-first-run"))
        .await
        .expect("the freshly minted CA must be able to sign")
        .cert_pem;
    assert!(
        verify_chains(&leaf, &bundle),
        "a leaf signed by the freshly minted CA must chain to its own bundle"
    );
}

/// The post-migration / co-located-relay shape, and the reason the guard keys
/// on `ca.key` specifically rather than on `ca.pem` or on "the legacy dir is
/// non-empty". Commit abce3d0 deliberately COPIES `ca.pem` into the new state
/// dir and leaves the original behind, because a legacy relay identity in that
/// same directory needs it (`postinstall-relay.sh::have_legacy_identity`
/// requires all of ca.pem/relay.pem/relay.key). So a perfectly healthy host
/// can have a legacy dir holding a public `ca.pem` plus relay material and NO
/// `ca.key` — there is no controller CA over there to lose, and a first run
/// must proceed. A guard that probed `ca.pem`, or `!legacy.is_empty()`, would
/// brick exactly the hosts the migration was written to protect.
#[tokio::test]
async fn legacy_dir_holding_only_public_material_does_not_block_a_first_run() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy");
    std::fs::create_dir_all(&legacy_dir).unwrap();

    // A real ca.pem (public cert, left behind by the migration) plus a relay
    // identity — everything a legacy dir can legitimately hold EXCEPT the
    // controller's own ca.key.
    let donor = tmp.path().join("donor");
    mint_ca_into(&donor);
    std::fs::copy(donor.join("ca.pem"), legacy_dir.join("ca.pem")).unwrap();
    std::fs::write(legacy_dir.join("relay.pem"), "-----BEGIN CERTIFICATE-----\n").unwrap();
    std::fs::write(legacy_dir.join("relay.key"), "-----BEGIN PRIVATE KEY-----\n").unwrap();
    assert!(
        !legacy_dir.join("ca.key").exists(),
        "precondition: the legacy dir must hold no controller CA key"
    );

    let trust = EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir)
        .expect("a legacy dir with no ca.key holds no controller CA — first run must mint");

    assert!(data_dir.join("ca.pem").is_file());
    assert!(data_dir.join("ca.key").is_file());
    let bundle = trust.trust_bundle().await.unwrap();
    // And the minted CA is genuinely new — it must NOT have silently adopted
    // the legacy public cert, which it has no matching private key for.
    assert_ne!(
        bundle,
        std::fs::read_to_string(legacy_dir.join("ca.pem")).unwrap(),
        "the new CA must be freshly minted, not the legacy public cert (whose key is gone)"
    );
}

// ---------------------------------------------------------------------------
// 2 + 3. The guard fires, mints nothing, and says something actionable.
// ---------------------------------------------------------------------------

/// The outage scenario itself: the controller is pointed at an empty data dir
/// while its real CA still sits in the legacy dir. It must refuse.
///
/// The critical half of this test is the second assertion. A guard that bails
/// AFTER minting is worthless: the operator fixes the config, restarts against
/// the legacy dir, and the fabric recovers — but a stray `ca.key` has been
/// left in the new dir, and the next time anything points back at it the same
/// silent rotation happens. So this asserts on the DIRECTORY CONTENTS, and it
/// scans recursively for key/cert material rather than just checking two
/// filenames, so a mint that landed under a different name (or in `secrets/`)
/// is caught too. `secrets/` itself is created by `open()` before the CA is
/// touched, so an empty-dir assertion would be wrong; absence of CA MATERIAL
/// is the real property.
#[test]
fn guard_refuses_and_mints_nothing_when_legacy_ca_key_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy");
    mint_ca_into(&legacy_dir);
    assert!(legacy_dir.join("ca.key").is_file(), "precondition: legacy CA planted");

    let err = EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir)
        .err()
        .expect("an empty data dir while a legacy CA exists must be refused, not minted over");
    // Surface the message on failure of the assertions below.
    let msg = format!("{err:#}");

    assert!(
        !data_dir.join("ca.pem").exists(),
        "no ca.pem may be created in the data dir when the guard fires; error was: {msg}"
    );
    assert!(
        !data_dir.join("ca.key").exists(),
        "no ca.key may be created in the data dir when the guard fires; error was: {msg}"
    );
    let stray = find_ca_material(&data_dir);
    assert!(
        stray.is_empty(),
        "the guard must fire BEFORE minting — found CA/key material left behind in the data dir: {stray:?}"
    );
}

/// An operator reading this error at 3am has to be able to act on it without
/// reading the source. The two things they cannot recover without are the two
/// paths — where the controller is looking, and where its state actually is —
/// plus the knob that reconciles them.
///
/// Asserted on substance, not prose: the exact wording can be rewritten freely
/// and these stay green, but dropping either path (the easy mistake: naming
/// only the legacy path, since that is the "interesting" one) makes them red.
/// Both directories are uniquely-named tempdirs, so a `contains` check cannot
/// pass by accident.
#[test]
fn guard_error_names_both_directories_and_the_knob() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy");
    mint_ca_into(&legacy_dir);

    let err = EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir)
        .err()
        .expect("guard must fire");
    // `{:#}` walks the whole anyhow context chain, so the assertion holds
    // whether the paths are named in the root error or in a wrapping context.
    let msg = format!("{err:#}");

    assert!(
        msg.contains(&data_dir.display().to_string()),
        "error must name the empty data dir the controller was pointed at ({}); got: {msg}",
        data_dir.display()
    );
    assert!(
        msg.contains(&legacy_dir.display().to_string()),
        "error must name the legacy dir where the real CA lives ({}); got: {msg}",
        legacy_dir.display()
    );
    assert!(
        msg.contains("WIREMESH_DATA_DIR"),
        "error must name the env var that repoints the controller, so the fix is \
         mechanical rather than a source dive; got: {msg}"
    );
}

/// The guard is only about the EMPTY-data-dir case. A controller whose data
/// dir already holds its own CA must load it and ignore the legacy dir
/// entirely — even though a legacy `ca.key` is sitting right there. This is
/// the steady state of every host that has completed the migration (the
/// migration copies `ca.pem` and, on some paths, leaves the whole legacy dir
/// intact), so a guard that keyed only on "legacy has a ca.key" would refuse
/// to boot on every migrated host.
///
/// Also pins that the legacy CA is not PREFERRED: the returned bundle must be
/// the data dir's own anchor, not the legacy one.
#[tokio::test]
async fn data_dir_with_its_own_ca_ignores_a_legacy_ca() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy");
    mint_ca_into(&data_dir);
    mint_ca_into(&legacy_dir);

    let data_ca_pem = std::fs::read_to_string(data_dir.join("ca.pem")).unwrap();
    let legacy_ca_pem = std::fs::read_to_string(legacy_dir.join("ca.pem")).unwrap();
    assert_ne!(
        data_ca_pem, legacy_ca_pem,
        "precondition: the two planted CAs must be distinct"
    );

    let trust = EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir)
        .expect("a data dir holding its own CA must load normally regardless of legacy state");
    let bundle = trust.trust_bundle().await.unwrap();
    assert_eq!(
        bundle, data_ca_pem,
        "must load the data dir's own CA, not the legacy one"
    );
    // The guard is a read-only probe: it must never consume, move, or rewrite
    // the legacy material (a co-located legacy relay may still depend on it).
    assert!(
        legacy_dir.join("ca.key").is_file(),
        "the legacy ca.key must still be there"
    );
    assert_eq!(
        std::fs::read_to_string(legacy_dir.join("ca.pem")).unwrap(),
        legacy_ca_pem,
        "the legacy ca.pem must be byte-identical after the probe"
    );
}

// ---------------------------------------------------------------------------
// 4. The load-bearing exemption: data_dir IS the legacy dir.
// ---------------------------------------------------------------------------

/// The k8s/Docker deployment shape. The operator-managed controller
/// Deployment mounts its PVC at `/var/lib/wiremesh`
/// (`wiremesh-operator/src/workloads.rs::DATA_DIR`) and the container image
/// uses the same path, so for those deployments the data dir and the legacy
/// dir are literally the same directory. Breaking this would take down every
/// operator-managed fabric on upgrade — strictly worse than the bug being
/// fixed. So: same dir, real CA present -> load it, unchanged, and a leaf
/// issued before the "restart" must still chain.
#[tokio::test]
async fn data_dir_equal_to_legacy_dir_loads_its_existing_ca() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("var-lib-wiremesh");

    // Plant a CA and issue a leaf, the way a running fabric would have, then
    // drop the handle to simulate a process restart.
    let leaf_before = {
        let trust = mint_ca_into(&dir);
        trust
            .sign(&gateway_csr("gw-k8s"), profile("gw-k8s"))
            .await
            .unwrap()
            .cert_pem
    };
    let ca_pem_before = std::fs::read(dir.join("ca.pem")).unwrap();
    let ca_key_before = std::fs::read(dir.join("ca.key")).unwrap();

    // Restart, now with the legacy dir set to the very same path.
    let trust = EmbeddedTrust::open_with_legacy_dir(&dir, &dir).expect(
        "the container/operator shape (data dir IS the legacy dir) must keep loading normally",
    );

    assert_eq!(
        std::fs::read(dir.join("ca.pem")).unwrap(),
        ca_pem_before,
        "ca.pem must be untouched"
    );
    assert_eq!(
        std::fs::read(dir.join("ca.key")).unwrap(),
        ca_key_before,
        "ca.key must be untouched — a rewrite here is a rotated trust anchor"
    );
    let bundle = trust.trust_bundle().await.unwrap();
    assert!(
        verify_chains(&leaf_before, &bundle),
        "a gateway enrolled before the restart must still validate against the reloaded CA"
    );
}

/// The same shape on a genuine first run: an operator-managed controller
/// starting with a fresh, empty PVC mounted at the legacy path. It must MINT.
///
/// Note on the guard's shape (see the report): the `data_dir != legacy_dir`
/// clause in the guard condition cannot actually change this outcome. Reaching
/// the mint branch already establishes that `data_dir` holds no `ca.key`, and
/// when the two paths denote the same directory that IS the legacy probe — so
/// "legacy has a ca.key" is unsatisfiable here. The clause is harmless,
/// self-documenting defence rather than live logic. This test therefore pins
/// the OUTCOME (which is what an operator experiences) and stays correct
/// whether or not the implementation keeps the redundant comparison.
#[test]
fn empty_data_dir_equal_to_legacy_dir_still_mints() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("var-lib-wiremesh");

    EmbeddedTrust::open_with_legacy_dir(&dir, &dir)
        .expect("a fresh PVC mounted at the legacy path is a first run — it must mint, not bail");

    assert!(dir.join("ca.pem").is_file(), "first run must persist ca.pem");
    assert!(dir.join("ca.key").is_file(), "first run must persist ca.key");
}

// ---------------------------------------------------------------------------
// 5. The pre-existing half-CA behavior must be unchanged.
// ---------------------------------------------------------------------------
// Checked before writing these: nothing in the repo covered the half-CA bail —
// `grep -rn "incomplete CA"` matched only the `bail!` in src/lib.rs, and
// wiremesh-trust has no unit-test module. So these are new coverage, not a
// duplicate. They matter here because the new guard is inserted next to that
// branch, and the easy refactoring mistake is to fold the two conditions
// together in a way that lets a half-CA fall through to the mint branch.

/// Only `ca.key` present -> still bails, and does not fabricate the missing
/// `ca.pem`. Legacy dir absent, so this pins the ORIGINAL behavior in
/// isolation from the new guard.
#[test]
fn half_ca_with_only_the_key_still_bails() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy-absent");
    let donor = tmp.path().join("donor");
    mint_ca_into(&donor);
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::copy(donor.join("ca.key"), data_dir.join("ca.key")).unwrap();

    let err = EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir)
        .err()
        .expect("a data dir with only ca.key is incomplete CA state and must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&data_dir.join("ca.pem").display().to_string()),
        "the error must name the file that is missing; got: {msg}"
    );
    assert!(
        !data_dir.join("ca.pem").exists(),
        "must not fabricate the missing ca.pem — that would pair a new cert with the old key"
    );
}

/// Only `ca.pem` present -> still bails, and does not mint a key beside it.
/// Minting here would be the same outage in a different costume: a new key
/// paired with a stale published cert.
#[test]
fn half_ca_with_only_the_cert_still_bails() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy-absent");
    let donor = tmp.path().join("donor");
    mint_ca_into(&donor);
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::copy(donor.join("ca.pem"), data_dir.join("ca.pem")).unwrap();

    let err = EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir)
        .err()
        .expect("a data dir with only ca.pem is incomplete CA state and must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&data_dir.join("ca.key").display().to_string()),
        "the error must name the file that is missing; got: {msg}"
    );
    assert!(
        !data_dir.join("ca.key").exists(),
        "must not mint a key next to a stale cert"
    );
}

/// Ordering: a half-CA in the data dir must still be refused when a legacy CA
/// also exists. Either diagnostic is defensible, so this asserts only the two
/// things that are not negotiable — it is an error, and nothing was written.
/// A refactor that checks the legacy dir first and then falls through to the
/// mint branch would pass the `is_err` half of the older tests only because
/// the legacy dir was absent there; this closes that hole.
#[test]
fn half_ca_still_bails_when_a_legacy_ca_also_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy");
    let donor = tmp.path().join("donor");
    mint_ca_into(&legacy_dir);
    mint_ca_into(&donor);
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::copy(donor.join("ca.key"), data_dir.join("ca.key")).unwrap();
    let key_before = std::fs::read(data_dir.join("ca.key")).unwrap();

    assert!(
        EmbeddedTrust::open_with_legacy_dir(&data_dir, &legacy_dir).is_err(),
        "incomplete CA state must be refused whether or not a legacy CA exists"
    );
    assert!(!data_dir.join("ca.pem").exists(), "nothing may be minted");
    assert_eq!(
        std::fs::read(data_dir.join("ca.key")).unwrap(),
        key_before,
        "the existing half of the CA must not be overwritten"
    );
}

// ---------------------------------------------------------------------------
// The one non-injectable fact: the constant itself.
// ---------------------------------------------------------------------------

/// Every other test in this file injects the legacy directory, which is what
/// makes them hermetic — and also means a typo in the production constant
/// (`/var/lib/weiremesh`, `var/lib/wiremesh`, a stale path from an earlier
/// draft) would leave all of them green while the guard never fires on a real
/// host. This pins the value. It reads no filesystem, so it is still hermetic.
#[test]
fn legacy_shared_data_dir_constant_is_the_historic_path() {
    assert_eq!(
        LEGACY_SHARED_DATA_DIR, "/var/lib/wiremesh",
        "the guard keys off the pre-split shared state dir; this is the path the \
         relay certdir default, the container image, the operator's PVC mount, and \
         every pre-split .deb/.rpm install used"
    );
    assert!(
        Path::new(LEGACY_SHARED_DATA_DIR).is_absolute(),
        "the legacy path must be absolute — a relative path would resolve against \
         the controller's cwd and make the guard fire (or not) unpredictably"
    );
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Plants a real, freshly minted CA into `dir` by driving the production mint
/// path with a legacy dir that cannot exist — so planting can never itself
/// trip the guard under test, and the planted material is exactly what a real
/// first run produces (correct PEM, correct 0600 mode) rather than a fixture
/// that only resembles it. Returns the handle so callers can also issue from
/// the planted CA.
fn mint_ca_into(dir: &Path) -> EmbeddedTrust {
    let sentinel = dir.join("__no_such_legacy_dir__");
    let trust = EmbeddedTrust::open_with_legacy_dir(dir, &sentinel)
        .expect("planting a CA into an empty dir must succeed");
    assert!(dir.join("ca.pem").is_file() && dir.join("ca.key").is_file());
    trust
}

/// Recursively collects any file under `root` that looks like CA material —
/// by name (`ca.pem`/`ca.key`) or by content (a PEM key or certificate block).
/// Used to prove the guard fired before minting rather than after: checking
/// two filenames would miss a mint that wrote elsewhere first.
fn find_ca_material(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // The data dir may legitimately not exist at all if the guard
            // fired before `create_dir_all` — that is a pass, not a failure.
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = entry.file_name();
            if name == "ca.pem" || name == "ca.key" {
                found.push(path);
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                if text.contains("PRIVATE KEY") || text.contains("BEGIN CERTIFICATE") {
                    found.push(path);
                }
            }
        }
    }
    found
}

fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A gateway generates its own keypair and a CSR for `cn`, returning the CSR
/// PEM. Mirrors `tests/embedded.rs::gateway_csr`.
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
        serial: None,
    }
}

/// Real chain verification: does `leaf_pem` verify as having been issued by a
/// CA in `bundle_pem`? Mirrors `tests/embedded.rs::verify_chains` — this is
/// genuine cryptographic path building via rustls-webpki, not a substring
/// check, so a leaf signed by a *different* CA (exactly what a silent re-mint
/// produces) fails it.
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
