// crates/wiremesh-controller/tests/boot_leaves_no_residue.rs
//
// Pins ONE ordering fact inside `serve()`: `EmbeddedTrust::open_with_legacy_dir`
// runs before `Db::open`, so a boot the CA guard refuses writes no
// `controller.db` — and nothing else either.
//
// WHY AN ORDERING IS WORTH A TEST FILE
// ------------------------------------
// It stopped being a local style choice and became load-bearing for the
// packaging. `deploy/packages/scripts/postinstall-server.sh` decides whether
// to PIN an upgraded install to the data dir it already uses by asking "does
// this directory hold controller state?". `Db::open` calls `run_migrations`,
// which writes a complete schema — so while it ran FIRST, one boot against
// the wrong directory left a fully-migrated `controller.db` behind before the
// CA guard refused, and that directory then looked occupied forever after.
// The pin silently never fired again: no error, no message, just a controller
// that comes up against an empty dir on some later upgrade.
//
// The fix has two independent halves, and this file covers the first:
//   1. `serve()` opens trust before the DB, so a refused boot leaves no
//      residue at all  <- HERE
//   2. `has_controller_state` keys on `ca.key` only, not `controller.db`
//      (shell, see the asymmetry note below)
// Either half alone closes the reported bug, which is exactly why the
// ordering needs pinning: with (2) in place, reverting (1) breaks nothing
// visible today. It reintroduces a latent trap that only fires the next time
// anything downstream reasons about `controller.db`, and no other test in the
// repo would notice. Swapping the two `open` calls back is the sabotage every
// test here is designed against — and each one reaches the ordering behind a
// DIFFERENT reason for the boot to be refused, so the pin does not depend on
// any single guard branch surviving a future refactor.
//
// HERMETICITY
// -----------
// Every test builds its own `Config` and sets `legacy_data_dir` explicitly —
// never `None`, which resolves to the real absolute `/var/lib/wiremesh`. That
// is not a formality: `None` would make these tests pass or fail according to
// whether the machine running them happens to have `/var/lib/wiremesh/ca.key`
// (green in the dev container, red on any real controller host), the same trap
// `wiremesh-trust/tests/ca_legacy_guard.rs` documents at the trust layer.
// Nothing here reads, writes or stats anything outside its own tempdir, and
// nothing needs privileges.
//
// CA fixtures are minted through the production path into a donor dir and
// copied, rather than hand-written, so they are real key/cert bytes and keep
// exercising the guard the day it starts parsing rather than merely checking
// existence.
//
// THE RUST-SIDE / SHELL ASYMMETRY
// -------------------------------
// There is no Rust equivalent of `has_controller_state`. The pin decision
// lives entirely in the postinst shell script; the controller has no notion
// of "this directory is already in use" and never probes for one. The only
// Rust code that agrees with the script's marker is the legacy probe in
// `wiremesh_trust::load_or_create_ca`, which also keys on `ca.key` — pinned
// (from the negative side: a `ca.pem`-only legacy dir must NOT count) by
// `ca_legacy_guard.rs::legacy_dir_holding_only_public_material_does_not_
// block_a_first_run`, so it is not duplicated here. Net: nothing in Rust can
// go red if someone widens the shell marker back to `controller.db`, and
// nothing in the shell can go red if the Rust ordering is reverted. The two
// halves of the fix are pinned in two languages by two mechanisms, and this
// file is only the Rust half.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use wiremesh_controller::{serve, Config};
use wiremesh_trust::EmbeddedTrust;

/// The regression in its real shape: the controller is pointed at an empty
/// data dir while the fabric's actual CA still sits in the legacy directory —
/// a `WIREMESH_DATA_DIR` typo, a pin that never fired, a unit override. The
/// guard refuses, and the data dir must be left exactly as it was found.
///
/// This is the boot that motivated the reorder, and until `Config` gained
/// `legacy_data_dir` it could not be reached from a test without hardcoding a
/// real absolute path. It is now the primary pin; the half-CA test below
/// covers the same property through the other refusal branch.
#[tokio::test]
async fn refused_boot_with_a_legacy_ca_creates_no_controller_db() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy");
    mint_ca_into(&legacy_dir);

    let err = serve(config_for(&data_dir, &legacy_dir))
        .await
        .err()
        .expect("an empty data dir while a legacy CA exists must be refused, not minted over");
    // `{:#}` walks the whole anyhow context chain, so this holds whether the
    // path is named by the root error or by `serve()`'s wrapping context.
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&legacy_dir.join("ca.key").display().to_string()),
        "the boot must have been refused BY THE LEGACY-CA GUARD (naming the CA it \
         found) — any other failure makes the no-residue assertions below prove \
         nothing; got: {msg}"
    );

    assert_no_db_residue(&data_dir);
    assert_data_dir_holds_only(&data_dir, &["secrets"]);
    // The guard is a read-only probe. A refused boot must not have consumed,
    // moved or rewritten the legacy material either — a co-located relay may
    // still depend on it, and the operator's recovery path is to point the
    // controller AT this directory.
    assert!(
        legacy_dir.join("ca.key").is_file() && legacy_dir.join("ca.pem").is_file(),
        "the legacy CA must survive the refused boot intact"
    );
}

/// The same property behind a different refusal: a half CA in the data dir
/// (`ca.key` present, `ca.pem` missing), which `load_or_create_ca` rejects on
/// its very first branch — before the legacy probe is reached at all.
///
/// Kept alongside the legacy-CA test rather than replaced by it, for two
/// reasons. It is the only test here that survives a rework of the legacy
/// guard: the commit that added the injectable seam already names an explicit
/// first-boot opt-in (`WIREMESH_INIT_CA`) as the follow-up that would change
/// that branch's behaviour, and whatever happens to it, "a refusal writes no
/// DB" must still hold. And it reaches the ordering with no injection at all —
/// the bail happens before `legacy_data_dir` is consulted — so it stays
/// meaningful even if the seam is later narrowed or removed. Costs one cheap
/// boot that binds nothing.
#[tokio::test]
async fn refused_boot_with_a_half_ca_creates_no_controller_db() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy-absent");
    plant_half_ca(&data_dir, tmp.path());

    let err = serve(config_for(&data_dir, &legacy_dir))
        .await
        .err()
        .expect("a boot against a data dir with incomplete CA state must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&data_dir.join("ca.pem").display().to_string()),
        "the boot must have been refused BY THE CA GUARD (naming the missing \
         ca.pem) — any other failure makes the no-residue assertions below \
         prove nothing; got: {msg}"
    );

    assert_no_db_residue(&data_dir);
    assert_data_dir_holds_only(&data_dir, &["ca.key", "secrets"]);
}

// ---------------------------------------------------------------------------
// The guard must not go blind: a probe it cannot answer is a refusal.
// ---------------------------------------------------------------------------
// `Path::exists()` is `metadata().is_ok()`, so it reports "absent" for EVERY
// stat error — including `EACCES`, which is exactly what a `User=wiremesh`
// controller gets for a root-owned 0700 `/var/lib/wiremesh` (a state
// `docs/install.md`'s own `chown` produces). A guard that reads "cannot tell"
// as "nothing there" mints a replacement CA in precisely the situation it
// exists to prevent. Both probes are now `fs::metadata` matched on
// `ErrorKind::NotFound`, and only a definite `NotFound` is permission to mint.
//
// ON EACCES SPECIFICALLY: it is the motivating errno and it is NOT reachable
// from this suite. `dev/Dockerfile` declares no `USER` and `./dev.sh run`
// passes no `--user`, so tests execute as root in a privileged container,
// where `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` mean any `chmod` a test
// performs inside its own tempdir denies that test nothing. Rather than write
// a case that is green for the wrong reason on the machine that actually runs
// it — or gate it on a uid check, which is a silent skip in disguise — the two
// tests below produce `ENOTDIR` and `ELOOP`: different errnos landing in the
// IDENTICAL `Err(e) if e.kind() == NotFound` / `Err(e)` match arms, reachable
// as any user. What they pin is the discrimination itself, "not-`NotFound`
// must bail". A revert to `Path::exists()`, or to a catch-all
// `Err(_) => false`, reddens both.

/// Stage one of the probe: the legacy DIRECTORY cannot be stat'd. Produced
/// here by making a parent component a regular file, so `fs::metadata` fails
/// `ENOTDIR` rather than `NotFound`. The controller must refuse — and, the
/// point of this file, must refuse without leaving a DB behind.
#[tokio::test]
async fn boot_refuses_when_the_legacy_directory_cannot_be_stat_ed() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    // A regular file where a directory component is expected: every stat that
    // walks through it fails ENOTDIR.
    let blocker = tmp.path().join("not-a-directory");
    std::fs::write(&blocker, b"this is a file, not a directory\n").unwrap();
    let legacy_dir = blocker.join("wiremesh");
    assert!(
        std::fs::metadata(&legacy_dir)
            .err()
            .is_some_and(|e| e.kind() != std::io::ErrorKind::NotFound),
        "precondition: the legacy path must fail to stat with something OTHER than \
         NotFound — a NotFound here would make this test assert the mint path"
    );

    let err = serve(config_for(&data_dir, &legacy_dir))
        .await
        .err()
        .expect(
            "a controller that cannot determine whether a legacy CA exists must refuse to \
             mint one — 'cannot tell' is not 'absent'",
        );
    let msg = format!("{err:#}");
    assert!(
        msg.contains("cannot determine") && msg.contains(&legacy_dir.display().to_string()),
        "the refusal must say it could not answer the probe, and name the path it \
         could not read; got: {msg}"
    );

    assert_no_db_residue(&data_dir);
    assert_data_dir_holds_only(&data_dir, &["secrets"]);
    assert!(
        !data_dir.join("ca.key").exists() && !data_dir.join("ca.pem").exists(),
        "a blind guard must mint NOTHING — not rotating the trust anchor while \
         unsure is this branch's entire purpose"
    );
}

/// Stage two: the legacy directory stats fine, but the `ca.key` inside it does
/// not. Produced by a self-referential symlink (`ELOOP`), which is what the
/// second `fs::metadata` hits. In production this stage is the co-located-
/// gateway case — a directory that exists but cannot be searched — and its
/// message is the one carrying the `chmod o+x` remedy, so this asserts on the
/// CA-KEY path to prove the second probe fired rather than the first.
#[tokio::test]
async fn boot_refuses_when_the_legacy_ca_key_cannot_be_stat_ed() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy");
    std::fs::create_dir_all(&legacy_dir).unwrap();
    let legacy_key = legacy_dir.join("ca.key");
    // Points at itself: resolving it loops, so `metadata` (which follows
    // symlinks) fails with something emphatically not `NotFound`, while the
    // directory above it stats perfectly well.
    std::os::unix::fs::symlink("ca.key", &legacy_key).unwrap();
    assert!(
        std::fs::metadata(&legacy_dir).unwrap().is_dir(),
        "precondition: the legacy dir itself must stat cleanly, so stage two is what \
         fails"
    );
    assert!(
        std::fs::metadata(&legacy_key)
            .err()
            .is_some_and(|e| e.kind() != std::io::ErrorKind::NotFound),
        "precondition: the legacy ca.key must fail to stat with something OTHER than \
         NotFound"
    );

    let err = serve(config_for(&data_dir, &legacy_dir))
        .await
        .err()
        .expect("an unanswerable ca.key probe must refuse the boot, not be read as absent");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("cannot determine") && msg.contains(&legacy_key.display().to_string()),
        "the refusal must name the CA key it could not stat (stage two), not merely \
         the directory; got: {msg}"
    );

    assert_no_db_residue(&data_dir);
    assert_data_dir_holds_only(&data_dir, &["secrets"]);
    assert!(
        !data_dir.join("ca.key").exists() && !data_dir.join("ca.pem").exists(),
        "a blind guard must mint NOTHING"
    );
}

// ---------------------------------------------------------------------------
// Anti-vacuity.
// ---------------------------------------------------------------------------

/// `controller.db` is asserted ABSENT four times above, and an assertion about
/// a file that is never created under any circumstances is green forever —
/// including after the ordering is reverted, if the DB were meanwhile renamed
/// or moved into a subdirectory. So: a boot the CA guard does NOT refuse must
/// create exactly that file, at exactly that path.
///
/// This is also the only place the two names stay tied together: the shell's
/// `has_controller_state` comment, `docs/install.md`'s migration steps and the
/// trust guard's operator instructions all name `controller.db` as the file to
/// move, and none of them can notice if the code stops producing it.
///
/// A COMPLETE CA is planted first, so `load_or_create_ca` takes its load
/// branch and never reaches the legacy probe — which is what makes a success
/// case expressible here at all.
#[tokio::test]
async fn successful_boot_does_create_controller_db() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let legacy_dir = tmp.path().join("legacy-absent");
    mint_ca_into(&data_dir);

    let running = serve(config_for(&data_dir, &legacy_dir))
        .await
        .expect("a data dir holding its own complete CA must boot");

    assert!(
        data_dir.join("controller.db").is_file(),
        "a successful boot must create `<data_dir>/controller.db` — the name the \
         refusal tests assert absent, and the one the packaging and the migration \
         docs both name"
    );

    // Full teardown rather than `drop`: `shutdown()` joins every server task
    // and releases the listeners, so the tempdir can be removed cleanly and no
    // task outlives the test.
    running.shutdown().await;
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Every port `0` (OS-assigned) and the socket inside the tempdir, so nothing
/// here can collide with a parallel test or with a controller running on the
/// developer's machine. The rotation intervals are the production defaults:
/// neither timer fires within a test's lifetime, and naming the defaults keeps
/// this file from depending on the timers at all.
///
/// `legacy_data_dir` is a required parameter rather than a defaulted field,
/// because the one value that must never appear in a test is the one `None`
/// selects (see the hermeticity note at the top). Making every caller name a
/// directory it owns is what stops that happening by omission.
fn config_for(data_dir: &Path, legacy_dir: &Path) -> Config {
    Config {
        data_dir: data_dir.to_path_buf(),
        tcp_port: 0,
        sync_tcp_port: 0,
        socket_path: data_dir.join("controller.sock"),
        admin_tcp_port: 0,
        observe_udp_port: 0,
        bind_ip: Config::default_bind_ip(),
        rotation_interval: Config::default_rotation_interval(),
        rotation_sweep_interval: Config::default_rotation_sweep_interval(),
        legacy_data_dir: Some(legacy_dir.to_path_buf()),
    }
}

/// Plants a real, freshly minted CA into `dir` by driving the production mint
/// path with a legacy dir that cannot exist — so planting can never itself
/// trip the guard under test, and the material is exactly what a real first
/// run produces rather than a fixture that resembles it. Mirrors
/// `ca_legacy_guard.rs::mint_ca_into`.
fn mint_ca_into(dir: &Path) {
    let sentinel = dir.join("__no_such_legacy_dir__");
    EmbeddedTrust::open_with_legacy_dir(dir, &sentinel)
        .expect("planting a CA into an empty dir must succeed");
    assert!(
        dir.join("ca.pem").is_file() && dir.join("ca.key").is_file(),
        "precondition: the planted CA must be complete"
    );
}

/// Plants REAL `ca.key` material into `data_dir` with no `ca.pem` beside it —
/// the "incomplete CA state" `load_or_create_ca` refuses on its first branch.
/// Minted into a throwaway donor dir and copied: a hand-written stub would
/// work today only because the guard checks existence rather than
/// parseability, and would stop exercising anything the day that changes.
fn plant_half_ca(data_dir: &Path, scratch: &Path) {
    let donor = scratch.join("donor");
    mint_ca_into(&donor);

    std::fs::create_dir_all(data_dir).unwrap();
    std::fs::copy(donor.join("ca.key"), data_dir.join("ca.key")).unwrap();
    assert!(
        !data_dir.join("ca.pem").exists(),
        "precondition: the planted CA must be incomplete"
    );
}

/// No `controller.db` anywhere under `data_dir`. Prefix-matched so SQLite's
/// `-wal`/`-shm` sidecars count as residue too, and recursive so a DB opened
/// one level down is not missed — checking a single literal path would let a
/// rename or a subdirectory hide the very regression this file exists for.
fn assert_no_db_residue(data_dir: &Path) {
    let db_files = find_by_prefix(data_dir, "controller.db");
    assert!(
        db_files.is_empty(),
        "a refused boot must not leave a migrated database behind: the packaging's \
         data-dir pin treats a directory holding controller state as already in use, \
         so residue from one mis-started boot disables it permanently. \
         `EmbeddedTrust::open_with_legacy_dir` must run before `Db::open` in \
         `serve()`. Found: {db_files:?}"
    );
}

/// The data dir contains `expected` and nothing else.
///
/// Deliberately strict. `serve()` creates the data dir and `EmbeddedTrust`
/// creates `secrets/` inside it before the CA is examined, so those — plus
/// whatever the test itself planted — are the whole legitimate contents of a
/// refused boot. Anything NEW appearing here is a write that lands before the
/// guard refuses, which is precisely the class of change this file exists to
/// force someone to look at, even when the new file is not a database.
fn assert_data_dir_holds_only(data_dir: &Path, expected: &[&str]) {
    let entries: BTreeSet<String> = std::fs::read_dir(data_dir)
        .expect("the data dir must exist — `serve()` creates it before anything else")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        entries, expected,
        "a refused boot must write NOTHING into the data dir beyond what \
         `EmbeddedTrust::open_with_legacy_dir` creates before it looks at the CA \
         (`secrets/`). Anything else here lands before the guard refuses — \
         re-examine whether it can be moved after it, and whether the packaging's \
         state detection can now false-positive on it"
    );
}

/// Every file under `root` whose name starts with `prefix`, recursively.
fn find_by_prefix(root: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // A dir that does not exist holds no residue — that is a pass.
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if entry.file_name().to_string_lossy().starts_with(prefix) {
                found.push(path);
            }
        }
    }
    found
}
