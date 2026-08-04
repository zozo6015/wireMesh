// crates/wiremesh-controller/tests/boot_leaves_no_residue.rs
//
// Pins ONE ordering fact inside `serve()`: `EmbeddedTrust::open` runs before
// `Db::open`, so a boot the CA guard refuses writes no `controller.db`.
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
// repo would notice. Swapping the two `open` calls back is the sabotage these
// tests are designed against.
//
// HERMETICITY — WHY THIS DRIVES THE HALF-CA REFUSAL, NOT THE LEGACY-CA ONE
// ------------------------------------------------------------------------
// The refusal that motivated the reorder is the legacy-CA guard (empty data
// dir + a `ca.key` in `/var/lib/wiremesh`). That one is NOT reachable
// hermetically from here: `serve()` calls `EmbeddedTrust::open`, which hard-
// codes `LEGACY_SHARED_DATA_DIR`; the injectable `open_with_legacy_dir` seam
// stops at the trust layer, and `Config` has no legacy-dir field. A test that
// tried it would be green on a dev container and red on a real controller
// host, or the reverse — see `wiremesh-trust/tests/ca_legacy_guard.rs` for
// the same argument at that layer.
//
// So this drives the OTHER `load_or_create_ca` refusal — a half CA in the
// data dir (`ca.key` present, `ca.pem` missing) — which bails on its very
// first branch, before the legacy probe is ever consulted. Nothing under
// `/var` is read or stat'd, and no privileges are needed. It is the same
// `EmbeddedTrust::open(...)?` returning `Err` from the same line of `serve()`,
// which is the whole of what the ordering can be tested through: `Db::open`
// cannot tell which branch refused, only whether it got to run first.
//
// Half-CA planting mirrors `ca_legacy_guard.rs`: mint into a donor dir with a
// legacy dir that cannot exist, then copy one half across, so the fixture is
// real CA material rather than something that merely looks like it, and the
// planting itself can never trip a guard.
//
// THE RUST-SIDE / SHELL ASYMMETRY
// -------------------------------
// There is no Rust equivalent of `has_controller_state`. The pin decision
// lives entirely in the postinst shell script; the controller has no notion
// of "this directory is already in use" and never probes for one. The only
// Rust code that agrees with the script's marker is the legacy probe in
// `wiremesh_trust::load_or_create_ca`, which also keys on `ca.key` — pinned
// (from the negative side, ca.pem-only must NOT count) by
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

/// The regression itself. A boot the CA guard refuses must leave the data dir
/// exactly as it found it — specifically, no `controller.db`.
///
/// Three assertions, in order of what they defend:
///   - the refusal came from the CA layer (without this the rest is vacuous:
///     a `serve()` that failed at `create_dir_all` would also write no DB),
///   - no `controller.db*` anywhere under the dir — prefix-matched, so the
///     WAL/SHM sidecars a differently-configured `Db::open` might leave are
///     caught too, and recursive, so a DB opened one level down is caught,
///   - nothing else appeared either. That last one is deliberately strict.
///     `ca.key` is the fixture and `secrets/` is created by
///     `EmbeddedTrust::open` itself before the CA is examined, so those two
///     are the whole legitimate contents; anything NEW showing up here is a
///     write that happens before the guard, which is precisely the class of
///     change this file exists to force someone to look at.
#[tokio::test]
async fn refused_boot_creates_no_controller_db() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    plant_half_ca(&data_dir, tmp.path());

    let err = serve(config_for(&data_dir))
        .await
        .err()
        .expect("a boot against a data dir with incomplete CA state must be refused");
    // `{:#}` walks the whole anyhow context chain, so this holds whether the
    // paths are named by the root error or by `serve()`'s wrapping context.
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&data_dir.join("ca.pem").display().to_string()),
        "the boot must have been refused BY THE CA GUARD (naming the missing \
         ca.pem) — any other failure makes the no-residue assertions below \
         prove nothing; got: {msg}"
    );

    let db_files = find_by_prefix(&data_dir, "controller.db");
    assert!(
        db_files.is_empty(),
        "a refused boot must not leave a migrated database behind: the packaging's \
         data-dir pin treats a directory holding controller state as already in use, \
         so residue from one mis-started boot disables it permanently. \
         `EmbeddedTrust::open` must run before `Db::open` in `serve()`. Found: {db_files:?}"
    );

    let entries: BTreeSet<String> = std::fs::read_dir(&data_dir)
        .expect("the data dir must exist — `serve()` creates it before anything else")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = ["ca.key", "secrets"].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        entries, expected,
        "a refused boot must write NOTHING into the data dir beyond what \
         `EmbeddedTrust::open` creates before it looks at the CA (`secrets/`). \
         Anything else here is a new write that lands before the guard refuses — \
         re-examine whether it can be moved after it, or whether the packaging's \
         state detection can now false-positive on it"
    );
}

/// Anti-vacuity guard for the test above. `controller.db` is asserted ABSENT
/// there, and an assertion about a file that is never created under any
/// circumstances is green forever — including after the ordering is reverted,
/// if the DB were meanwhile renamed or moved into a subdirectory. So: a boot
/// that the CA guard does NOT refuse must create exactly that file, at exactly
/// that path.
///
/// This is also the only place the two names stay tied together: the shell's
/// `has_controller_state` comment, `docs/install.md`'s migration steps and the
/// trust guard's operator instructions all name `controller.db` as the file to
/// move, and none of them can notice if the code stops producing it.
///
/// Hermetic for the same reason the refusal test is, by the opposite route: a
/// COMPLETE CA is planted first, so `load_or_create_ca` takes its load branch
/// and the legacy probe (which is only reachable when the data dir has no CA
/// of its own) is never evaluated. Booting an empty data dir here would make
/// the test's outcome depend on whether the host running it happens to have
/// `/var/lib/wiremesh/ca.key`.
#[tokio::test]
async fn successful_boot_does_create_controller_db() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("controller-state");
    let sentinel = tmp.path().join("__no_such_legacy_dir__");
    EmbeddedTrust::open_with_legacy_dir(&data_dir, &sentinel)
        .expect("planting a complete CA into an empty dir must succeed");

    let running = serve(config_for(&data_dir))
        .await
        .expect("a data dir holding its own complete CA must boot");

    assert!(
        data_dir.join("controller.db").is_file(),
        "a successful boot must create `<data_dir>/controller.db` — the name the \
         refusal test asserts absent, and the one the packaging and the migration \
         docs both name"
    );

    // Full teardown rather than `drop`: `shutdown()` joins every server task
    // and releases the listeners, so the tempdir can be removed cleanly and
    // no task outlives the test.
    running.shutdown().await;
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Every port `0` (OS-assigned) and the socket inside the tempdir, so nothing
/// here can collide with a parallel test or with a controller running on the
/// developer's machine. The rotation intervals are the production defaults:
/// neither timer has fired by the time these tests finish, and pinning them to
/// the defaults keeps this file from depending on the timers at all.
fn config_for(data_dir: &Path) -> Config {
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
    }
}

/// Plants REAL `ca.key` material into `data_dir` with no `ca.pem` beside it —
/// the "incomplete CA state" that `load_or_create_ca` refuses on its first
/// branch, before it ever probes the legacy directory.
///
/// The key is minted by the production path into a throwaway donor dir (with a
/// legacy dir that cannot exist, so planting can never itself trip a guard),
/// then copied. A hand-written stub would work today only because the guard
/// checks existence rather than parseability — and would then stop exercising
/// anything the day it starts parsing.
fn plant_half_ca(data_dir: &Path, scratch: &Path) {
    let donor = scratch.join("donor");
    let sentinel = scratch.join("__no_such_legacy_dir__");
    EmbeddedTrust::open_with_legacy_dir(&donor, &sentinel)
        .expect("minting a donor CA must succeed");

    std::fs::create_dir_all(data_dir).unwrap();
    std::fs::copy(donor.join("ca.key"), data_dir.join("ca.key")).unwrap();
    assert!(
        !data_dir.join("ca.pem").exists(),
        "precondition: the planted CA must be incomplete"
    );
}

/// Every file under `root` whose name starts with `prefix`, recursively.
/// Prefix rather than equality so SQLite's `-wal`/`-shm` sidecars count as
/// residue too; recursive so a DB opened in a subdirectory is not missed.
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
