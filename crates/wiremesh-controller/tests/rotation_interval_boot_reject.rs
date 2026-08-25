//! Binary-level cover for the one link in the rotation-interval chain that no
//! library test can reach: that `main.rs` actually *calls*
//! `rotation_interval_from_env` and turns its `Err` into a failed boot.
//!
//! `rotation_interval_from_env` being correct is worth nothing if `main.rs`
//! ignores it, `unwrap_or_default()`s it, or logs-and-continues the way
//! `WIREMESH_BIND_IP` deliberately does. The promise to the operator is that a
//! mistyped interval stops the controller at boot — because the alternative is
//! someone who typed `30dd` believing they armed rotation, or `of` believing
//! they disabled it, running for months on whatever the fallback silently
//! picked and finding out at the worst possible moment. (Which fallback is
//! moot: since the 2026-08-12 flip an absent variable means NO timer, so a
//! swallowed value would strand the fabric un-rotated rather than rotate it on
//! a schedule nobody chose. Both are the software deciding in the operator's
//! place, which is what the non-zero exit refuses to do.)
//!
//! Only the FAILURE path is exercised here, deliberately: it aborts before
//! `serve()` binds a listener, mints a CA, or touches any state, so this test
//! spawns a process that is guaranteed to be short-lived and side-effect-free.
//! A successful boot would leave a real controller running and is covered
//! in-process by `wiremesh-testkit` everywhere else.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wiremesh_controller::ROTATION_INTERVAL_ENV;

/// A present-but-malformed `WIREMESH_ROTATION_INTERVAL` must exit the
/// controller non-zero, name the variable and the offending value on stderr,
/// and leave nothing behind — never fall back to any resolution and boot
/// anyway.
#[test]
fn malformed_rotation_interval_aborts_the_boot() {
    let data_dir = tempfile::tempdir().expect("creating a temp data dir for the spawned binary");
    let bogus = "30dd";

    let mut child = Command::new(env!("CARGO_BIN_EXE_wiremesh-controller"))
        .env(ROTATION_INTERVAL_ENV, bogus)
        // Pointed at a directory this test owns purely as belt-and-braces: if
        // the boot ever regressed to proceeding past the malformed value, it
        // must not be able to write into the host's /var/lib/wiremesh.
        .env("WIREMESH_DATA_DIR", data_dir.path())
        .env(
            "WIREMESH_SOCKET_PATH",
            data_dir.path().join("controller.sock"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning the built wiremesh-controller binary");

    // Bounded wait, not a blocking `output()`: if the value is (wrongly)
    // accepted, the controller boots and runs forever, and this test must fail
    // with a clear message rather than hang the suite.
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait().expect("polling the spawned controller") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the controller was still running 15s after being started with \
                     {ROTATION_INTERVAL_ENV}={bogus:?} — a malformed rotation interval must \
                     abort the boot, not be swallowed into whatever the unset case resolves \
                     to while the operator believes they changed it"
                );
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr was piped")
        .read_to_string(&mut stderr)
        .expect("reading the spawned controller's stderr");

    assert!(
        !status.success(),
        "the controller must exit NON-ZERO for {ROTATION_INTERVAL_ENV}={bogus:?} \
         (status: {status:?}, stderr:\n{stderr})"
    );
    assert!(
        stderr.contains(ROTATION_INTERVAL_ENV),
        "the boot failure must name the variable at fault on stderr — the controller reads \
         several WIREMESH_* vars and the operator has to know which one to fix. Got:\n{stderr}"
    );
    assert!(
        stderr.contains(bogus),
        "the boot failure must quote the rejected value {bogus:?} back to the operator. \
         Got:\n{stderr}"
    );

    // Aborting BEFORE any side effect is part of the contract: a controller
    // that half-started (minted a CA, opened the DB) and then bailed would
    // leave residue for the next boot to trip over.
    for residue in ["controller.db", "ca.pem", "ca.key", "controller.sock"] {
        let path = data_dir.path().join(residue);
        assert!(
            !path.exists(),
            "the boot must fail before creating {residue} — the rotation-interval check runs \
             ahead of serve(), so a rejected value must leave the data dir untouched \
             ({})",
            path.display()
        );
    }
}
