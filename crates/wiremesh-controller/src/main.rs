//! `wiremesh-controller` binary: a thin wrapper that reads the process
//! environment, builds a `Config` from it via
//! [`wiremesh_controller::config_from_env`], and hands off to the library
//! entrypoint [`wiremesh_controller::serve`], which does all the actual work.
//!
//! Kept thin on purpose, and thinner since 2026-08-12: everything here is
//! unreachable from an integration test (`wiremesh-testkit::TestController`
//! calls `serve` in-process, and no test can call `main`), so any logic left in
//! this file is logic nothing can pin. The env→`Config` assembly used to live
//! here and was exactly that — the one untested link in the opt-in rotation
//! contract, where a one-line edit re-armed a 30-day timer on every install
//! with the whole suite green. It now lives in the library behind an injectable
//! lookup; see `config_from_env`'s doc comment and
//! `tests/config_from_env.rs`. What remains is argv handling, the listener
//! banner, and the ctrl-c wait.

use anyhow::Result;
use wiremesh_controller::{config_from_env, serve};

#[tokio::main]
async fn main() -> Result<()> {
    // Live-deployment diagnostics: answer `-h`/`--help` and `-V`/`--version`
    // before reading any WIREMESH_* var or calling `serve` (see `cli`).
    match wiremesh_controller::cli::cli_action(std::env::args()) {
        wiremesh_controller::cli::CliAction::Help(m) => {
            print!("{m}");
            return Ok(());
        }
        wiremesh_controller::cli::CliAction::Version(s) => {
            println!("{s}");
            return Ok(());
        }
        wiremesh_controller::cli::CliAction::Run => {}
    }

    // The real process environment, read through `std::env::var` itself rather
    // than the lossy `|k| std::env::var(k).ok()`: `config_from_env` and
    // everything under it distinguish a PRESENT-but-non-UTF-8 value from an
    // absent one, and this is the call that decides whether they get to. A
    // malformed port or rotation interval comes back as an `Err` here and exits
    // non-zero — see `config_from_env`'s doc comment for which variables are
    // hard errors and which warn and fall back.
    //
    // (Wrapped in a closure rather than passed as the bare `std::env::var`
    // path: `var` is generic over `K: AsRef<OsStr>`, so the bare path infers
    // ONE specific lifetime and fails the callee's higher-ranked `Fn(&str)`
    // bound.)
    #[allow(clippy::redundant_closure)]
    let config = config_from_env(|k| std::env::var(k))?;

    let running = serve(config).await?;
    eprintln!(
        "wiremesh-controller listening: tcp={} sync_tcp={} uds={} admin_tcp={} observe_udp={}",
        running.tcp_addr(),
        running.sync_tcp_addr(),
        running.socket_path().display(),
        running.admin_tcp_addr(),
        running.observe_addr()
    );

    tokio::signal::ctrl_c().await?;
    eprintln!("wiremesh-controller: shutting down");
    running.shutdown().await;
    Ok(())
}
