//! `wiremesh-relay-enroll` — thin CLI wrapper over
//! `wiremesh_relay::enroll::run_enroll`. Writes the relay's `ca.pem` /
//! `relay.pem` / `relay.key` identity into `--certdir`, then hands the
//! files to the packaged service user when possible (best-effort chown —
//! ops finding 2026-07-27/28 "Relay Finding A": the documented `sudo`
//! enroll left root-owned 0600 files the `User=wiremesh` unit could not
//! read, crash-looping the service; see
//! `enroll::chown_identity_best_effort`).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Live-deployment diagnostics: answer `-h`/`--help` and `-V`/`--version`
    // before `parse_args`' required-flag validation runs. `cli_action` receives
    // argv[1..] (same skip(1) convention as `parse_args`).
    match wiremesh_relay::enroll::cli_action(std::env::args().skip(1)) {
        wiremesh_relay::enroll::CliAction::Help(m) => {
            print!("{m}");
            return Ok(());
        }
        wiremesh_relay::enroll::CliAction::Version(s) => {
            println!("{s}");
            return Ok(());
        }
        wiremesh_relay::enroll::CliAction::Run => {}
    }

    let args = wiremesh_relay::enroll::parse_args(std::env::args().skip(1))?;
    let certdir = args.certdir.clone();
    wiremesh_relay::enroll::run_enroll(args).await?;
    wiremesh_relay::enroll::chown_identity_best_effort(&certdir);
    Ok(())
}
