//! `wiremesh-relay-enroll` — thin CLI wrapper over
//! `wiremesh_relay::enroll::run_enroll`. Writes the relay's `ca.pem` /
//! `relay.pem` / `relay.key` identity into `--certdir`.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = wiremesh_relay::enroll::parse_args(std::env::args().skip(1))?;
    wiremesh_relay::enroll::run_enroll(args).await
}
