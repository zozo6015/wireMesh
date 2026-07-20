use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Local gateway configuration (not desired state — that comes from Sync).
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub controller_sync_addr: SocketAddr,
    pub observe_addr: SocketAddr,
    pub tun_ifname: String,
    pub wg_listen_port: u16,
    pub state_dir: PathBuf,
}

impl GatewayConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(std::env::args())
    }

    pub fn parse(args: impl Iterator<Item = String>) -> anyhow::Result<Self> {
        let mut controller = None;
        let mut observe = None;
        let mut tun = None;
        let mut wg_port = None;
        let mut state_dir = None;
        let mut it = args.skip(1); // argv[0]
        while let Some(flag) = it.next() {
            let mut val = || it.next().ok_or_else(|| anyhow!("flag {flag} needs a value"));
            match flag.as_str() {
                "--controller-sync" => controller = Some(val()?.parse().context("--controller-sync")?),
                "--observe" => observe = Some(val()?.parse().context("--observe")?),
                "--tun" => tun = Some(val()?),
                "--wg-port" => wg_port = Some(val()?.parse().context("--wg-port")?),
                "--state-dir" => state_dir = Some(PathBuf::from(val()?)),
                other => return Err(anyhow!("unknown flag {other}")),
            }
        }
        Ok(GatewayConfig {
            controller_sync_addr: controller.ok_or_else(|| anyhow!("--controller-sync required"))?,
            observe_addr: observe.ok_or_else(|| anyhow!("--observe required"))?,
            tun_ifname: tun.ok_or_else(|| anyhow!("--tun required"))?,
            wg_listen_port: wg_port.ok_or_else(|| anyhow!("--wg-port required"))?,
            state_dir: state_dir.ok_or_else(|| anyhow!("--state-dir required"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_all_fields_from_args() {
        let args = [
            "wiremesh-gateway",
            "--controller-sync", "127.0.0.1:6000",
            "--observe", "127.0.0.1:6001",
            "--tun", "wg0",
            "--wg-port", "51820",
            "--state-dir", "/var/lib/wiremesh",
        ]
        .into_iter()
        .map(String::from);
        let cfg = GatewayConfig::parse(args).expect("valid args parse");
        assert_eq!(cfg.tun_ifname, "wg0");
        assert_eq!(cfg.wg_listen_port, 51820);
        assert_eq!(cfg.controller_sync_addr.to_string(), "127.0.0.1:6000");
        assert_eq!(cfg.observe_addr.to_string(), "127.0.0.1:6001");
        assert_eq!(cfg.state_dir.to_str().unwrap(), "/var/lib/wiremesh");
    }

    #[test]
    fn parse_rejects_missing_required_flag() {
        let args = ["wiremesh-gateway", "--tun", "wg0"].into_iter().map(String::from);
        assert!(GatewayConfig::parse(args).is_err());
    }
}
