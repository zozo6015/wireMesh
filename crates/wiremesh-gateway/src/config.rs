use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Local gateway configuration (not desired state — that comes from Sync).
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Controller Sync dial target as `host:port` — a DNS hostname (e.g. a
    /// DDNS name for a controller behind a dynamic public IP) or an IP
    /// literal. Kept as a STRING, not a resolved `SocketAddr`, on purpose:
    /// resolution happens inside `sync::connect` on every (re)dial, so a
    /// rotated DDNS A record is picked up at the next reconnect without a
    /// gateway restart, and parse never does a DNS lookup — the gateway must
    /// still boot fail-static with the controller AND its resolver
    /// unreachable (spec §5.1; `docs/research/
    /// operator-remote-deployment-notes.md` Finding 3).
    pub controller_sync_addr: String,
    /// Controller observation (UDP endpoint-discovery) dial target as
    /// `host:port`. Same string-not-`SocketAddr` rationale as
    /// [`Self::controller_sync_addr`]: the observe loop re-resolves it every
    /// tick, which is the DDNS pickup path for endpoint observation.
    pub observe_addr: String,
    pub tun_ifname: String,
    pub wg_listen_port: u16,
    pub state_dir: PathBuf,
    /// Address the Prometheus metrics endpoint binds to. Optional flag
    /// `--metrics <ip:port>`; defaults to `127.0.0.1:0` (loopback,
    /// OS-assigned port) so the historical behavior is unchanged. The
    /// mesh-milestone netns test passes a routable `0.0.0.0:<fixed-port>` so
    /// it can scrape `wiremesh_gateway_default_deny_total` from the root
    /// namespace over the underlay.
    pub metrics_addr: SocketAddr,
}

// The syntax-only boot-time `host:port` validation behind
// `--controller-sync`/`--observe` moved to `wiremesh-enroll` (byte-identical
// semantics) when the relay bin's `--controller` gained the same boot
// posture (Backlog 2) — a misconfigured unit must exit non-zero at boot on
// either binary, not run forever logging resolution failures. Re-exported
// under the original path so `parse` below and the pinned unit tests are
// unchanged. Full semantics (no DNS; the two IPv6/typo'd-IP-literal
// fail-at-boot exceptions) are documented at the definition.
pub use wiremesh_enroll::validate_host_port;

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
        let mut metrics_addr = None;
        let mut it = args.skip(1); // argv[0]
        while let Some(flag) = it.next() {
            let mut val = || {
                it.next()
                    .ok_or_else(|| anyhow!("flag {flag} needs a value"))
            };
            match flag.as_str() {
                "--controller-sync" => {
                    let v = val()?;
                    validate_host_port(&v).context("--controller-sync")?;
                    controller = Some(v);
                }
                "--observe" => {
                    let v = val()?;
                    validate_host_port(&v).context("--observe")?;
                    observe = Some(v);
                }
                "--tun" => tun = Some(val()?),
                "--wg-port" => wg_port = Some(val()?.parse().context("--wg-port")?),
                "--state-dir" => state_dir = Some(PathBuf::from(val()?)),
                "--metrics" => metrics_addr = Some(val()?.parse().context("--metrics")?),
                other => return Err(anyhow!("unknown flag {other}")),
            }
        }
        Ok(GatewayConfig {
            controller_sync_addr: controller
                .ok_or_else(|| anyhow!("--controller-sync required"))?,
            observe_addr: observe.ok_or_else(|| anyhow!("--observe required"))?,
            tun_ifname: tun.ok_or_else(|| anyhow!("--tun required"))?,
            wg_listen_port: wg_port.ok_or_else(|| anyhow!("--wg-port required"))?,
            state_dir: state_dir.ok_or_else(|| anyhow!("--state-dir required"))?,
            // Optional: default to loopback + OS-assigned port (historical
            // behavior) when `--metrics` is absent.
            metrics_addr: metrics_addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0))),
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
            "--controller-sync",
            "127.0.0.1:6000",
            "--observe",
            "127.0.0.1:6001",
            "--tun",
            "wg0",
            "--wg-port",
            "51820",
            "--state-dir",
            "/var/lib/wiremesh",
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
        let args = ["wiremesh-gateway", "--tun", "wg0"]
            .into_iter()
            .map(String::from);
        assert!(GatewayConfig::parse(args).is_err());
    }

    /// DNS hostnames (e.g. a DDNS name for the controller) are valid
    /// `--controller-sync` / `--observe` values and are kept VERBATIM as
    /// strings — parse must not resolve them (resolution is deferred to dial
    /// time so the gateway still boots fail-static with the resolver down).
    #[test]
    fn parse_accepts_hostname_dial_targets_verbatim() {
        let args = [
            "wiremesh-gateway",
            "--controller-sync",
            "controller.example.com:9500",
            "--observe",
            "ddns.example.net:9600",
            "--tun",
            "wg0",
            "--wg-port",
            "51820",
            "--state-dir",
            "/var/lib/wiremesh",
        ]
        .into_iter()
        .map(String::from);
        let cfg = GatewayConfig::parse(args).expect("hostname dial targets parse");
        assert_eq!(cfg.controller_sync_addr, "controller.example.com:9500");
        assert_eq!(cfg.observe_addr, "ddns.example.net:9600");
        // `--metrics` was absent: historical loopback default is unchanged.
        assert_eq!(cfg.metrics_addr, SocketAddr::from(([127, 0, 0, 1], 0)));
    }

    fn parse_with_sync_value(v: &str) -> anyhow::Result<GatewayConfig> {
        let args = [
            "wiremesh-gateway",
            "--controller-sync",
            v,
            "--observe",
            "127.0.0.1:6001",
            "--tun",
            "wg0",
            "--wg-port",
            "51820",
            "--state-dir",
            "/var/lib/wiremesh",
        ]
        .into_iter()
        .map(String::from);
        GatewayConfig::parse(args)
    }

    #[test]
    fn parse_rejects_controller_sync_with_empty_host() {
        assert!(parse_with_sync_value(":9500").is_err());
    }

    #[test]
    fn parse_rejects_controller_sync_with_missing_port() {
        assert!(parse_with_sync_value("controller.example.com").is_err());
    }

    #[test]
    fn parse_rejects_controller_sync_with_non_u16_port() {
        assert!(parse_with_sync_value("controller.example.com:65536").is_err());
        assert!(parse_with_sync_value("controller.example.com:http").is_err());
        assert!(parse_with_sync_value("controller.example.com:").is_err());
    }

    #[test]
    fn parse_rejects_malformed_observe_value() {
        let args = [
            "wiremesh-gateway",
            "--controller-sync",
            "127.0.0.1:6000",
            "--observe",
            "observer.example.com",
            "--tun",
            "wg0",
            "--wg-port",
            "51820",
            "--state-dir",
            "/var/lib/wiremesh",
        ]
        .into_iter()
        .map(String::from);
        assert!(
            GatewayConfig::parse(args).is_err(),
            "--observe without a port must be rejected"
        );
    }

    /// `--metrics` is a BIND address, not a dial target: it still requires a
    /// literal `SocketAddr`, so a hostname there stays invalid.
    #[test]
    fn parse_metrics_still_requires_socket_addr_literal() {
        let mk = |metrics: &str| {
            [
                "wiremesh-gateway",
                "--controller-sync",
                "127.0.0.1:6000",
                "--observe",
                "127.0.0.1:6001",
                "--tun",
                "wg0",
                "--wg-port",
                "51820",
                "--state-dir",
                "/var/lib/wiremesh",
                "--metrics",
                metrics,
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
            .into_iter()
        };
        assert!(
            GatewayConfig::parse(mk("localhost:9100")).is_err(),
            "hostname must be rejected"
        );
        let cfg = GatewayConfig::parse(mk("0.0.0.0:9100")).expect("ip:port metrics parses");
        assert_eq!(cfg.metrics_addr, SocketAddr::from(([0, 0, 0, 0], 9100)));
    }

    #[test]
    fn validate_host_port_accepts_hostnames_and_ipv4_literals() {
        assert!(validate_host_port("127.0.0.1:6000").is_ok());
        assert!(validate_host_port("controller.example.com:9500").is_ok());
        assert!(validate_host_port("localhost:1").is_ok());
    }

    /// v1 is IPv4-only end to end, so IPv6 dial-target literals — bracketed
    /// or any host parsing as an IPv6 `IpAddr` — are rejected at parse time
    /// (boot), with an error that says so, instead of failing at every dial.
    #[test]
    fn validate_host_port_rejects_ipv6_dial_targets() {
        for target in [
            "[::1]:9500",
            "[2001:db8::1]:9500",
            "::1:9500",
            "2001:db8::1:9500",
        ] {
            let err = validate_host_port(target)
                .expect_err(&format!("IPv6 dial target {target:?} must be rejected"));
            let chain = format!("{err:#}");
            assert!(
                chain.contains("IPv6") || chain.contains("IPv4-only"),
                "rejection of {target:?} must mention IPv6/v1-IPv4-only, got: {chain}"
            );
        }
        // Bracketed-but-invalid is likewise rejected (bracket = IPv6 attempt).
        assert!(validate_host_port("[::zz]:9500").is_err());
        // And the same boot-time behavior end-to-end through `parse`.
        assert!(parse_with_sync_value("[::1]:9500").is_err());
    }

    /// IP-literal ATTEMPTS must fast-fail at parse time: a host that is
    /// IPv4-shaped (digits and dots only) or bracketed can never be a
    /// resolvable DNS name, so the whole string must parse as a `SocketAddr`
    /// — a typo'd literal like `10.0.0.300` errors at boot instead of
    /// looping on resolution failures forever.
    #[test]
    fn validate_host_port_rejects_malformed_ip_literal_attempts() {
        assert!(
            validate_host_port("10.0.0.300:9500").is_err(),
            "IPv4-shaped host, invalid octet"
        );
        assert!(
            validate_host_port("999.1.2.3:1").is_err(),
            "IPv4-shaped host, out-of-range octets"
        );
    }

    /// The fast-fail must not eat genuine hostnames: names mixing digits and
    /// letters are not digits-and-dots-only, so they stay on the deferred-
    /// resolution hostname path.
    #[test]
    fn validate_host_port_keeps_digit_bearing_hostnames_valid() {
        assert!(validate_host_port("host1.example:9500").is_ok());
        assert!(validate_host_port("1host:9500").is_ok());
    }

    /// The reviewer-requested boot-time behavior end-to-end through `parse`:
    /// a typo'd IP literal in `--controller-sync` errors instead of being
    /// waved through as a "hostname".
    #[test]
    fn parse_rejects_controller_sync_with_invalid_ip_literal() {
        assert!(parse_with_sync_value("10.0.0.300:9500").is_err());
    }

    #[test]
    fn validate_host_port_rejects_syntax_errors() {
        assert!(
            validate_host_port("no-port-at-all").is_err(),
            "missing port"
        );
        assert!(validate_host_port(":9500").is_err(), "empty host");
        assert!(validate_host_port("host:").is_err(), "empty port");
        assert!(validate_host_port("host:0x1f").is_err(), "non-numeric port");
        assert!(
            validate_host_port("host:65536").is_err(),
            "port out of u16 range"
        );
        assert!(validate_host_port("host:-1").is_err(), "negative port");
    }
}
