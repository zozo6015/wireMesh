//! Local WireGuard endpoint enumeration (cycle4b Task 8, spec §5). The
//! gateway reports its own routable local addresses to the controller
//! (`Sync.Report.local_endpoints`) so peers can discover a direct path
//! candidate without waiting on the controller's own NAT-observation probe.
//! Shells out to `ip -4 -o addr show` — the repo's established convention
//! for network introspection (see `crate::routes`) — rather than
//! `getifaddrs`/`nix`, to keep the same single dependency surface.
use std::process::Command;

/// Enumerate the host's routable IPv4 addresses and format each as
/// `ip:wg_port` for use as a WireGuard endpoint candidate. Loopback
/// (127.0.0.0/8) and link-local (169.254.0.0/16) addresses are excluded —
/// neither is ever reachable by a peer gateway.
///
/// Never fails outright: a spawn error or non-zero `ip` exit is logged to
/// stderr and yields an empty list, mirroring the tolerance the sync loop
/// already applies to the observation probe (`main.rs`'s `observe::report_once`
/// call site) — a report round with no discoverable local addresses is a
/// legitimate, non-fatal outcome, not a reason to crash the gateway.
pub fn local_wg_endpoints(wg_port: u16) -> Vec<String> {
    let out = match Command::new("ip")
        .args(["-4", "-o", "addr", "show"])
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            eprintln!("wiremesh-gateway: spawning ip -4 -o addr show failed: {e}");
            return Vec::new();
        }
    };
    if !out.status.success() {
        eprintln!(
            "wiremesh-gateway: ip -4 -o addr show failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_ip_addr_output(&text, wg_port)
}

/// Pure parse of `ip -4 -o addr show` output into `ip:wg_port` candidate
/// strings, factored out of [`local_wg_endpoints`] so it's unit-testable
/// without root/network-namespace privileges. Each line looks like:
///
/// ```text
/// 2: eth0    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0\       valid_lft forever preferred_lft forever
/// ```
///
/// i.e. whitespace-separated fields with the literal token `inet` followed
/// by the `addr/prefixlen` field. Lines without an `inet` token (shouldn't
/// occur given `-4`, but tolerated defensively) are skipped. Loopback
/// (127.0.0.0/8) and link-local (169.254.0.0/16) addresses are filtered —
/// they are never a usable candidate for a peer gateway to dial.
pub(crate) fn parse_ip_addr_output(out: &str, wg_port: u16) -> Vec<String> {
    let mut result = Vec::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(inet_pos) = fields.iter().position(|f| *f == "inet") else {
            continue;
        };
        let Some(cidr) = fields.get(inet_pos + 1) else {
            continue;
        };
        let ip = cidr.split('/').next().unwrap_or(cidr);
        if is_usable_ipv4(ip) {
            result.push(format!("{ip}:{wg_port}"));
        }
    }
    result
}

fn is_usable_ipv4(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    if addr.is_loopback() {
        return false;
    }
    // Link-local: 169.254.0.0/16.
    if addr.octets()[0] == 169 && addr.octets()[1] == 254 {
        return false;
    }
    if addr.is_unspecified() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture based on real `ip -4 -o addr show` output inside the dev
    /// container: loopback, a routable eth0 address, and a link-local
    /// fallback address (assigned when DHCP hasn't completed yet).
    const FIXTURE: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0\\       valid_lft forever preferred_lft forever
3: eth0    inet 169.254.1.1/16 scope link eth0\\       valid_lft forever preferred_lft forever
";

    #[test]
    fn filters_loopback_and_link_local_appends_port() {
        let got = parse_ip_addr_output(FIXTURE, 51820);
        assert_eq!(got, vec!["172.17.0.3:51820".to_string()]);
    }

    #[test]
    fn multiple_routable_addrs_all_kept() {
        let text = "\
1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 10.0.0.5/24 scope global eth0
3: eth1    inet 10.1.0.5/24 scope global eth1
";
        let got = parse_ip_addr_output(text, 51820);
        assert_eq!(
            got,
            vec!["10.0.0.5:51820".to_string(), "10.1.0.5:51820".to_string()]
        );
    }

    #[test]
    fn empty_output_yields_empty_list() {
        assert_eq!(parse_ip_addr_output("", 51820), Vec::<String>::new());
    }

    #[test]
    fn unspecified_address_is_filtered() {
        let text = "1: eth0    inet 0.0.0.0/0 scope global eth0\n";
        assert_eq!(parse_ip_addr_output(text, 51820), Vec::<String>::new());
    }
}
