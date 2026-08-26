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

/// Deterministic fault injection for the rotation setup path — **test-only**.
///
/// Gated on the `netns-tests` feature, which is NOT a default feature, so none
/// of this compiles into a release binary: `cargo build --release` produces a
/// `wiremesh-gateway` with no such environment read at all. The netns suites
/// spawn the binary via `env!("CARGO_BIN_EXE_wiremesh-gateway")`, which is
/// built with the test's own feature set, so the hook is present exactly where
/// it is needed and nowhere else.
///
/// It lives in the library — with its own unit tests — rather than inline in
/// `main.rs`, per the v0.10.0 lesson that `main.rs`'s env-to-config assembly
/// went untested until it was extracted.
///
/// # This module is the ONLY home for test-only knobs
///
/// Every environment variable that exists to make a test possible lives here
/// and nowhere else — currently [`fault::ROTATION_FAIL_ENV`] and
/// [`fault::OVERLAP_STALL_WARN_ENV`]. The rule matters because the whole
/// safety argument is per-module: this module is gated on the non-default
/// `netns-tests` feature, so nothing in it compiles into a release binary, and
/// each knob is verified by a `strings` check on the shipped binary WITH a
/// positive control (an empty grep on its own proves only that the grep ran).
/// A knob parsed inline in `main.rs`, or in any other module, would sit
/// outside that argument and outside those checks — which is the v0.10.0
/// lesson, where `main.rs`'s env-to-config assembly went untested until it was
/// extracted. Add the next one here, with its own pure parse function, its own
/// unit tests, and its own re-measured `strings` pair.
///
/// # Why a fault hook at all
///
/// B2's done-bar has to observe a rotation that fails PART-WAY and then prove
/// the next one succeeds. The alternative — occupying the reserved own-tun port
/// so `plan_tunnel` errors — does not work from outside the process:
/// `plan_tunnel` arbitrates against `TunnelSet::plans()` (in-process state),
/// not against the OS.
#[cfg(feature = "netns-tests")]
pub mod fault {
    use anyhow::{anyhow, Context};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;

    /// The environment variable that arms the hook.
    /// Format: `<point>` or `<point>:<count>`, e.g.
    /// `after-enforcer-insert` or `after-mint:2`.
    pub const ROTATION_FAIL_ENV: &str = "WIREMESH_TEST_FAIL_ROTATION";

    /// Where in `handle_rotate_inner` an injected failure fires. The names
    /// match the residue each point leaves behind (design §2.2's step table).
    ///
    /// There is deliberately **no `after-submit` point.** A rotation whose key
    /// has been submitted is not abortable gateway-side — the controller
    /// grace-promotes onto it at 90s with zero acks and retires the prior epoch
    /// at ~120s, so unwinding then turns a degraded-but-reachable gateway into
    /// a hard, non-self-healing blackhole (design §3.2 Piece 1b). A hook that
    /// could reach that point would be a standing invitation to wire the unwind
    /// to it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RotationFailPoint {
        /// After the key is minted and persisted, before the tun is planned.
        /// Residue: an orphan `"pending"` key on disk, nothing else.
        AfterMint,
        /// After the new tun is up, before its enforcer is attached.
        /// Residue: orphan key + a live tun.
        AfterBringUp,
        /// After the enforcer is inserted into the shared map, before the peer
        /// apply. Residue: orphan key + live tun + a live enforcer entry — the
        /// maximal case, and the one the done-bar drives.
        AfterEnforcerInsert,
    }

    impl RotationFailPoint {
        fn parse(s: &str) -> anyhow::Result<Self> {
            match s {
                "after-mint" => Ok(Self::AfterMint),
                "after-bring-up" => Ok(Self::AfterBringUp),
                "after-enforcer-insert" => Ok(Self::AfterEnforcerInsert),
                other => Err(anyhow!(
                    "unknown rotation fail point {other:?}; expected one of \
                     after-mint, after-bring-up, after-enforcer-insert"
                )),
            }
        }
    }

    /// An armed (or disarmed) rotation fault, with a one-shot latch.
    #[derive(Debug)]
    pub struct RotationFaults {
        point: Option<RotationFailPoint>,
        remaining: AtomicU32,
    }

    impl RotationFaults {
        /// Parse a spec. **Pure** — takes the value rather than reading the
        /// environment, so its unit tests need no env mutation (and are
        /// therefore safe under a parallel test harness).
        ///
        /// * `None`, empty, or whitespace-only → armed: nothing.
        /// * `<point>` → that point, count 1.
        /// * `<point>:<count>` → that point, that count (`:0` arms nothing).
        /// * anything else → `Err`.
        ///
        /// A malformed spec is a HARD ERROR, never a silent no-op: a typo'd
        /// fault point that quietly armed nothing would produce a green netns
        /// run that proved nothing at all. Note the interaction between the
        /// two rules — whitespace collapses to "absent" for the WHOLE spec
        /// only, never for a half, or the hard-error posture would have a
        /// whitespace-shaped bypass (`"after-mint: "` is an error, not a
        /// default).
        pub fn parse(spec: Option<&str>) -> anyhow::Result<Self> {
            let Some(raw) = spec.map(str::trim).filter(|s| !s.is_empty()) else {
                return Ok(Self {
                    point: None,
                    remaining: AtomicU32::new(0),
                });
            };
            let (point_str, count) = match raw.split_once(':') {
                None => (raw, 1u32),
                Some((p, c)) => {
                    let p = p.trim();
                    let c = c.trim();
                    if p.is_empty() {
                        return Err(anyhow!(
                            "{ROTATION_FAIL_ENV}={raw:?}: a count with no fail point"
                        ));
                    }
                    if c.is_empty() {
                        return Err(anyhow!(
                            "{ROTATION_FAIL_ENV}={raw:?}: a trailing ':' with no count"
                        ));
                    }
                    let n: u32 = c.parse().with_context(|| {
                        format!("{ROTATION_FAIL_ENV}={raw:?}: count {c:?} is not a number")
                    })?;
                    (p, n)
                }
            };
            Ok(Self {
                point: Some(RotationFailPoint::parse(point_str)?),
                remaining: AtomicU32::new(count),
            })
        }

        /// Read [`ROTATION_FAIL_ENV`].
        pub fn from_env() -> anyhow::Result<Self> {
            Self::parse(std::env::var(ROTATION_FAIL_ENV).ok().as_deref())
        }

        /// Should the rotation currently at `at` fail? Consumes one unit of
        /// the latch if so.
        ///
        /// The latch only ever decrements and never resets, which is what lets
        /// the done-bar fail the FIRST directive and watch the SECOND complete
        /// inside one process — no restart, which would reset the state machine
        /// for free and confound the sabotage runs.
        pub fn take(&self, at: RotationFailPoint) -> bool {
            if self.point != Some(at) {
                return false;
            }
            // Compare-exchange rather than load-then-store so two callers can
            // never both consume the same unit.
            self.remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    n.checked_sub(1).filter(|_| n > 0)
                })
                .is_ok()
        }
    }

    /// Overrides `main.rs`'s `OVERLAP_STALL_WARN` (90s) — **test-only**.
    ///
    /// The R2 stall warning fires only after the rotation has sat in
    /// `Overlapping` for the full 90s, which mirrors the controller's
    /// `GRACE_PROMOTE`. A netns test cannot wait that long, and it cannot reach
    /// the warning any faster: the emission lives inside
    /// `run_rotation_ticks`'s `if let Some(a) = role_a` guard, so it is
    /// reachable ONLY from a genuine R2 — a rotation that got past
    /// `role_a = Some` and submitted, whose new tun no peer ever corroborates
    /// live. (Every fault point in `RotationFailPoint` precedes that
    /// assignment, so an injected abort can never produce a stall.)
    ///
    /// This knob lowers the threshold so that scenario is observable in
    /// seconds. It does NOT change what the constant means: `OVERLAP_STALL_WARN`
    /// stays 90s and stays the production source of truth — this is consulted
    /// only under `netns-tests`, and only as an override.
    pub const OVERLAP_STALL_WARN_ENV: &str = "WIREMESH_TEST_OVERLAP_STALL_WARN_SECS";

    /// Parse an override spec. **Pure** — takes the value rather than reading
    /// the environment, so its unit tests need no env mutation.
    ///
    /// * `None`, empty, or whitespace-only → `None` (no override; production
    ///   threshold applies). Absent must arm nothing: every netns suite builds
    ///   with `netns-tests` ON and runs with this variable unset.
    /// * a non-negative integer number of seconds → `Some(Duration)`. `0` is
    ///   valid and means "warn on the first tick of the spell".
    /// * anything else → `Err`. A malformed spec is a HARD ERROR, never a
    ///   silent fallback to 90s: falling back would make the test either wait
    ///   the full 90s or time out, and the likely "fix" for that is widening a
    ///   tolerance on an assertion — which is how a typo becomes a weakened
    ///   test.
    pub fn parse_overlap_stall_warn(spec: Option<&str>) -> anyhow::Result<Option<Duration>> {
        let Some(raw) = spec.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let secs: u64 = raw.parse().with_context(|| {
            format!("{OVERLAP_STALL_WARN_ENV}={raw:?}: expected a number of seconds")
        })?;
        Ok(Some(Duration::from_secs(secs)))
    }

    /// The process-wide stall-threshold override, read from the environment
    /// once. `None` means "use the production constant".
    ///
    /// A malformed spec panics here rather than being ignored — see
    /// [`parse_overlap_stall_warn`]. This is test-only code; failing loudly at
    /// the first tick is the correct posture.
    pub fn overlap_stall_warn_override() -> Option<Duration> {
        static OVERRIDE: OnceLock<Option<Duration>> = OnceLock::new();
        *OVERRIDE.get_or_init(|| {
            parse_overlap_stall_warn(std::env::var(OVERLAP_STALL_WARN_ENV).ok().as_deref())
                .expect("parsing the overlap-stall-warning override")
        })
    }

    /// The process-wide armed fault set, read from the environment once.
    ///
    /// A malformed spec panics here rather than being ignored — see
    /// [`RotationFaults::parse`]. This is test-only code; failing loudly at the
    /// first rotation is the correct posture.
    pub fn rotation_faults() -> &'static RotationFaults {
        static FAULTS: OnceLock<RotationFaults> = OnceLock::new();
        FAULTS.get_or_init(|| {
            RotationFaults::from_env().expect("parsing the rotation fault-injection spec")
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

    //
    //

    #[cfg(feature = "netns-tests")]
    mod rotation_fault_hook {
        use crate::config::fault::{RotationFailPoint, RotationFaults, ROTATION_FAIL_ENV};

        #[test]
        fn parse_accepts_each_fail_point_with_a_default_count_of_one() {
            for (text, expect) in [
                ("after-mint", RotationFailPoint::AfterMint),
                ("after-bring-up", RotationFailPoint::AfterBringUp),
                (
                    "after-enforcer-insert",
                    RotationFailPoint::AfterEnforcerInsert,
                ),
            ] {
                let f = RotationFaults::parse(Some(text))
                    .unwrap_or_else(|e| panic!("{text:?} must parse: {e:#}"));
                assert!(f.take(expect), "{text:?}: the FIRST directive must fail");
                assert!(
                    !f.take(expect),
                    "{text:?}: the count defaults to 1, so the SECOND directive must pass. This \
                     is what makes the hook a one-shot — `rotation_wedge.rs` step (iv) issues \
                     its directive to the SAME live process, and a hook that kept firing would \
                     red step (iv) for a harness reason rather than the wedge."
                );
            }
        }

        #[test]
        fn parse_reads_an_explicit_count_and_never_resets_it() {
            let f = RotationFaults::parse(Some("after-mint:2")).expect("`:N` must parse");
            assert!(f.take(RotationFailPoint::AfterMint));
            assert!(f.take(RotationFailPoint::AfterMint));
            assert!(!f.take(RotationFailPoint::AfterMint));
            assert!(
                !f.take(RotationFailPoint::AfterMint),
                "the counter only ever decrements — it must NOT reset (on a Sync reconnect or \
                 anything else). A resetting counter would re-arm between the two directives \
                 `rotation_wedge.rs` issues and fail the retry too, which is exactly the \
                 symptom the wedge produces — the harness would be forging its own red."
            );
        }

        #[test]
        fn take_only_fires_at_the_configured_point() {
            let f = RotationFaults::parse(Some("after-enforcer-insert")).unwrap();
            assert!(
                !f.take(RotationFailPoint::AfterMint),
                "a non-configured point must not consume the budget, or the rotation would fail \
                 EARLIER than the test asked and leave a smaller residue — step (iii) asserts on \
                 the tun, the enforcer gauge AND the store, and only the deepest point \
                 (`uapi::apply`, design §2.2 step 8) produces all three"
            );
            assert!(
                !f.take(RotationFailPoint::AfterBringUp),
                "likewise for the middle point"
            );
            assert!(f.take(RotationFailPoint::AfterEnforcerInsert));
        }

        #[test]
        fn an_absent_variable_arms_nothing() {
            let f = RotationFaults::parse(None).expect("an absent variable is not an error");
            for at in [
                RotationFailPoint::AfterMint,
                RotationFailPoint::AfterBringUp,
                RotationFailPoint::AfterEnforcerInsert,
            ] {
                assert!(
                    !f.take(at),
                    "an unset {ROTATION_FAIL_ENV} must leave EVERY fail point disarmed. Every netns suite in this \
                     crate spawns gateways without it (`key_rotation.rs`, `mesh_milestone.rs`, \
                     `nat_matrix.rs`, `relay_matrix.rs`), and all of them are built with this \
                     feature ON — so a default that armed anything would break the whole \
                     privileged suite at once."
                );
            }
        }

        #[test]
        fn an_empty_or_whitespace_only_value_is_treated_as_absent() {
            for empty in ["", "   ", "\t", "\n"] {
                let f = RotationFaults::parse(Some(empty)).unwrap_or_else(|e| {
                    panic!(
                        "{empty:?} must parse as ARMS-NOTHING, not as an error: an exported-but- \
                         empty variable is what a shell leaves behind \
                         (`{ROTATION_FAIL_ENV}=` with no value, or a cleared CI variable), and \
                         failing the boot on it would turn an innocuous environment into a \
                         gateway that will not start. Got: {e:#}"
                    )
                });
                for at in [
                    RotationFailPoint::AfterMint,
                    RotationFailPoint::AfterBringUp,
                    RotationFailPoint::AfterEnforcerInsert,
                ] {
                    assert!(!f.take(at), "{empty:?} must arm nothing");
                }
            }
        }

        #[test]
        fn a_zero_count_is_valid_and_arms_nothing() {
            let f = RotationFaults::parse(Some("after-mint:0")).expect("`:0` is a valid count");
            assert!(
                !f.take(RotationFailPoint::AfterMint),
                "`:0` names a point but budgets no failures. It is VALID — not an error — so a \
                 run can be disarmed by editing the count alone, without deleting the variable \
                 and losing which point was being exercised. `take` is true only when the armed \
                 point matches AND the remaining budget is > 0, and 0 fails the second half."
            );
        }

        #[test]
        fn surrounding_whitespace_is_trimmed_from_the_spec_and_from_each_half() {
            // The counterpart to the two rules either side of it, and the
            // reason they are not in conflict: whitespace IS trimmed at both
            // levels, but a half that trims away to NOTHING is an error, while
            // a whole spec that trims away to nothing means "absent". Pinning
            // the positive case is what keeps the distinction legible — read
            // alone, the Err list above looks like "whitespace is rejected",
            // which is not the rule.
            let f =
                RotationFaults::parse(Some("  after-mint  ")).expect("the whole spec is trimmed");
            assert!(f.take(RotationFailPoint::AfterMint));

            let f = RotationFaults::parse(Some("after-mint : 3")).expect("each half is trimmed");
            assert!(f.take(RotationFailPoint::AfterMint));
            assert!(f.take(RotationFailPoint::AfterMint));
            assert!(f.take(RotationFailPoint::AfterMint));
            assert!(
                !f.take(RotationFailPoint::AfterMint),
                "the count was 3, not more"
            );
        }

        #[test]
        fn an_unparseable_value_is_a_hard_error_not_a_silent_disarm() {
            for bad in [
                "after-lunch",
                "after-mint:",
                // THE BYPASS (gateway-dev's final table). Whitespace collapses
                // to "absent" for the WHOLE spec only — never for a HALF. So a
                // space after the colon is the trailing-colon case, not the
                // absent case. Without this pin, `WIREMESH_TEST_FAIL_ROTATION=\
                // "after-mint: "` would slip through the empty-means-absent
                // rule and silently disarm the hook, which is precisely the
                // silent-disarm this whole test exists to forbid.
                "after-mint: ",
                "after-mint:\t",
                "after-mint:xyz",
                ":2",
                " :2",
                "after-mint:1:2",
            ] {
                assert!(
                    RotationFaults::parse(Some(bad)).is_err(),
                    "{bad:?} must be a hard error — a malformed value is a typo, and an EMPTY \
                     one is not (see the sibling test: empty means absent, deliberately). A typo \
                     that silently disarmed the hook would \
                     make `rotation_wedge.rs` observe a gateway that rotated NORMALLY and report \
                     it as 'the unwind never ran' — a harness bug wearing a product bug's \
                     failure message. Failing loudly at first use names the real cause in one \
                     line."
                );
            }
        }
    }
}
