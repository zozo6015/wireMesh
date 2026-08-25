//! The controller binary's environment→[`Config`] assembly: the step between
//! reading `WIREMESH_*` out of the process environment and handing a `Config`
//! to `serve`.
//!
//! # Why this file exists
//!
//! The rotation contract ratified on 2026-08-12 — an ABSENT
//! `WIREMESH_ROTATION_INTERVAL` means NO timer, so automatic key rotation is
//! opt-in — is carried by three links, and only two of them were pinned:
//!
//! | link | pinned by |
//! |---|---|
//! | 1. env absent → `rotation_interval_from_env` → `Ok(None)` | `tests/rotation_interval_parse.rs` |
//! | 2. **the binary puts that value into `Config.rotation_interval` unmodified** | **this file** |
//! | 3. `Config.rotation_interval: None` → `serve` spawns no timer task | `tests/rotation_disabled.rs` |
//!
//! Link 2 had no test at all. The concrete regression that let through: someone
//! edits the `Config { .. }` literal to
//!
//! ```ignore
//! rotation_interval: rotation_interval.or(Some(Config::default_rotation_interval())),
//! ```
//!
//! for "upgrade compatibility", or drops the field's line while resolving a
//! merge conflict, or reorders the literal during a refactor — and **every
//! existing test stays green.** `rotation_interval_parse.rs` tests the resolver
//! and never reaches the binary; `rotation_disabled.rs` and
//! `rotation_timer.rs` build a `Config` directly through
//! `wiremesh_testkit::TestController` and never boot through the binary's
//! assembly; `rotation_disabled_banner.rs` calls the formatter;
//! `cli_help_version.rs` reads `--help`. The one test that spawns the real
//! binary, `rotation_interval_boot_reject.rs`, says in its own module doc that
//! it exercises the FAILURE path deliberately — it only ever passes a malformed
//! value. Net result of that edit: 0 failed, 0 ignored, and every
//! `.deb`/`.rpm`/container/source install silently re-arms a 30-day rotation
//! timer pointed at `docs/BACKLOG.md` item 9, the open rotation wedge. That is
//! the exact bug the 2026-08-12 flip exists to delete.
//!
//! # Why a library seam and not a spawned boot
//!
//! The obvious instrument — spawn `wiremesh-controller` with a clean
//! environment and observe that it does not rotate — is the wrong one here, for
//! the same reason `automatic_rotation_disabled_banner()` was extracted rather
//! than stderr-scraped: a real boot mints a CA and trips the `/var/lib/wiremesh`
//! re-mint guard on any host that already has one, and
//! [`Config::legacy_data_dir`] is deliberately NOT env-settable (an
//! operator-settable override would be a one-line bypass of the guard). Such a
//! test would go red on real controller hosts and on developer boxes for
//! reasons having nothing to do with rotation.
//!
//! So the assembly moves into the library behind an injectable lookup, exactly
//! as `rotation_interval_from_env` already is:
//!
//! ```ignore
//! /// Builds the `Config` the binary boots with, reading every `WIREMESH_*`
//! /// variable through `lookup` (`main.rs` passes `|k| std::env::var(k)`).
//! pub fn config_from_env(
//!     lookup: impl Fn(&str) -> std::result::Result<String, std::env::VarError>,
//! ) -> anyhow::Result<Config>;
//! ```
//!
//! `main.rs` becomes a thin caller of it, so what these tests assemble is
//! literally what the shipped binary assembles. `lookup` mirrors
//! [`std::env::var`]'s own signature (NOT the lossy `.ok()` form) for the reason
//! `rotation_interval_from_env`'s doc gives: `Err(VarError::NotUnicode(..))`
//! means PRESENT-but-unreadable, and collapsing it into "absent" would answer a
//! question the operator DID answer, with the answer they did not give. It is
//! `Fn` rather than `FnOnce` because eight variables are read.
//!
//! Until `config_from_env` exists this file does not compile, and that compile
//! failure is the expected RED — the same idiom `rotation_interval_parse.rs`
//! and `rotation_disabled_banner.rs` both open with.
//!
//! # What is asserted here, and what is deliberately not
//!
//! Everything below is a property `main.rs` has TODAY. The extraction is a
//! refactor, so this file's job is to make it a behaviour-preserving one — and
//! then to keep it preserved. The rotation assertions are the reason the file
//! exists; the `bind_ip`, port, path, `rotation_sweep_interval` and
//! `legacy_data_dir` assertions come along because they have the identical
//! untested-wiring shape and the same extraction moves them.
//!
//! Deliberately NOT pinned: the ORDER in which variables are read. Two
//! malformed variables at once produce whichever error the assembly happens to
//! reach first, and that is an implementation detail, not an operator-facing
//! contract — so every error case below is exercised in isolation.

use std::env::VarError;
use std::path::PathBuf;
use std::time::Duration;

use wiremesh_controller::{
    config_from_env, parse_rotation_interval, Config, ROTATION_INTERVAL_ENV,
};

// ---------------------------------------------------------------------------
// The operator-facing variable names.
//
// Spelled out as literals rather than imported, for the reason
// `env_lookup_is_called_once_with_the_canonical_variable_name` gives about
// `ROTATION_INTERVAL_ENV`: these names appear in the systemd unit, in
// `deploy/packages/env/controller.env`, in `docs/install.md`, and in the
// operator's rendered Deployment. Renaming one is a breaking change to every
// deployment that sets it, not a refactor, so the test states the name
// independently instead of agreeing with whatever the code currently reads.
// ---------------------------------------------------------------------------

const DATA_DIR_ENV: &str = "WIREMESH_DATA_DIR";
const TCP_PORT_ENV: &str = "WIREMESH_TCP_PORT";
const SYNC_TCP_PORT_ENV: &str = "WIREMESH_SYNC_TCP_PORT";
const SOCKET_PATH_ENV: &str = "WIREMESH_SOCKET_PATH";
const ADMIN_TCP_PORT_ENV: &str = "WIREMESH_ADMIN_TCP_PORT";
const OBSERVE_UDP_PORT_ENV: &str = "WIREMESH_OBSERVE_UDP_PORT";
const BIND_IP_ENV: &str = "WIREMESH_BIND_IP";

/// The four port variables, with the `Config` field each one feeds.
const PORT_VARS: &[(&str, &str)] = &[
    (TCP_PORT_ENV, "tcp_port"),
    (SYNC_TCP_PORT_ENV, "sync_tcp_port"),
    (ADMIN_TCP_PORT_ENV, "admin_tcp_port"),
    (OBSERVE_UDP_PORT_ENV, "observe_udp_port"),
];

/// Every variable the binary reads. Used by
/// `every_documented_variable_is_actually_consulted`.
const ALL_VARS: &[&str] = &[
    DATA_DIR_ENV,
    TCP_PORT_ENV,
    SYNC_TCP_PORT_ENV,
    SOCKET_PATH_ENV,
    ADMIN_TCP_PORT_ENV,
    OBSERVE_UDP_PORT_ENV,
    BIND_IP_ENV,
    ROTATION_INTERVAL_ENV,
];

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// A `lookup` over a fixed set of variables: anything not listed is ABSENT,
/// which is what a stock install actually has.
fn lookup_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> std::result::Result<String, VarError> {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    move |key: &str| {
        owned
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .ok_or(VarError::NotPresent)
    }
}

/// Assembles a `Config` from `pairs`, asserting success. A failure here is
/// reported with the operator-visible error chain, since that is the only
/// feedback a real boot would give before exiting non-zero.
fn config_from(pairs: &[(&str, &str)]) -> Config {
    config_from_env(lookup_of(pairs)).unwrap_or_else(|e| {
        panic!("config_from_env({pairs:?}) must succeed, got startup error: {e:#}")
    })
}

/// Assembles from `pairs`, asserting FAILURE, and returns the full error chain
/// as the operator would see it (`{:#}`, so a `context`-wrapped cause is
/// included). `describe_ok` renders the accepted-but-shouldn't-have-been
/// `Config` for the panic message, since `Config` is not `Debug`.
fn config_rejected(pairs: &[(&str, &str)], describe_ok: impl Fn(&Config) -> String) -> String {
    match config_from_env(lookup_of(pairs)) {
        Ok(c) => panic!(
            "config_from_env({pairs:?}) must be REJECTED — a malformed value the operator \
             typed has to fail the boot loudly, never be silently replaced by a default they \
             did not choose. Got a Config with {}",
            describe_ok(&c)
        ),
        Err(e) => format!("{e:#}"),
    }
}

/// The all-absent environment: no `WIREMESH_*` set at all. This is not a
/// contrived case — it is what every stock install has. The `.deb`/`.rpm` ship
/// `deploy/packages/env/controller.env` with the rotation line commented out,
/// the ghcr container image sets no rotation env, and a source build inherits
/// whatever the host has, which is nothing.
const NOTHING_SET: &[(&str, &str)] = &[];

// ---------------------------------------------------------------------------
// The gap this file was written for.
// ---------------------------------------------------------------------------

/// **The important one.** A controller booted with NOTHING set runs with no
/// rotation-initiation timer.
///
/// This is link 2 of the three-link contract in the module doc: the step
/// between a `rotation_interval_from_env` that correctly answers `Ok(None)` and
/// a `serve` that correctly spawns nothing for `None`. Both of its neighbours
/// are pinned; without this assertion the middle can be rewritten to arm the
/// timer anyway and the entire suite stays green.
#[test]
fn all_absent_environment_arms_no_rotation_timer() {
    let config = config_from(NOTHING_SET);
    assert_eq!(
        config.rotation_interval, None,
        "with no WIREMESH_* set at all, the Config handed to serve() must carry \
         rotation_interval: None — no rotation-initiation timer. This is the assembly step \
         between a correct rotation_interval_from_env (pinned in rotation_interval_parse.rs) \
         and a correctly-gated serve() (pinned in rotation_disabled.rs), and it is the ONLY \
         thing standing between those two. The specific regression: writing \
         `rotation_interval: rotation_interval.or(Some(Config::default_rotation_interval()))` \
         here — for 'upgrade compatibility', or while resolving a merge conflict — leaves \
         every other test in this crate green while silently re-arming a 30-day automatic \
         rotation on every .deb, .rpm, container image and source build that never set the \
         variable. Automatic rotation still walks into docs/BACKLOG.md item 9, the rotation \
         wedge: a rotation that fails part-way parks the gateway's phase off `Idle`, \
         `Rotation::on_directive` is honoured only from `Idle`, and that gateway then \
         silently ignores every later RotateDirective until it is restarted, never scrubbing \
         the old key. On a 30-day fuse, on a fabric nobody is watching. An operator who \
         never made a choice must not have one made for them. Got: {:?}",
        config.rotation_interval
    );
}

/// The value is PASSED THROUGH, not merely defaulted to `None`.
///
/// The trap: `None` from an absent variable and `None` from a `config_from_env`
/// that ignores the environment entirely are indistinguishable in the field, so
/// an assembly hard-wired to `rotation_interval: None` would satisfy the test
/// above while breaking the knob for the operator who deliberately turns it on.
/// "Nothing ever rotates" is not the contract either — the escape hatch is
/// OPT-IN rotation, not NO rotation.
///
/// This is the technique `only_an_explicit_interval_can_arm_the_timer` uses one
/// layer down (`rotation_interval_parse.rs`), lifted to the assembly: an
/// explicit interval must arrive as exactly what `parse_rotation_interval`
/// makes of it — not filtered, clamped, rounded, or replaced — while both ways
/// of expressing no choice arrive as `None`.
#[test]
fn an_explicit_interval_reaches_config_unmodified() {
    for raw in ["30d", "12h", "900s", "  15m\n"] {
        let config = config_from(&[(ROTATION_INTERVAL_ENV, raw)]);
        let want = parse_rotation_interval(raw).expect("the same value parses standalone");
        assert_eq!(
            config.rotation_interval, want,
            "{ROTATION_INTERVAL_ENV}={raw:?} must reach Config.rotation_interval as exactly \
             what parse_rotation_interval makes of it. The assembly is a conduit, not a \
             policy: an operator who wrote an interval down gets that interval. Got: {:?}",
            config.rotation_interval
        );
        assert!(
            config.rotation_interval.is_some(),
            "{ROTATION_INTERVAL_ENV}={raw:?} is an operator explicitly ASKING for automatic \
             rotation, so the timer must be armed. Without this assertion a config_from_env \
             hard-wired to `rotation_interval: None` would pass every other rotation test in \
             this file — making absence mean 'no timer' must not turn into making everything \
             mean 'no timer'. Got: {:?}",
            config.rotation_interval
        );
    }

    // The two ways of expressing no choice. Both land on None — and they must
    // do so through the resolver, not because the field was hard-coded, which
    // the loop above is what rules out.
    for raw in ["off", "OFF", "  Off  "] {
        let config = config_from(&[(ROTATION_INTERVAL_ENV, raw)]);
        assert_eq!(
            config.rotation_interval, None,
            "{ROTATION_INTERVAL_ENV}={raw:?} is the explicit escape hatch and must reach \
             Config as None — no rotation-initiation timer. Got: {:?}",
            config.rotation_interval
        );
    }
    assert_eq!(
        config_from(NOTHING_SET).rotation_interval,
        config_from(&[(ROTATION_INTERVAL_ENV, "off")]).rotation_interval,
        "an unset {ROTATION_INTERVAL_ENV} and an explicit {ROTATION_INTERVAL_ENV}=off must \
         reach Config as the same thing. If they have diverged, one of the two paths grew a \
         default the other did not — which is precisely the pre-2026-08-12 shape, where `off` \
         worked perfectly and silence armed a 30-day timer"
    );
}

/// A malformed rotation interval is a STARTUP ERROR that names the variable —
/// the contract `rotation_interval_boot_reject.rs` observes end-to-end (non-zero
/// exit, stderr naming the variable), asserted at the seam so the extraction
/// cannot quietly swallow it.
///
/// The failure this prevents is the worst kind of silence: an operator who
/// typed `30dd` and believes they armed a monthly rotation, or who typed `of`
/// and believes they disabled one, with nothing to contradict them until the
/// day it matters.
#[test]
fn malformed_rotation_interval_is_a_startup_error_naming_the_variable() {
    for raw in [
        "of", "0", "30", "30dd", "30D", "abc", "", "   ", "-1d", "30w", "0s", "3651d",
    ] {
        let msg = config_rejected(&[(ROTATION_INTERVAL_ENV, raw)], |c| {
            format!("rotation_interval = {:?}", c.rotation_interval)
        });
        assert!(
            msg.contains(ROTATION_INTERVAL_ENV),
            "{ROTATION_INTERVAL_ENV}={raw:?} is malformed, and the rejection must name the \
             variable at fault — the controller reads eight WIREMESH_* variables and the \
             operator has to be told which one to fix. Got: {msg:?}"
        );
    }
}

/// A PRESENT-but-not-UTF-8 rotation interval is a startup error too.
///
/// This pins that the assembly hands `rotation_interval_from_env` the FULL
/// `std::env::var` result and not a lossy narrowing of it. The obvious thing to
/// write while extracting — collapse the lookup to `Option<String>` once, at
/// the top, because six of the eight variables only care about present-vs-absent
/// — destroys exactly this case: a mis-encoded value would read as absent, and
/// an operator who wrote `12h` would run with no timer at all while nothing told
/// them. `rotation_interval_from_env`'s signature exists to keep the third case
/// distinguishable; the assembly above it must not throw that away.
#[test]
fn non_utf8_rotation_interval_is_a_startup_error() {
    use std::os::unix::ffi::OsStringExt;
    // `off` with a stray continuation byte: present, non-empty, not a `String`.
    let not_utf8 = std::ffi::OsString::from_vec(vec![b'o', b'f', b'f', 0x80]);

    let result = config_from_env(|key| {
        if key == ROTATION_INTERVAL_ENV {
            Err(VarError::NotUnicode(not_utf8.clone()))
        } else {
            Err(VarError::NotPresent)
        }
    });
    match result {
        Ok(c) => panic!(
            "a PRESENT-but-not-UTF-8 {ROTATION_INTERVAL_ENV} must fail the boot, got a Config \
             with rotation_interval = {:?}. The operator SET this variable, so the one thing \
             that must not happen is the controller quietly picking a value for them: \
             treating it as absent leaves a fabric with no timer for someone who typed `12h`, \
             and treating it as an interval arms one for someone who typed `off`. This is the \
             case a lossy `std::env::var(k).ok()` lookup silently destroys.",
            c.rotation_interval
        ),
        Err(e) => {
            let msg = format!("{e:#}");
            assert!(
                msg.contains(ROTATION_INTERVAL_ENV),
                "the rejection must name {ROTATION_INTERVAL_ENV} — the bytes cannot be echoed \
                 back legibly, so the variable's name is the only thing the operator gets to \
                 act on. Got: {msg:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// `WIREMESH_BIND_IP` — the same untested-wiring shape, retro-covered.
// ---------------------------------------------------------------------------

/// An absent `WIREMESH_BIND_IP` binds loopback, which is the historical
/// behaviour every dev/test deployment depends on.
#[test]
fn absent_bind_ip_is_the_loopback_default() {
    let config = config_from(NOTHING_SET);
    assert_eq!(
        config.bind_ip,
        Config::default_bind_ip(),
        "with {BIND_IP_ENV} unset the enroll/sync/observe listeners must bind \
         Config::default_bind_ip() — 127.0.0.1. Widening that default would expose those \
         listeners on every interface of every host that installed the package without \
         asking for it; narrowing or changing it breaks every existing loopback deployment. \
         Got: {:?}",
        config.bind_ip
    );
    assert_eq!(
        Config::default_bind_ip(),
        std::net::Ipv4Addr::LOCALHOST,
        "sanity: the default is loopback. Asserted independently of the accessor so this \
         test cannot pass by agreeing with a default that was itself changed"
    );
}

/// An explicit bind IP is used verbatim. `0.0.0.0` is the one the Kubernetes
/// operator sets so the controller Service can reach those listeners, so it is
/// not a hypothetical.
#[test]
fn explicit_bind_ip_is_used_verbatim() {
    for raw in ["0.0.0.0", "10.0.125.41", "127.0.0.1", "192.168.1.7"] {
        let config = config_from(&[(BIND_IP_ENV, raw)]);
        let want: std::net::Ipv4Addr = raw.parse().expect("the test's own literal parses");
        assert_eq!(
            config.bind_ip, want,
            "{BIND_IP_ENV}={raw:?} must reach Config.bind_ip verbatim. `0.0.0.0` in \
             particular is what the Kubernetes operator emits (see \
             wiremesh-operator/src/workloads.rs) so the enroll/sync/observe listeners are \
             reachable through the controller Service — silently substituting the loopback \
             default there would make every operator-deployed controller unreachable. \
             Got: {:?}",
            config.bind_ip
        );
    }
}

/// A malformed bind IP WARNS AND FALLS BACK to loopback — it is deliberately
/// NOT a startup error, unlike a malformed port or rotation interval.
///
/// The asymmetry is intentional and worth stating, because it looks like an
/// inconsistency someone will one day "fix" in either direction: a wrong bind
/// IP announces itself the moment nothing can connect, whereas a wrong rotation
/// interval is invisible until it fires — or, since 2026-08-12, until it
/// doesn't. (`rotation_interval_from_env`'s doc comment records the same
/// reasoning from the other side.)
///
/// Note which fallback: LOOPBACK. A malformed value must never degrade to
/// `0.0.0.0`; "I could not understand you, so I exposed the fabric's control
/// plane on every interface" is not a recoverable mistake.
#[test]
fn malformed_bind_ip_falls_back_to_loopback_without_failing_the_boot() {
    for raw in [
        "not-an-ip",
        "999.1.1.1",
        "10.0.0",
        "10.0.0.1/24",
        "::1",
        "2001:db8::1",
        "",
    ] {
        let config = config_from_env(lookup_of(&[(BIND_IP_ENV, raw)])).unwrap_or_else(|e| {
            panic!(
                "{BIND_IP_ENV}={raw:?} is malformed, but it must NOT fail the boot — the \
                 binary warns on stderr and falls back to the loopback default. Turning this \
                 into a hard error would stop the boot of a controller that would otherwise \
                 have come up fine on loopback, which is a strictly worse outcome for a \
                 value whose wrongness is self-announcing. Got: {e:#}"
            )
        });
        assert_eq!(
            config.bind_ip,
            Config::default_bind_ip(),
            "{BIND_IP_ENV}={raw:?} must fall back to Config::default_bind_ip() (127.0.0.1), \
             never to a wildcard: a value the controller could not parse must not end up \
             exposing the enroll/sync/observe listeners on every interface. The IPv6 \
             literals are in this list on purpose — v1 is IPv4-only, and `bind_ip` is an \
             Ipv4Addr, so `::1` is a value an operator can plausibly type and must land here \
             rather than anywhere surprising. Got: {:?}",
            config.bind_ip
        );
    }
}

// ---------------------------------------------------------------------------
// The four port variables — same shape again.
// ---------------------------------------------------------------------------

/// Absent port variables mean `0` = OS-assigned, the convention every port in
/// `Config` follows.
#[test]
fn absent_ports_are_os_assigned() {
    let config = config_from(NOTHING_SET);
    for (field, got) in [
        ("tcp_port", config.tcp_port),
        ("sync_tcp_port", config.sync_tcp_port),
        ("admin_tcp_port", config.admin_tcp_port),
        ("observe_udp_port", config.observe_udp_port),
    ] {
        assert_eq!(
            got, 0,
            "with no port variables set, Config.{field} must be 0 — the OS-assigned \
             convention shared by every port in this struct. A non-zero default here would \
             be a fixed port nobody asked for, colliding with whatever already holds it. \
             Got: {got}"
        );
    }
}

/// Explicit ports land in the RIGHT fields.
///
/// Four `u16`s read in sequence into four adjacent fields of one struct literal
/// is the classic place for a copy-paste swap — `sync_tcp_port: tcp_port` reads
/// perfectly well and would leave the Sync listener on the enrollment port. So
/// every variable gets a DISTINCT value: any permutation of the four fails,
/// which a shared value like `8443` everywhere would not catch.
#[test]
fn explicit_ports_land_in_their_own_fields() {
    let config = config_from(&[
        (TCP_PORT_ENV, "18441"),
        (SYNC_TCP_PORT_ENV, "18442"),
        (ADMIN_TCP_PORT_ENV, "18443"),
        (OBSERVE_UDP_PORT_ENV, "18444"),
    ]);
    for (var, field, got, want) in [
        (TCP_PORT_ENV, "tcp_port", config.tcp_port, 18441u16),
        (
            SYNC_TCP_PORT_ENV,
            "sync_tcp_port",
            config.sync_tcp_port,
            18442,
        ),
        (
            ADMIN_TCP_PORT_ENV,
            "admin_tcp_port",
            config.admin_tcp_port,
            18443,
        ),
        (
            OBSERVE_UDP_PORT_ENV,
            "observe_udp_port",
            config.observe_udp_port,
            18444,
        ),
    ] {
        assert_eq!(
            got, want,
            "{var}={want} must reach Config.{field}. The four values here are deliberately \
             distinct so a crossed wire between two adjacent fields of the Config literal \
             fails loudly — an operator whose Sync listener silently came up on the \
             enrollment port would debug TLS handshakes for a day. Got: {got}"
        );
    }

    // Explicitly asking for the OS to choose is not the same as saying nothing,
    // and must still be accepted rather than rejected as "zero".
    let zeroed = config_from(&[(TCP_PORT_ENV, "0")]);
    assert_eq!(
        zeroed.tcp_port, 0,
        "an explicit {TCP_PORT_ENV}=0 asks the OS to assign, which is a legitimate value \
         (it is what the test harness and every ephemeral deployment use) and must be \
         accepted, not rejected the way a zero rotation interval is. Got: {}",
        zeroed.tcp_port
    );
}

/// A malformed port is a STARTUP ERROR naming the variable — not a silent `0`.
///
/// An operator who mistyped a port number has to find out at boot, rather than
/// discover later that their controller is listening on an ephemeral port
/// nothing is configured to dial.
#[test]
fn malformed_port_is_a_startup_error_naming_the_variable() {
    for &(var, field) in PORT_VARS {
        for raw in ["abc", "-1", "70000", "", "8443.0", "0x1f90"] {
            let msg = config_rejected(&[(var, raw)], |c| {
                format!(
                    "tcp_port={} sync_tcp_port={} admin_tcp_port={} observe_udp_port={}",
                    c.tcp_port, c.sync_tcp_port, c.admin_tcp_port, c.observe_udp_port
                )
            });
            assert!(
                msg.contains(var),
                "{var}={raw:?} is not a valid u16 port and must fail the boot with a message \
                 naming {var} (it feeds Config.{field}). Falling back to 0 would give the \
                 operator an OS-assigned ephemeral listener they never asked for and cannot \
                 dial, with nothing on stderr to explain it. Got: {msg:?}"
            );
        }
    }
}

/// A PRESENT-but-not-UTF-8 port variable is a startup error naming the
/// variable, not an absent one.
///
/// Same distinction the rotation interval preserves, for the same reason: the
/// variable IS set, so "fall back to the default" answers a question the
/// operator did answer.
#[test]
fn non_utf8_port_is_a_startup_error() {
    use std::os::unix::ffi::OsStringExt;
    let not_utf8 = std::ffi::OsString::from_vec(vec![b'8', b'4', b'4', b'3', 0x80]);

    let result = config_from_env(|key| {
        if key == TCP_PORT_ENV {
            Err(VarError::NotUnicode(not_utf8.clone()))
        } else {
            Err(VarError::NotPresent)
        }
    });
    match result {
        Ok(c) => panic!(
            "a PRESENT-but-not-UTF-8 {TCP_PORT_ENV} must fail the boot, got Config.tcp_port \
             = {}. Treating it as absent hands the operator an OS-assigned port in place of \
             the one they tried to set, and says nothing.",
            c.tcp_port
        ),
        Err(e) => {
            let msg = format!("{e:#}");
            assert!(
                msg.contains(TCP_PORT_ENV),
                "the rejection must name {TCP_PORT_ENV} — the bytes cannot be echoed back \
                 legibly, so the variable's name is all the operator has. Got: {msg:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Paths.
// ---------------------------------------------------------------------------

/// The absent-case paths are the production locations the packaging, the
/// systemd unit and the docs all assume.
#[test]
fn absent_paths_are_the_production_locations() {
    let config = config_from(NOTHING_SET);
    assert_eq!(
        config.data_dir,
        PathBuf::from("/var/lib/wiremesh"),
        "with {DATA_DIR_ENV} unset the controller must use /var/lib/wiremesh — the directory \
         holding the SQLite DB, the embedded CA and the secrets, and the path the .deb/.rpm \
         create, the systemd unit points at, and docs/install.md documents. Changing it \
         silently orphans an existing fabric's CA and database. Got: {:?}",
        config.data_dir
    );
    assert_eq!(
        config.socket_path,
        PathBuf::from("/run/wiremesh/controller.sock"),
        "with {SOCKET_PATH_ENV} unset the Admin UDS must be /run/wiremesh/controller.sock — \
         the path `fabricctl` dials by default. Changing it breaks every local admin command \
         on an otherwise healthy controller. Got: {:?}",
        config.socket_path
    );
}

/// Explicit paths are used verbatim — this is how the packaging and the test
/// harness relocate a controller.
#[test]
fn explicit_paths_are_used_verbatim() {
    let config = config_from(&[
        (DATA_DIR_ENV, "/srv/wiremesh/data"),
        (SOCKET_PATH_ENV, "/srv/wiremesh/run/controller.sock"),
    ]);
    assert_eq!(
        config.data_dir,
        PathBuf::from("/srv/wiremesh/data"),
        "{DATA_DIR_ENV} must reach Config.data_dir verbatim — relocating the data directory \
         is the supported way to run a controller outside /var/lib. Got: {:?}",
        config.data_dir
    );
    assert_eq!(
        config.socket_path,
        PathBuf::from("/srv/wiremesh/run/controller.sock"),
        "{SOCKET_PATH_ENV} must reach Config.socket_path verbatim. Note it is NOT derived \
         from data_dir: the two are set independently (the socket belongs under /run, which \
         is tmpfs, while the data directory must persist). Got: {:?}",
        config.socket_path
    );
}

// ---------------------------------------------------------------------------
// The two fields that must NOT become environment-settable.
// ---------------------------------------------------------------------------

/// `legacy_data_dir` stays `None` no matter what the environment says.
///
/// This one is a safety property, not a convenience: `legacy_data_dir` is the
/// directory the CA re-mint guard probes before it will mint a new CA, and
/// `Config::legacy_data_dir`'s doc comment states outright that wiring it to an
/// environment variable would be a one-line bypass of the guard — whose entire
/// job is to stop a misconfiguration from rotating the fabric's trust anchor
/// and invalidating every enrolled identity at once. An extraction that
/// mechanically gave every `Config` field an env var, or a later "make it
/// testable" edit, would open exactly that hole; the field is left `None` so
/// production always probes the real `/var/lib/wiremesh`.
#[test]
fn legacy_data_dir_is_never_environment_settable() {
    let plausible_spellings = [
        ("WIREMESH_LEGACY_DATA_DIR", "/tmp/not-the-real-one"),
        ("WIREMESH_LEGACY_DIR", "/tmp/not-the-real-one"),
        ("WIREMESH_CA_LEGACY_DATA_DIR", "/tmp/not-the-real-one"),
        // Set alongside a relocated data_dir, which is the shape a real
        // "let me point everything somewhere else" attempt would take.
        (DATA_DIR_ENV, "/srv/wiremesh/data"),
    ];
    for pair in plausible_spellings {
        let config = config_from(&[pair]);
        assert!(
            config.legacy_data_dir.is_none(),
            "Config.legacy_data_dir must stay None so the CA re-mint guard always probes the \
             real /var/lib/wiremesh — see Config::legacy_data_dir's doc comment: an \
             operator-settable override is a one-line bypass of the guard that exists to \
             stop a misconfiguration from re-minting the fabric's trust anchor and \
             invalidating every enrolled gateway, relay and client identity at once. \
             {} produced legacy_data_dir = {:?}",
            pair.0,
            config.legacy_data_dir
        );
    }
}

/// The decision-sweep interval is the library default and is not read from the
/// environment.
///
/// It is deliberately NOT an operator knob: the sweep is what promotes, retires
/// and recovers rotations that are already in flight, and it keeps running even
/// when the initiation timer is off (see `Config::rotation_interval`'s doc, and
/// `rotation_disabled.rs::sweep_still_drives_in_flight_rotations_with_the_timer_disabled`).
/// An operator who set it to something large — or who confused it with
/// `WIREMESH_ROTATION_INTERVAL` and set it to `off`-adjacent nonsense — would
/// strand half-finished rotations, which is worse than either rotating or not.
#[test]
fn rotation_sweep_interval_is_the_default_and_not_environment_settable() {
    let cases: [&[(&str, &str)]; 3] = [
        NOTHING_SET,
        &[("WIREMESH_ROTATION_SWEEP_INTERVAL", "12h")],
        &[(ROTATION_INTERVAL_ENV, "30d")],
    ];
    for pairs in cases {
        let config = config_from(pairs);
        assert_eq!(
            config.rotation_sweep_interval,
            Config::default_rotation_sweep_interval(),
            "Config.rotation_sweep_interval must be Config::default_rotation_sweep_interval() \
             regardless of the environment ({pairs:?}). The sweep drives in-flight rotations \
             to completion and recovers crash-orphaned `retiring` rows; it is not the \
             operator-facing schedule knob and must not become one by accident, and it must \
             not be coupled to {ROTATION_INTERVAL_ENV} either — it keeps running when the \
             initiation timer is off, which is the whole reason turning the timer off does \
             not strand a rotation that had already started. Got: {:?}",
            config.rotation_sweep_interval
        );
    }
    assert_eq!(
        Config::default_rotation_sweep_interval(),
        Duration::from_secs(5),
        "sanity: the sweep default is 5 seconds. Stated independently of the accessor so the \
         assertions above cannot pass by agreeing with a default that was itself changed"
    );
}

// ---------------------------------------------------------------------------
// The environment is actually consulted.
// ---------------------------------------------------------------------------

/// Every documented variable is READ. A field quietly hard-wired to its default
/// still satisfies the absent-case tests above — this is what distinguishes
/// "the assembly resolved to the default" from "the assembly never asked".
///
/// Only membership is asserted, never order or count: which variable is read
/// first is an implementation detail, and a variable read twice is harmless.
#[test]
fn every_documented_variable_is_actually_consulted() {
    let seen = std::cell::RefCell::new(Vec::new());
    let config = config_from_env(|key| {
        seen.borrow_mut().push(key.to_string());
        Err(VarError::NotPresent)
    })
    .expect("an all-absent environment must assemble, not error");

    // Asserted here too, so this test cannot pass against an assembly that
    // consulted every variable correctly and then ignored what it got.
    assert_eq!(
        config.rotation_interval, None,
        "sanity: the all-absent case still resolves to no timer (the contract pinned in \
         all_absent_environment_arms_no_rotation_timer). Got: {:?}",
        config.rotation_interval
    );

    let seen = seen.into_inner();
    for var in ALL_VARS {
        assert!(
            seen.iter().any(|k| k == var),
            "config_from_env never consulted {var}. Every one of these is an operator-facing \
             knob documented in docs/install.md and shipped in \
             deploy/packages/env/controller.env; a field hard-wired to its default looks \
             identical to a resolved default in every other test here, and would leave an \
             operator editing a variable nothing reads. Variables actually looked up: {seen:?}"
        );
    }
}
