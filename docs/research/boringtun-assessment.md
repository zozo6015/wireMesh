# boringtun Maintenance-Health Assessment (Phase 0, Bet 1)

Bet 1 under assessment: *embed boringtun (userspace WireGuard) as a library,
configure it externally via the standard `wg` UAPI socket, as the gateway's
primary data-plane implementation.* This doc folds together Task 3's
API-friction/root-cause findings, Task 4's throughput measurement, and fresh
upstream facts (gathered 2026-07-15) into one recommendation for the Phase 0
report (Task 15).

## Facts (as of 2026-07-15)

Gathered via `gh api` against `cloudflare/boringtun` (raw output in the
Appendix):

- **Archived?** No (`"archived": false`).
- **Last push to the repo:** `pushed_at: 2026-06-29T06:18:56Z` (< 3 weeks
  before this assessment).
- **Last commit on the default branch (`master`):** `2026-06-15T07:58:57Z`
  (from `commits?per_page=5`; the two 2026-06-05 and two 2026-05-01 commits in
  the same sample show a steady, non-bursty commit cadence, not a
  one-off pushed-and-abandoned repo).
- **Open issues:** `open_issues_count: 106` at the repo-object level, which
  GitHub's API defines as issues **plus** PRs combined. Split via the search
  API: **74 open issues**, **32 open pull requests** — a healthy PR pipeline
  (PRs are actively being proposed, not just issues piling up unanswered).
  The newest open items are dated 2026-07-05 (`#489`–`#491`, e.g. "Don't roam
  peer endpoint on cookie replies", "Use ip+port for calculating cookie") and
  2026-06-29 (`#488`, a dependency bump) — i.e. active upstream traffic in the
  two weeks before this assessment, not just drive-by issue filing. Caveat:
  these four items came from the `/issues` endpoint, which returns issues and
  PRs mixed, so their issue-vs-PR classification is inferred from the titles
  (code-change/dependency-bump phrasing), not strictly proven by the endpoint
  itself. `#492` ("docs: include modules behind feature flags", 2026-07-12) is
  the newest item of all but is omitted from this activity narrative because
  it reads as a documentation request, not code-change traffic.
- **Formal GitHub "Releases" page is stale, but tags are not:** the
  `/releases` endpoint's newest 3 entries are all from **2022**
  (`boringtun-cli-0.5.2` / `boringtun-0.5.2`, 2022-07-20; `boringtun-cli-0.5.1`,
  2022-07-14). Taken alone this would look like the project stopped shipping
  in 2022. It hasn't: the `/tags` endpoint shows newer, un-"released" tags —
  `boringtun-0.7.1` / `boringtun-cli-0.7.1` — whose annotated-tag date is
  **2026-05-01T22:56:08Z**. Cloudflare evidently keeps cutting version tags
  (and, per crates.io, publishing them) without maintaining the GitHub
  Releases page's release notes. **Takeaway: judge this project's release
  cadence by tags/commits, not by the Releases tab — the Releases tab alone
  would materially mislead.**
- **Version actually used by our spike vs. current upstream:** `spike/tunnel`
  pins `boringtun = { version = "0.6", features = ["device"] }`
  (`spike/tunnel/Cargo.toml:7`), locked to `0.6.0`
  (`spike/tunnel/Cargo.lock`). Current upstream is `0.7.1` (tagged
  2026-05-01) — we are one minor version behind, not on an abandoned line.
- **Our observed API friction (Task 3, Step 4):**
  - The brief's sketched API (`DeviceConfig::default()`, `cfg.n_threads = 2`,
    `DeviceHandle::new(&ifname, cfg)`, `handle.wait()`) matched boringtun
    0.6.0's real API **verbatim** — zero field-name drift, confirmed against
    `boringtun-0.6.0/src/device/mod.rs`. The only friction was converting
    `boringtun::device::Error` (doesn't impl `std::error::Error`) to
    `anyhow::Error` at the call site — a minor ergonomics point, not an API
    break.
  - A real, load-bearing finding did surface, but it's an architectural
    property, not a code bug: the UAPI control socket
    (`register_api_handler()` in `boringtun-0.6.0/src/device/api.rs`) binds a
    Unix socket at a fixed path `/var/run/wireguard/<ifname>.sock`, scoped
    only by the process's **mount** namespace, never by the **network**
    namespace the device's TUN interface lives in — unlike kernel WireGuard's
    netlink-based configuration, which is network-namespace-aware by
    construction. Two same-named interfaces sharing a mount namespace (as our
    two-peer `natlab` test did by default) collide: the second to bind
    silently deletes and replaces the first's socket file, and every
    subsequent `wg` command from either side is misrouted to whichever device
    won the race. Full root-cause trace and the `natlab` fix (private,
    forced-`rprivate` mount namespace per `Ns`) are preserved in the Appendix
    (originally Task 3's scratch notes). **Not a concern for the
    production one-gateway-per-segment/pod model** (each gateway process
    already has its own mount namespace by construction) — it only bit the
    test lab, which now works around it in `natlab` itself, reusable by
    Tasks 6–9 and 14.
  - Net effect on Bet 1's narrow claim ("embed boringtun as a library,
    configure via UAPI"): **validated** for the single-instance-per-host case
    the real gateway will run.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| **boringtun as-is (crates.io, track upstream releases)** | Zero maintenance burden on us; upstream is actively committed to (last commit 2026-06-15, 32 open PRs) and not archived; matches spec's "boringtun primary" decision; embedding API already proven to work exactly as documented (Task 3); upgrade path from our pinned 0.6.0 to current 0.7.1 is a routine minor-version bump, not a rewrite | We inherit upstream's release cadence and any regressions in its receive path; the Releases page being stale means we must track tags/crates.io, not GitHub's Releases tab, to know when to update; **the ~7.7 Mbit/s in-container receive-side cap (Task 4) is unexplained and, if it turns out to be a boringtun receive-pipeline property rather than environment noise, this option inherits that ceiling** |
| **boringtun vendored fork** | Full control to patch the receive path immediately if the cloud run reproduces the cap; can pin/audit exact code independent of upstream churn | Maintenance burden shifts entirely to us — every upstream security fix (WireGuard is a security-sensitive protocol implementation) now has to be manually re-applied or re-merged; premature until we know *whether* there's even a bug to fix (see Throughput evidence below) — forking blind is wasted effort if the cap turns out to be Docker-Desktop/linuxkit-specific |
| **kernel WireGuard only (netlink via a `wireguard-control`-style crate)** | Fastest path available — kernel-side WireGuard has none of a userspace receive-pipeline's syscall/copy overhead, and completely sidesteps the mount-namespace-scoped-UAPI finding above (netlink is network-namespace-aware natively); "maintained in-kernel" means no separate userspace crate to track at all | **Kills the userspace-everywhere story** the spec calls for boringtun-primary to serve: LXC containers and no-kernel-module hosts can't load the WireGuard kernel module and would have no data plane at all under kernel-only. Adopting this as the *only* path is a **spec change** (spec currently designates boringtun as primary specifically to cover that case), not a drop-in swap — it would need to go back through the same decision process that set boringtun-primary in the first place |
| **own Noise impl (`snow` crate) + own device layer** | No dependency on boringtun's release cadence or design choices at all | Reimplementing and re-auditing a WireGuard-compatible transport is out of this spike's budget and audit scope entirely; discarded without further analysis for that reason alone — not a serious contender at Phase 0 |

## Throughput evidence

(Full detail, environment, and raw transcripts: `docs/research/phase0-results.md`,
"Bet 1: boringtun throughput" section.)

Measured inside the dev container (Docker Desktop/linuxkit VM on an Apple
Silicon host, `nproc=8`, explicitly **not** representative of production and
not to be used to judge the G-2 gate on its own):

- Baseline veth (no tunnel): ~131 Gbit/s — confirms the lab harness itself has
  no artificial bottleneck.
- boringtun tunnel, MTU 1280, TCP forward/reverse: ~7.5–7.8 Mbit/s both
  directions — roughly 3 orders of magnitude below the veth baseline and far
  below the ≥1 Gbps G-2 target.
- Follow-up diagnostic (same setup): UDP burst at `-b 500M` shows the sender
  delivering the full offered rate at **0% send-side loss**, while the
  receiver delivers only ~7.27 Mbit/s with **98% datagram loss**
  (250169/254031 lost). Parallel TCP (`-P 4`) aggregates to ~8.0 Mbit/s —
  parallelism doesn't move the cap. TCP retransmits stay low (7–10 per 10 s
  run), ruling out an MSS/retransmit-storm explanation.

This is the signature of a **fixed receive-side delivery cap** — consistent
with a receive-pipeline bottleneck (decrypt → TUN write, or an internal queue
silently dropping) — and is **inconsistent with plain environment noise**
like shared-vCPU scheduling jitter, which would be expected to show variable
loss/throughput, not a near-identical ~7.3–7.8 Mbit/s ceiling across TCP
forward, TCP reverse, TCP×4-parallel, and raw UDP alike.

**The cause has not been isolated.** It may be specific to running under a
Docker-Desktop/linuxkit VM on Apple Silicon (a real and plausible
possibility — nested virtualization and linuxkit's network stack are known
sources of exactly this kind of artificial ceiling), or it may be a genuine
boringtun receive-path property that will reproduce on real hardware. The
**G-2 cloud run** (re-running this exact, unmodified `bench.sh` on a
non-virtualized 4-vCPU cloud VM, checking specifically for the same
receive-side datagram-loss signature via `iperf3 -u -b 0`) is the designated
discriminator between these two explanations and has **not yet been run**.

## Recommendation

**Adopt boringtun as-is (crates.io), conditional on the G-2 cloud run —
do not fork, and do not escalate to a kernel-only spec change yet.**

Reasoning tied to the facts above:

1. **Maintenance health supports "as-is."** The repo is not archived, has a
   default-branch commit from 2026-06-15 and a repo push as recent as
   2026-06-29 (both within a month of this 2026-07-15 assessment), an active
   32-PR review pipeline, and version tags (0.7.1) two minor versions ahead
   of the 0.5.2 a stale-looking Releases page would suggest is latest. This
   clears the bar for "safe to depend on
   without vendoring" — vendoring is a burden-shifting move that should be
   reserved for a project that's actually abandoned or for a bug upstream
   won't fix, neither of which is established here.
2. **The API friction found in Task 3 does not argue against adoption.** The
   embedding API matched our sketch exactly; the one real finding (UAPI
   socket is mount-namespace-, not network-namespace-scoped) is a documented,
   worked-around property that does not affect the production
   one-gateway-per-segment/pod topology at all — it only bit our multi-peer
   test lab, and `natlab` now handles it for every later task.
3. **The throughput cap is the one fact that could flip this recommendation,
   and it is explicitly unresolved.** This recommendation is therefore
   **conditional, not final**: it holds *if* the G-2 cloud run does not
   reproduce the ~98% receive-side loss signature. If that signature *does*
   reproduce on non-virtualized hardware, this recommendation should be
   revisited immediately — re-open this assessment, and treat "vendored fork
   to patch the receive path" as the next option to pursue *before*
   escalating to a kernel-only spec change, since forking is reversible and
   keeps boringtun-primary (and the LXC/no-module use case it protects) intact
   while a fix is pursued.
4. **Kernel-WireGuard-only is explicitly not recommended at this time**,
   even considering the throughput cap, because switching primaries is a
   spec change (the spec designates boringtun primary specifically to serve
   hosts without a loadable WireGuard kernel module) and no evidence yet
   distinguishes "boringtun has a receive bottleneck" from "this container
   environment has one" — escalating to a spec change on unconfirmed data
   would be premature. If the G-2 run *does* confirm a genuine boringtun
   receive-path ceiling that a vendored fork cannot practically close, kernel-
   WireGuard-only (accepting the LXC/no-module gap, or gating it behind a
   fallback/degraded mode for that minority of hosts) becomes the escalation
   path — but that is a decision for after G-2 data exists, not now.
5. **Action item, not optional:** run the pending G-2 `bench.sh` on a real
   4-vCPU cloud VM and record the result in `docs/research/phase0-results.md`
   before Bet 1 is considered validated for the G-2 gate, per the note
   already in that doc.

## Appendix: raw gh api output

Commands run 2026-07-15 against `cloudflare/boringtun` (host, via `gh`):

```
$ gh api repos/cloudflare/boringtun --jq '{pushed_at, open_issues_count, archived}'
{"archived":false,"open_issues_count":106,"pushed_at":"2026-06-29T06:18:56Z"}

$ gh api repos/cloudflare/boringtun/releases --jq '.[0:3][] | {tag_name, published_at}'
{"published_at":"2022-07-20T17:04:19Z","tag_name":"boringtun-cli-0.5.2"}
{"published_at":"2022-07-20T17:03:41Z","tag_name":"boringtun-0.5.2"}
{"published_at":"2022-07-14T21:13:35Z","tag_name":"boringtun-cli-0.5.1"}

$ gh api "repos/cloudflare/boringtun/commits?per_page=5" --jq '.[].commit.committer.date'
2026-06-15T07:58:57Z
2026-06-05T23:07:58Z
2026-06-05T22:49:05Z
2026-05-01T22:49:48Z
2026-05-01T22:49:48Z
```

Follow-up commands run to explain the stale-looking Releases page and
disambiguate "open_issues_count" (issues vs. PRs):

```
$ gh api repos/cloudflare/boringtun/releases --jq '.[] | {tag_name, published_at}'
{"published_at":"2022-07-20T17:04:19Z","tag_name":"boringtun-cli-0.5.2"}
{"published_at":"2022-07-20T17:03:41Z","tag_name":"boringtun-0.5.2"}
{"published_at":"2022-07-14T21:13:35Z","tag_name":"boringtun-cli-0.5.1"}
{"published_at":"2022-07-14T21:12:27Z","tag_name":"boringtun-0.5.1"}
{"published_at":"2022-07-11T20:38:18Z","tag_name":"v0.5.0"}
{"published_at":"2022-03-07T19:11:15Z","tag_name":"v0.4.0"}
(the full /releases list; nothing newer than 2022 has a formal GitHub Release)

$ gh api "repos/cloudflare/boringtun/tags?per_page=10" --jq '.[].name'
v0.5.0
v0.4.0
v0.3.0
v0.2.0
boringtun-cli-0.7.1
boringtun-cli-0.7.0
boringtun-cli-0.5.2
boringtun-cli-0.5.1
boringtun-0.7.1
boringtun-0.7.0

$ gh api repos/cloudflare/boringtun/git/refs/tags/boringtun-0.7.1
{"ref":"refs/tags/boringtun-0.7.1", ...,
 "object":{"sha":"56fc417ef7e3c85ca530aa4ddee6e8a646bace55","type":"tag", ...}}

$ gh api repos/cloudflare/boringtun/git/tags/56fc417ef7e3c85ca530aa4ddee6e8a646bace55 --jq '{tag, tagger, object}'
{"object":{"sha":"253f7afb2b3df9e952065d10bf2af19913cb176b","type":"commit", ...},
 "tag":"boringtun-0.7.1",
 "tagger":{"date":"2026-05-01T22:56:08Z","email":"csinead@cloudflare.com","name":"Celeste Sinéad"}}

$ gh api "search/issues?q=repo:cloudflare/boringtun+type:issue+state:open" --jq '.total_count'
74

$ gh api "search/issues?q=repo:cloudflare/boringtun+type:pr+state:open" --jq '.total_count'
32

$ gh api "repos/cloudflare/boringtun/issues?state=open&sort=created&direction=desc&per_page=5" --jq '.[] | {number, title, created_at}'
{"created_at":"2026-07-12T00:54:48Z","number":492,"title":"docs: include modules behind feature flags"}
{"created_at":"2026-07-05T15:17:14Z","number":491,"title":"Pad  transport messages to a multiple of 16 bytes (WiP)"}
{"created_at":"2026-07-05T15:12:34Z","number":490,"title":"Use ip+port for calculating cookie"}
{"created_at":"2026-07-05T14:04:17Z","number":489,"title":"Don't roam peer endpoint on cookie replies"}
{"created_at":"2026-06-29T06:18:57Z","number":488,"title":"build(deps): bump actions/cache from 5 to 6"}
```

## Appendix: Task 3 root-cause notes (preserved verbatim)

The following are Task 3's original scratch notes on the boringtun 0.6
embedding API and the mount-namespace-scoped UAPI socket finding, preserved
in full since Sections above summarize but do not replace this level of
detail.

### What was checked

boringtun 0.6's `device` feature, embedded via `boringtun::device::{DeviceConfig,
DeviceHandle}`, configured externally via the standard `wg` UAPI socket — the
embedding mode the future gateway will use.

### API match vs. the brief's sketch

The brief's Step 2 sketch (`DeviceConfig::default()`, `cfg.n_threads = 2`,
`DeviceHandle::new(&ifname, cfg)`, `handle.wait()`) matched boringtun 0.6.0's real
API **verbatim** — no field renames were needed. Confirmed against source at
`/usr/local/cargo/registry/src/index.crates.io-*/boringtun-0.6.0/src/device/mod.rs`:

- `DeviceConfig { n_threads, use_connected_socket, use_multi_queue, uapi_fd }`
  implements `Default` exactly as sketched.
- `DeviceHandle::new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error>`
  synchronously creates the TUN device and registers the UAPI handler (when
  `uapi_fd < 0`, the default) before returning — so by the time `DeviceHandle::new`
  returns `Ok`, `/var/run/wireguard/<ifname>.sock` already exists and `wg` can talk
  to it immediately.

No corrections to the sketch were required for the binary itself. The `Result<_,
boringtun::device::Error>` needed converting to `anyhow::Error` at the call site
(`.map_err(|e| anyhow::anyhow!(...))`), a minor ergonomics point, not an API break.

### Real finding: UAPI socket is mount-namespace-scoped, not network-namespace-scoped

This is the substantive discovery, and it did not come from a field-name mismatch —
it came from the integration test failing intermittently/deterministically at the
`wg set` / `ip addr add` / `ping` stage even after the device came up correctly on
both sides.

**Root cause** (confirmed via `boringtun-0.6.0/src/device/api.rs::register_api_handler`):

```rust
const SOCK_DIR: &str = "/var/run/wireguard/";
...
let path = format!("{}/{}.sock", SOCK_DIR, self.iface.name()?);
create_sock_dir();
let _ = remove_file(&path);              // unlinks any existing socket at that path
let api_listener = UnixListener::bind(&path)...;
```

The UAPI control socket path is derived **only from the interface name** and lives
in the process's *mount* namespace. It is **not** scoped by the *network*
namespace the device's TUN interface actually lives in. Real kernel WireGuard
avoids this because kernel-side configuration goes over generic netlink, which
*is* network-namespace-aware; boringtun's userspace fallback protocol (the
original wg-quick/wireguard-go UAPI convention) predates that and is a plain
Unix domain socket at a fixed path.

`ip netns exec <ns> <cmd>` (used throughout `natlab`, and by the test's own `wg`
invocations) isolates the **network** namespace only. It does *not* give each
namespace a private `/run`: `ip netns exec`'s own internal `unshare(CLONE_NEWNS)`
clones the *mount table*, but `/run` is normally an existing tmpfs *instance*
shared by the whole container, so the clone still points at the same underlying
filesystem. Verified directly:

```
ip netns exec dbg-a sh -c 'echo FROM_A > /var/run/wireguard/marker'
ip netns exec dbg-b cat /var/run/wireguard/marker   # => FROM_A (visible!)
```

**Consequence for this test:** the test's two `spike-tunnel` processes both use
interface name `wg0` (required — the test's own `wg`/`ip` commands hardcode
`wg0` in both namespaces, mirroring how a real gateway would name its interface).
Both processes' `register_api_handler()` calls race to bind
`/var/run/wireguard/wg0.sock`; whichever binds *last* silently deletes
(`remove_file`) the other's socket file and takes over the path. Every subsequent
`wg set`/`wg show wg0` call from *either* namespace then talks to whichever
device most recently won that race — regardless of which network namespace
issued the command. Observed symptom: `wg show wg0` in both namespaces showed
**identical** state (both peers configured on one device), while the other
device silently received zero configuration, so the "overlay ping" had no
working WireGuard session on one end and failed with 100% packet loss. This
reproduced consistently under manual, non-cargo-test reproduction, ruling out a
cargo-test-specific timing fluke.

**This is a structural incompatibility, not a fixable code bug** in the binary:
no ordering, retry, or delay logic inside `spike-tunnel` can avoid it, because
exactly one inode can exist at `/var/run/wireguard/wg0.sock` at a time in a
shared mount namespace, and the stock `wg` CLI hardcodes that path from the
ifname argument with no override. It only doesn't bite in production because a
real gateway is its own process on its own host/pod — i.e. it already has a
private mount namespace by construction. It only surfaces here because the test
lab (`natlab`) puts two same-named interfaces in one shared mount namespace.

### Fix applied (in `spike/natlab`, not `spike/tunnel`)

Gave each `natlab::Ns` its own **persistent, private mount namespace** (created
via `unshare --mount=<pin-file>`, a util-linux ≥ 2.33 feature — confirmed present,
util-linux 2.38.1 in the dev container) with a private `tmpfs` mounted at
`/var/run/wireguard`. `Ns::exec`/`Ns::spawn` now do
`nsenter --mount=<pin> -- ip netns exec <name> <cmd>` instead of bare
`ip netns exec <name> <cmd>`. Validated in isolation (outside cargo test) that:
writes to one Ns's private `/var/run/wireguard` are invisible from the other Ns
and from the root mount namespace, and that with this in place both `wg show`
outputs correctly diverge (one peer each) and the ping succeeds with 0% loss.

This is a `natlab` API-surface-preserving change (no signature changes to
`Ns`/`Lab` public methods), so `tests/tunnel_ping.rs` required zero changes.
Verified no regression: `spike/natlab`'s own `veth_ping.rs` test still passes.

A follow-up reviewer defect fix (commit `3fcfc29`) hardened this further: the
initial `unshare --mount=<pin>` setup mounted the private tmpfs without forcing
mount propagation, so isolation depended on the container's ambient
propagation default for `/run`. The fix runs `mount --make-rprivate /` inside
the unshare'd namespace *before* creating the tmpfs mount, so isolation holds
by construction regardless of ambient defaults.

### Assessment input carried forward from Task 3

- boringtun 0.6's embedded `device` feature works exactly as documented for the
  single-instance-per-host case the real gateway will use — Bet 1 (embed +
  external `wg`-UAPI config) is **validated**.
- The UAPI socket's mount-namespace scoping (vs. network-namespace scoping) is a
  real, load-bearing property worth flagging for the actual gateway design: if
  the gateway ever runs multiple logical interfaces with the same name in the
  same mount namespace (e.g. multiple gateway processes on one host sharing a
  container), they will collide exactly like this test did. Not a concern for
  the current one-gateway-per-segment/pod model, but worth a design note if that
  assumption ever changes.
- This finding, and the `natlab` fix, should be reused verbatim by Tasks 6–9 and
  14, which copy the same lab pattern — otherwise they will hit the identical
  collision as soon as they spin up two same-named tunnel interfaces.
