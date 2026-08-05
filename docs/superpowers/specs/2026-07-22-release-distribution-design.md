# WireMesh release & distribution — design

Status: approved shape (owner decisions 2026-07-22, **amended 2026-07-23**). Build
in progress on branch `release-pipeline`. Complements the already-merged
container images (`deploy/docker/Dockerfile` + `.github/workflows/container-images.yml`,
PR #15 → ghcr.io/zozo6015/wiremesh-*).

## 0. 2026-07-23 amendments (owner decisions)
- **Windows is now IN scope** (was §7 out-of-scope): ship a Windows x86_64
  `fabricctl` binary **and a Windows `.msi` installer** (WiX, fabricctl + a PATH
  entry; Authenticode-unsigned until an owner code-signing cert is provisioned —
  same skip-with-notice guard as the other signing jobs).
> **AMENDED 2026-08-05 (owner decision).** macOS is no longer admin-only. A
> **single-host client peer** is in scope (PRD Non-Goals item 1 amendment; design §11.8),
> so macOS gains a **per-device connectivity** role alongside its admin/control-plane
> components — the artifact list below grows a `wiremesh-client` column when that ships.
> **The gateway stays Linux-only and that is unchanged**: the client needs no enforcer of
> its own (PRD G-4a), so it does not require the `pf` backend that the gateway exclusion
> exists to avoid. Do not read "macOS = fabricctl + controller + relay" below as evidence
> that macOS cannot carry data-plane connectivity; it means macOS cannot host a *gateway*.

- **Component scope: macOS = fabricctl + controller + relay; Windows = fabricctl
  ONLY.** Discovered during the build (2026-07-23): the controller and relay use
  Unix-only APIs unconditionally — a `tokio::net::UnixListener` admin socket and
  `std::os::unix::fs` 0600 secret perms — so they compile on macOS (Unix) but
  **not on Windows**. Windows isn't a control-plane/relay target, so we ship only
  the admin CLI there; `fabricctl`'s own `--socket` UDS path is `#[cfg(unix)]`-gated
  so it builds on Windows and uses TCP admin (`--addr`+`--token`) instead. The
  **gateway stays Linux-only** (eBPF/tun). `mkcerts` rides with relay.
- **Versioning is git-tag-driven**: pushing `vMAJOR.MINOR.PATCH` sets that version
  everywhere — the built binaries' `--version`, tarball/deb/rpm/msi/pkg names, package
  versions, and the GitHub Release. `workflow_dispatch` takes an explicit `version`
  input (default `0.0.0-dev`) for unsigned dry-runs. A `scripts/set-version.sh`
  rewrites the packaged crates' `[package] version` before building so the binaries
  self-report the release version. `Cargo.toml` holds the base/dev version.
- **Build strategy simplified to NATIVE runners per arch** (supersedes §4.1's
  `cross`): Linux amd64 on `ubuntu-latest`, arm64 on `ubuntu-24.04-arm`; macOS
  x86_64 on `macos-13`, arm64 on `macos-14`; Windows on `windows-latest`. The arm64
  gateway "cross-compile risk" (§7) is **moot** — `container-images.yml` already
  builds the arm64 gateway natively (running on the cluster). Linux binaries are
  extracted from the existing Dockerfile `builder` via a new `FROM scratch AS export`
  stage (`docker buildx build --target export --output`), reusing the proven eBPF
  toolchain build; mac/Windows build the portable crates directly with stable
  `cargo` (no eBPF toolchain needed — those crates don't depend on the enforcer).

## 1. Goal
Distribute the WireMesh binaries the ways users actually consume them, on
`v*` release tags, for **x86_64 + arm64** (Windows x86_64 per §0):
1. **Standalone binaries** — per-component tarballs attached to the GitHub Release (+ `SHA256SUMS`).
2. **Linux `.deb` + `.rpm`** — attached to the Release as downloads. WireMesh
   itself **hosts no package repository** (project tenet: ships binaries + docs,
   never hosted infrastructure); an *optional, self-hostable* GPG-signed apt/yum
   repo tree the user can stand up from these assets is a follow-up (§4.2).
3. **Windows `.msi`** (fabricctl) + **macOS `.pkg`** installers (unsigned until
   signing secrets are provisioned).

## 2. Platform × component matrix (THE hard constraint)
> **AMENDED by §0 (2026-07-23):** add a **Windows x86_64** column — `fabricctl`
> only (controller/relay are Unix-only servers; gateway is Linux-only). The table
> below shows Linux+macOS; Windows = fabricctl (`.msi`/tarball) as in §0.

The **gateway is Linux-only** — it loads eBPF (tc/BPF), creates a tun, and programs
nftables/routes; it does not compile or run on macOS. So macOS artifacts cover only the
portable components.

| Component            | Linux x86_64 | Linux arm64 | macOS x86_64 | macOS arm64 | Kind                    |
|----------------------|:---:|:---:|:---:|:---:|-------------------------|
| `wiremesh-controller`| ✅ | ✅ | ✅ | ✅ | server (systemd / launchd-less) |
| `wiremesh-gateway`   | ✅ | ✅ | ❌ | ❌ | **privileged data plane (Linux only)** |
| `wiremesh-relay` (+`mkcerts`) | ✅ | ✅ | ✅ | ✅ | server |
| `fabricctl`          | ✅ | ✅ | ✅ | ✅ | admin CLI (the primary mac target) |

- Standalone tarballs: every ✅ cell.
- deb/rpm + repo: the Linux columns (all 4, both arches).
- macOS `.pkg`: the macOS-✅ components (controller/relay/fabricctl) — bundled into ONE
  `wiremesh-<version>.pkg` (choosable payloads) or per-component; default = one `.pkg`
  installing `fabricctl` + optional controller/relay payloads. (fabricctl is the point.)

### Mac connectivity model (owner decision 2026-07-22 — ~~keep the segment model~~)

> **SUPERSEDED IN PART, 2026-08-05 (owner decision).** The paragraph below is kept for the
> record but **no longer states current scope.** A **single-host client peer** is now in
> scope (PRD Non-Goals item 1 amendment; engineering design §11.8), so "a Mac does not run
> WireMesh to join the mesh" and "no … per-device client in v1" are both reversed. What
> **stands unchanged** is the *reason it gives for the gateway*: macOS has no eBPF, so no
> macOS **gateway** — the client is a different component that needs no enforcer of its
> own (PRD G-4a), which is exactly why it does not reopen that question. The paragraph's
> guess at the shape was also close: a `utun` + userspace-WG data plane is roughly what
> phase 3 would build, though phases 1–2 need far less.

The macOS artifacts are **operator/admin tooling ONLY** (chiefly `fabricctl`; controller/
relay for local dev). They are **NOT a data-plane client** — a Mac does not run WireMesh
to join the mesh. Per WireMesh's core tenets ("one gateway per segment", "no agents on
workloads"), a Mac connects to the fabric **transparently as a workload behind its
segment's (Linux) gateway** — the gateway does all WireGuard + L4 enforcement; the device
runs nothing. There is deliberately **no macOS gateway / per-device client** in v1 (a
Tailscale-style roaming per-device client would be a separate new subsystem: a `utun` +
userspace-WG data plane with macOS-native L4 enforcement since macOS has no eBPF — out of
scope here). This is why the matrix leaves the gateway Linux-only and macOS packaging is
CLI/admin-scoped.

## 3. PREREQUISITES the owner must provision (gates the build)
The signing/notarization/repo pieces need secrets that only the owner can create. The
build cycle CANNOT complete these without them:
- **GPG signing key** (for the apt/yum repo + optionally the deb/rpm themselves):
  a dedicated ASCII-armored private key + passphrase → repo secrets
  `WIREMESH_GPG_PRIVATE_KEY`, `WIREMESH_GPG_PASSPHRASE`; publish the public key so
  users install it as a **keyring** — apt: drop it at
  `/usr/share/keyrings/wiremesh.gpg` and use `deb [signed-by=/usr/share/keyrings/wiremesh.gpg] …`
  (NOT the deprecated `apt-key`); rpm: `rpm --import`.
- **Apple Developer ID** (for the `.pkg`): a "Developer ID Installer" certificate (.p12)
  + password, an Apple Team ID, and notarization credentials (an App Store Connect API
  key: issuer id + key id + .p8) → secrets `APPLE_INSTALLER_CERT_P12`,
  `APPLE_CERT_PASSWORD`, `APPLE_TEAM_ID`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`,
  `APPLE_NOTARY_KEY_P8`. (Without an Apple Developer account this becomes an UNSIGNED
  `.pkg` or the Homebrew-tap fallback — flag to owner.)
- `contents: write` on the `release` job for Release assets (`packages: write`
  on GHCR is used by the separate container-images workflow).
- **(OPTIONAL, follow-up only)** hosting for a *self-hosted* signed apt/yum repo
  tree — WireMesh ships the `.deb`/`.rpm` as Release downloads and hosts no repo
  itself (project tenet). If an operator wants a repo, they host it themselves
  (their own Pages/object-store/web root) from these assets; that publish path +
  any hosting permissions are their concern, not the core pipeline's.

## 4. Tooling & build strategy
### 4.1 Multi-arch binaries
> **SUPERSEDED by §0 (2026-07-23):** the pipeline uses **native runners per arch**
> — no `cross`. Linux via the Dockerfile `export` stage on `ubuntu-latest` +
> `ubuntu-24.04-arm`; macOS builds both arches on `macos-14` (arm64 native +
> `x86_64-apple-darwin` cross via Apple's toolchain); Windows `fabricctl` on
> `windows-latest`. The arm64-gateway cross-compile risk below is moot. The rest
> of this subsection is retained for historical context only.
- **Linux x86_64 + arm64**: cross-compile from one x86_64 runner using
  `cross` (or `cargo-zigbuild`) for `aarch64-unknown-linux-gnu`. The eBPF object is
  arch-independent (`aya` emits `bpfel` bytecode regardless of host/target arch), so only
  the gateway *userspace* cross-compiles — reuse the `dev/Dockerfile` toolchain (nightly +
  bpf-linker) plus the aarch64 cross toolchain. Validate the arm64 gateway builds (aya +
  boringtun cross-compile) EARLY — this is the main build risk.
- **macOS x86_64 + arm64**: build natively on `macos-13` (x86_64) + `macos-14` (arm64)
  runners, or one arm64 runner + `--target x86_64-apple-darwin`; `lipo` into universal
  binaries for the `.pkg`. Only controller/relay/fabricctl (no gateway).
- Package each as `wiremesh-<component>-<version>-<target>.tar.gz` (+ a `SHA256SUMS`),
  attach to the Release.

### 4.2 Linux deb/rpm (nfpm) + hosted repo
- **nfpm** config per component × arch → `.deb` + `.rpm` from the prebuilt binaries
  (fed via a `scratch` `export` stage added to `deploy/docker/Dockerfile`, or the tarball
  binaries). Each service package ships: the binary in `/usr/bin`, a **systemd unit**
  (`deploy/packages/systemd/wiremesh-{controller,gateway,relay}.service`), an
  `/etc/wiremesh/<svc>.env` `EnvironmentFile` (holds the CLI flags), a `wiremesh` system
  user (servers non-root; **gateway runs as root**, its unit grants the privileged/network
  scope), `/var/lib/wiremesh` (0700, owned), and deps: gateway → `iproute2`, `nftables`,
  `conntrack`(deb)/`conntrack-tools`(rpm); others → none. Relay ships `mkcerts` as
  `wiremesh-mkcerts`.
- **Hosted repo** (GitHub Pages): a `repo` job GPG-signs and assembles both trees:
  - apt: `aptly` (or `reprepro`) → `dists/stable/{main}/binary-{amd64,arm64}` + signed
    `Release`/`InRelease`; users add `deb [signed-by=…] https://<pages>/apt stable main`.
  - yum: `createrepo_c` + `gpg --detach-sign repodata/repomd.xml` → `rpm/{x86_64,aarch64}`;
    users drop a `.repo` file pointing at `https://<pages>/rpm/$basearch` with `gpgkey=`.
  - Publish the tree to Pages; publish the public key + install instructions there too.

### 4.3 macOS `.pkg`
- `pkgbuild` (component pkg: universal binaries → `/usr/local/bin`) → `productbuild`
  (distribution `.pkg`), `codesign`/`--sign "Developer ID Installer: …"`, then
  `xcrun notarytool submit --wait` + `xcrun stapler staple`. Runs on a macOS runner.
  Import the cert into a temporary keychain from the `.p12` secret.

## 5. CI workflow (`.github/workflows/release.yml`, trigger: `push tags v*` + dispatch)
Jobs (fan-out, then publish):
1. `binaries-linux` (matrix amd64/arm64) → tarballs (artifacts).
2. `binaries-macos` (matrix x86_64/arm64) → tarballs + universal (artifacts).
3. `packages-linux` (needs binaries-linux) → nfpm `.deb`/`.rpm` (artifacts).
4. `pkg-macos` (needs binaries-macos) → signed+notarized `.pkg` (artifact).
5. `release` (needs 1-4) → attach all tarballs + `.deb`/`.rpm` + `.pkg` + `SHA256SUMS` to the GitHub Release.
6. `repo` (needs packages-linux) → build+sign the apt/yum trees, deploy to Pages.
Guard signing/notarization/Pages jobs on the presence of the secrets (skip-with-notice if absent, so a fork/dry-run still builds unsigned artifacts).

## 6. Task decomposition (for the build cycle)
1. `export` stage in `deploy/docker/Dockerfile` + Linux amd64/arm64 binary build (validate arm64 gateway cross-compile) → tarballs.
2. macOS binary build (x86_64+arm64, universal) → tarballs; components = controller/relay/fabricctl.
3. Release job: attach tarballs + `SHA256SUMS`.
4. nfpm configs + systemd units + `/etc/wiremesh` env files → unsigned `.deb`/`.rpm` (both arches), install/remove scriptlets, `wiremesh` user, deps.
5. GPG-signed apt repo (aptly) on Pages + public key + docs.
6. GPG-signed yum repo (createrepo_c) on Pages + `.repo` + docs.
7. macOS `.pkg`: pkgbuild/productbuild + codesign + notarize + staple.
8. Wire `release.yml` (fan-out + publish + repo), secret-guards, dispatch dry-run.
9. Docs: install instructions (tarball / apt / yum / pkg) in README + `docs/`.

## 7. Follow-ups / notes
- v1 could ship x86_64-only if the arm64 gateway cross-compile proves hard; arm64 is the
  main unknown — de-risk it first (a throwaway `cross build --target aarch64` of the gateway).
- Homebrew tap remains a cheap ADDITION later (formula pointing at the release tarballs).
- Windows: **now IN scope (§0, 2026-07-23)** — a Windows x86_64 `fabricctl` binary
  + a WiX `.msi`. controller/relay stay Unix-only; gateway stays Linux-only.
- Reproducible builds / SBOM (syft) + cosign image signing: a security follow-up.
