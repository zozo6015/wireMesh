# Installing WireMesh

WireMesh ships as **container images** (see `docs/operator.md` for Kubernetes) and,
via the `Release` workflow on every `v*` tag, as **standalone binaries, Linux
`.deb`/`.rpm` packages, a Windows `.msi` installer, and a macOS `.pkg`**.

> The **gateway is Linux-only** (it loads eBPF, creates a tun, programs
> nftables/routes). The **controller and relay are Unix servers** (Unix-domain
> admin socket + unix file-mode secret handling), so on **Windows only
> `fabricctl` (the admin CLI) ships**. macOS is Unix, so it gets all three
> portable components.

## Platform × component matrix

| Component | Linux (amd64/arm64) | macOS (x86_64/arm64) | Windows (x86_64) |
|-----------|:--:|:--:|:--:|
| `fabricctl` (admin CLI) | ✅ deb/rpm/tar | ✅ pkg/tar | ✅ msi/zip |
| `wiremesh-controller` | ✅ deb/rpm/tar | ✅ pkg/tar | ❌ Unix-only |
| `wiremesh-relay` (+`mkcerts`) | ✅ deb/rpm/tar | ✅ pkg/tar | ❌ Unix-only |
| `wiremesh-gateway` | ✅ deb/rpm/tar | ❌ | ❌ |

## Verify your download first

Every Release includes a `SHA256SUMS` file covering all artifacts (tarballs,
`.deb`, `.rpm`, `.msi`, `.pkg`). **Verify before installing** — this is your
integrity check while Authenticode/Apple/GPG signing is still being provisioned:

```sh
# Download SHA256SUMS + your artifact(s) into the same dir, then:
sha256sum -c SHA256SUMS --ignore-missing        # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing    # macOS
```

```powershell
# Windows (PowerShell): compare against the line in SHA256SUMS for your file
(Get-FileHash .\wiremesh-fabricctl-<version>-windows-x86_64.msi -Algorithm SHA256).Hash
```

Only install artifacts that verify.

## Linux — `.deb` / `.rpm`

Download the package for your component + arch from the [Release](https://github.com/zozo6015/wireMesh/releases),
verify it against `SHA256SUMS` (above), then:

```sh
# Debian/Ubuntu
sudo apt install ./wiremesh-gateway_<version>_arm64.deb
# RHEL/Fedora
sudo dnf install ./wiremesh-gateway-<version>.aarch64.rpm
```

Each service package installs the binary to `/usr/bin`, a **systemd unit**, and
config under `/etc/wiremesh/`. The gateway package pulls in `iproute2 nftables
conntrack procps`. After editing the config:

```sh
sudo systemctl enable --now wiremesh-controller     # or wiremesh-gateway / wiremesh-relay
```

**Gateway** — enroll once before first start (needs a token from the controller/operator):

```sh
sudo wiremesh-gateway enroll --token-file /etc/wiremesh/gateway.token \
  --controller <controller-host>:9400 --ca /etc/wiremesh/ca.pem \
  --state-dir /var/lib/wiremesh --cidr <this-segment-cidr>
sudo systemctl enable --now wiremesh-gateway
```

(WireMesh itself hosts no package repository — it ships the `.deb`/`.rpm` as
Release downloads. If you want `apt`/`dnf` to resolve `wiremesh-*` directly, you
can stand up your **own** GPG-signed apt/yum repo from these assets; a helper to
assemble a self-hosted repo tree is a tracked follow-up, gated on a signing key.)

## Standalone binaries (any Linux/macOS/Windows)

Download `wiremesh-<component>-<version>-<os>-<arch>.tar.gz` (or the Windows
`.zip`), verify against `SHA256SUMS`, and drop the binary on your `PATH`:

```sh
tar xzf wiremesh-fabricctl-<version>-linux-amd64.tar.gz
sudo install -m0755 fabricctl /usr/local/bin/
```

## Windows — `.msi`

**Verify the `.msi` against `SHA256SUMS` first** (see above). Then run
`wiremesh-fabricctl-<version>-windows-x86_64.msi`. It installs `fabricctl` into
`C:\Program Files\WireMesh` and adds that directory to the system `PATH`. On
Windows, `fabricctl` talks to the controller over **TCP** (`--addr <host:port>
--token <token>`); the Unix-domain-socket admin path is not available.

The installer is not yet Authenticode-signed, so SmartScreen will warn about an
unknown publisher — your SHA-256 check is what establishes integrity in the
meantime. Signed installers are a tracked follow-up.

## macOS — `.pkg`

**Verify the `.pkg` against `SHA256SUMS` first** (see above). Then open
`wiremesh-<version>-macos-universal*.pkg`; it installs the CLIs to
`/usr/local/bin`. Universal (x86_64 + arm64).

The `.pkg` is not yet signed/notarized, so Gatekeeper will warn — your SHA-256
check is what establishes integrity in the meantime. If you prefer to avoid the
Gatekeeper prompt entirely, use the verified `.tar.gz` instead. Signed +
notarized installers are a tracked follow-up.

## Versioning

Artifacts are versioned from the git tag: pushing `v1.2.3` stamps `1.2.3` into
every binary's `--version`, the package versions, and the artifact names.
