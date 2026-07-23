# Installing WireMesh

WireMesh ships as **container images** (see `docs/operator.md` for Kubernetes) and,
via the `Release` workflow on every `v*` tag, as **standalone binaries, Linux
`.deb`/`.rpm` packages, a Windows `.msi` installer, and a macOS `.pkg`**.

> The **gateway is Linux-only** (it loads eBPF, creates a tun, programs
> nftables/routes). macOS and Windows artifacts cover the portable components
> only: `fabricctl` (admin CLI), `wiremesh-controller`, `wiremesh-relay`.

## Platform × component matrix

| Component | Linux (amd64/arm64) | macOS (x86_64/arm64) | Windows (x86_64) |
|-----------|:--:|:--:|:--:|
| `fabricctl` (admin CLI) | ✅ deb/rpm/tar | ✅ pkg/tar | ✅ msi/zip |
| `wiremesh-controller` | ✅ deb/rpm/tar | ✅ pkg/tar | ✅ msi/zip |
| `wiremesh-relay` (+`mkcerts`) | ✅ deb/rpm/tar | ✅ pkg/tar | ✅ msi/zip |
| `wiremesh-gateway` | ✅ deb/rpm/tar | ❌ | ❌ |

## Linux — `.deb` / `.rpm`

Download the package for your component + arch from the [Release](https://github.com/zozo6015/wireMesh/releases), then:

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

(A GPG-signed hosted apt/yum repo — `apt install wiremesh-gateway` without a
manual download — is a tracked follow-up, gated on the owner's signing key.)

## Standalone binaries (any Linux/macOS/Windows)

Download `wiremesh-<component>-<version>-<os>-<arch>.tar.gz` (or the Windows
`.zip`), verify against `SHA256SUMS`, and drop the binary on your `PATH`:

```sh
tar xzf wiremesh-fabricctl-<version>-linux-amd64.tar.gz
sudo install -m0755 fabricctl /usr/local/bin/
```

## Windows — `.msi`

Run `wiremesh-<version>-windows-x86_64.msi`. It installs `fabricctl`,
`wiremesh-controller`, `wiremesh-relay`, `wiremesh-mkcerts` into
`C:\Program Files\WireMesh` and adds that directory to the system `PATH`.
(Unsigned until an Authenticode certificate is provisioned — SmartScreen will
warn; choose *More info → Run anyway*.)

## macOS — `.pkg`

Open `wiremesh-<version>-macos-universal*.pkg`; it installs the CLIs to
`/usr/local/bin`. Universal (x86_64 + arm64). Unsigned/un-notarized until an
Apple Developer ID is provisioned — right-click → *Open* to bypass Gatekeeper, or
use the tarball.

## Versioning

Artifacts are versioned from the git tag: pushing `v1.2.3` stamps `1.2.3` into
every binary's `--version`, the package versions, and the artifact names.
