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
# The controller has no enrollment step — start it directly:
sudo systemctl enable --now wiremesh-controller
```

**The controller's data dir is `/var/lib/wiremesh-controller`** (`WIREMESH_DATA_DIR`
in `/etc/wiremesh/controller.env`), holding the fabric CA (`ca.pem`/`ca.key`),
the SQLite DB (`controller.db`) and `secrets/`. Like the relay, it gets its own
dir rather than sharing the gateway's `/var/lib/wiremesh` — the controller runs
as the `wiremesh` user, the gateway's identity there is root-owned 0700, and
whichever of the two claims the directory locks the other out. The unit's
`StateDirectory=wiremesh-controller` creates it owned `wiremesh:wiremesh` mode
0700 at first start; nothing needs to pre-create it. **Back this directory up:**
losing `ca.key` means re-enrolling every gateway.

Upgrading from a release that defaulted to `/var/lib/wiremesh`? The package
copies the controller's own files across (and only those — a co-located
gateway's or relay's files stay put), verifies them, repoints
`WIREMESH_DATA_DIR`, and only then removes the originals. It prints what it did
or why it declined, so **read the install output**. Two follow-ups it cannot do
for you:

- If an earlier controller package already chowned `/var/lib/wiremesh` to
  `wiremesh` on a host that also runs a **gateway**, the gateway is still locked
  out of its own `identity.json` and crash-loops. Give the directory back:
  `sudo chown root:root /var/lib/wiremesh && sudo systemctl restart wiremesh-gateway`.
  (The postinstall detects and prints this; it does not run it, because a
  co-located *legacy relay* needs that directory `wiremesh`-owned instead —
  migrate the relay to `/var/lib/wiremesh-relay` first if both apply.)
- Restart the controller (`sudo systemctl restart wiremesh-controller`) so it
  picks up the new path.

The **gateway** and **relay** must be **enrolled once before first start** (each
needs a token minted by the controller/operator). Replace the UPPERCASE
placeholders with your values (they are written this way so the commands are
safe to copy-paste — angle-bracket placeholders would be shell redirections):

```sh
# Gateway:
sudo wiremesh-gateway enroll --token-file /etc/wiremesh/gateway.token \
  --controller CONTROLLER_HOST:9400 --ca /etc/wiremesh/ca.pem \
  --state-dir /var/lib/wiremesh --cidr SEGMENT_CIDR
sudo systemctl enable --now wiremesh-gateway

# Relay:
sudo wiremesh-relay-enroll --token-file /etc/wiremesh/relay.token \
  --controller CONTROLLER_HOST:9400 --ca /etc/wiremesh/ca.pem \
  --certdir /var/lib/wiremesh-relay --endpoint PUBLIC_IP:4443
sudo systemctl enable --now wiremesh-relay
```

**The relay's cert dir is `/var/lib/wiremesh-relay` — its own dedicated state
dir, never `/var/lib/wiremesh`.** A relay and a gateway can share a host, but
they must not share a state dir: `/var/lib/wiremesh` is the gateway's
root-only (0700 root) directory, while the relay service runs as the
`wiremesh` user — an identity enrolled into the gateway's dir is unreadable
by the relay, which then crash-loops on "Permission denied". The package and
the unit (`StateDirectory=wiremesh-relay`) create `/var/lib/wiremesh-relay`
owned `wiremesh:wiremesh` mode 0700, and `wiremesh-relay-enroll` (run under
`sudo` as documented) chowns the identity it writes to the `wiremesh` service
user automatically — if it can't (it tells you), run
`chown -R wiremesh:wiremesh /var/lib/wiremesh-relay` yourself. The three
identity files (`ca.pem`, `relay.pem`, `relay.key`) must EACH be mode 0600
individually (the enroll tool writes them that way; keep them so — a
directory-level 0700 alone is not sufficient).

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
`wiremesh-<version>-macos-universal-unsigned.pkg`; it installs the CLIs to
`/usr/local/bin`. Universal (x86_64 + arm64). (The `-unsigned` suffix drops once
Apple signing/notarization is provisioned.)

The `.pkg` is not yet signed/notarized, so Gatekeeper will warn — your SHA-256
check is what establishes integrity in the meantime. If you prefer to avoid the
Gatekeeper prompt entirely, use the verified `.tar.gz` instead. Signed +
notarized installers are a tracked follow-up.

## Versioning

Artifacts are versioned from the git tag: pushing `v1.2.3` stamps `1.2.3` into
every binary's `--version`, the package versions, and the artifact names.
