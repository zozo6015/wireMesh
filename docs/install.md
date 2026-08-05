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

**On a fresh install the controller's data dir is
`/var/lib/wiremesh-controller`** (`WIREMESH_DATA_DIR` in
`/etc/wiremesh/controller.env`), holding the fabric CA (`ca.pem`/`ca.key`), the
SQLite DB (`controller.db`) and `secrets/`. Like the relay, it gets its own dir
rather than sharing the gateway's `/var/lib/wiremesh` — the controller runs as
the `wiremesh` user, the gateway's identity there is root-owned 0700, and
whichever of the two claims the directory locks the other out. The unit's
`StateDirectory=wiremesh-controller` creates it owned `wiremesh:wiremesh` mode
0700 at first start; nothing needs to pre-create it. **Back this directory up:**
losing `ca.key` means re-enrolling every gateway.

### Automatic key rotation (`WIREMESH_ROTATION_INTERVAL`)

The controller rotates every gateway's WireGuard key on a timer — **every 30
days by default**. Set `WIREMESH_ROTATION_INTERVAL` in
`/etc/wiremesh/controller.env` to change or disable it; it takes effect on
controller restart.

```sh
WIREMESH_ROTATION_INTERVAL=30d    # <integer><s|m|h|d>, lowercase unit
WIREMESH_ROTATION_INTERVAL=off    # disable the automatic schedule
```

A malformed value (`30dd`, `30D`, `0d`) is a **startup error** — the controller
refuses to boot rather than quietly falling back to the 30-day default and
leaving you believing you changed something. Uppercase units are rejected on
purpose (`M` reads as "months" to too many people); a zero interval is rejected
because it would rotate in a hot loop — if you meant "never", write `off`. So is
anything longer than `3650d` (10 years): a timer that never fires is "never"
without the boot banner below that tells you so — again, write `off`.

`off` disables the automatic **schedule** only. It does not disable rotation as
a capability:

- a rotation already in flight when you switch it off still completes — the
  controller's decision sweep keeps running, including its recovery of a
  rotation orphaned by a crash;
- **manual rotation still works.** `fabricctl` / the Admin `RotateKey` RPC
  rotates a chosen gateway on demand — use it if you believe a key is
  compromised;
- keys already in use keep working; nothing expires on its own.

While it is off, no key is rotated on a schedule for as long as the controller
runs, and the controller prints a loud `AUTOMATIC KEY ROTATION IS OFF` warning
at every boot (visible in `journalctl -u wiremesh-controller`). Treat that
banner as a standing to-do, not background noise.

### Upgrading from a release that used `/var/lib/wiremesh`

**Your state stays exactly where it is.** If the package finds control-plane
state in `/var/lib/wiremesh`, it pins `WIREMESH_DATA_DIR` back to that path and
moves nothing. Upgrades never relocate a live controller's CA or database —
that is a deliberate design decision, not an omission (see the runbook
`docs/runbooks/controller-migration-to-fi.md`, field note 3). Read the install
output; it says which directory it settled on.

Pinning edits `/etc/wiremesh/controller.env`, which both package managers then
regard as locally modified. Two consequences to expect on later upgrades:

- **deb** will prompt (`Configuration file '/etc/wiremesh/controller.env' …
  Modified (by you or by a script) since installation`) whenever a release
  changes that file. Keeping your version is the safe answer; diff it if you
  want new settings.
- **rpm** will *not* prompt. It writes `/etc/wiremesh/controller.env.rpmnew` and
  leaves yours alone — so newly shipped settings **silently stop arriving**.
  **Check for `*.rpmnew` in `/etc/wiremesh/` after every upgrade** and merge by
  hand.

One thing the package cannot do for you: if an earlier controller release
already chowned `/var/lib/wiremesh` to `wiremesh` on a host that also runs a
**gateway**, that gateway is still locked out of its own `identity.json` and
crash-loops. It needs the directory back:

```sh
# STOP: run this ONLY if no controller or relay state remains in
# /var/lib/wiremesh. `ls /var/lib/wiremesh` must show NO ca.key and NO
# relay.pem. If either is there, do the migration procedure below FIRST —
# this chown locks the `wiremesh` user out of that directory, and a
# controller that can no longer read its own CA refuses to start.
sudo ls /var/lib/wiremesh
sudo chown root:root /var/lib/wiremesh   # NOT -R — deliberate, see below
sudo systemctl restart wiremesh-gateway
```

**Do not add `-R`.** The bug being undone was itself non-recursive (`chown
wiremesh:wiremesh /var/lib/wiremesh`, no `-R`), so only the directory's own
ownership ever changed and the gateway's files inside were never touched — the
gateway was locked out of *traversing* the directory, not out of the files, and
restoring the directory alone is the exact inverse. A recursive chown would go
further than the bug did and rewrite files that are `wiremesh`-owned for good
reasons — a legacy relay's `relay.key`, or a pinned controller's
`ca.key`/`controller.db`/`secrets/` — breaking those to fix the gateway.

The postinstall detects this and prints the command but will not run it, because
a co-located controller (now pinned there) or a legacy relay needs that same
directory readable by the `wiremesh` user. No single ownership serves all three
— give the gateway a directory to itself first, using the procedure below.

### Moving the controller to its own directory (optional, manual)

Only needed if a controller and a gateway share `/var/lib/wiremesh` and you want
them separated. Do it with the controller **stopped** — this is precisely the
work an unattended package script must not attempt.

First check you are not on a host with a frozen unit:

```sh
systemctl cat wiremesh-controller | head -1
```

If that shows `/etc/systemd/system/wiremesh-controller.service` (someone ran
`systemctl edit --full`), **stop here**. That frozen copy predates this layout:
it has no `StateDirectory=wiremesh-controller`, so `ProtectSystem=strict` will
make the new directory read-only and the controller will crash-loop on opening
its database. Run `sudo systemctl revert wiremesh-controller` to go back to the
packaged unit, or add `StateDirectory=wiremesh-controller` and
`ReadWritePaths=/var/lib/wiremesh-controller` to your override first.

Every command below uses absolute paths on purpose — do **not** `cd` into
`/var/lib/wiremesh` first. It is mode 0700, so an unprivileged `cd` fails while
the `sudo` commands after it would still run, quietly relocating the wrong
files (or none) and then repointing the config anyway.

```sh
# 0. Stop FIRST, then back up: the tarball below copies a SQLite database, and
#    a copy taken from under a running controller can be torn.
sudo systemctl stop wiremesh-controller

# 1. Back up the crown jewels. Keep the tarball root-only — it contains ca.key,
#    and root's umask would otherwise make it world-readable.
sudo install -d -m 0700 /root/wiremesh-backup
sudo tar -C /var/lib/wiremesh -czf /root/wiremesh-backup/state.tar.gz .
sudo chmod 0600 /root/wiremesh-backup/state.tar.gz

# 2. Record the CA fingerprint NOW; step 6 has to compare against it.
sudo openssl x509 -in /var/lib/wiremesh/ca.pem -noout -fingerprint -sha256

sudo install -d -o wiremesh -g wiremesh -m 0700 /var/lib/wiremesh-controller

# 3. Move only the controller's own entries. Leave the gateway's identity.json,
#    wg_private.key, state.json and epoch_keys.json exactly where they are.
#    `secrets/` does not exist on every install — if mv reports it missing,
#    that is harmless, the controller recreates it. If instead mv reports
#    "Directory not empty", a previous boot already created a secrets/ in the
#    new dir: merge it by hand (`sudo cp -a /var/lib/wiremesh/secrets/. \
#    /var/lib/wiremesh-controller/secrets/`) rather than forcing the move.
#
#    controller.db is moved WITH ITS SIDECARS. A cleanly stopped controller
#    leaves controller.db alone, but one that crashed or was SIGKILLed leaves a
#    hot journal next to it (controller.db-journal, or -wal/-shm if the journal
#    mode was ever changed). Those are part of the database, not scratch files:
#    move the .db without them and SQLite opens a file whose last transaction
#    can neither be completed nor rolled back. The glob is a no-op when the
#    shutdown was clean — which is the normal case here, since step 0 stopped
#    the service, but "something already went wrong" is exactly why people run
#    this procedure.
sudo sh -c 'mv /var/lib/wiremesh/controller.db* /var/lib/wiremesh-controller/'
sudo mv /var/lib/wiremesh/ca.key        /var/lib/wiremesh-controller/
sudo mv /var/lib/wiremesh/secrets       /var/lib/wiremesh-controller/

# 4. ca.pem is COPIED, not moved: a legacy relay identity in this directory is
#    ca.pem + relay.pem + relay.key, and removing it would break that relay.
sudo cp -p /var/lib/wiremesh/ca.pem /var/lib/wiremesh-controller/

sudo chown -R wiremesh:wiremesh /var/lib/wiremesh-controller

# If /etc/wiremesh/controller.env is a symlink into a config-management tree,
# edit the target instead — `sed -i` replaces the symlink with a regular file.
# The leading [[:space:]]* matters: an indented assignment is still live to
# systemd, and a pattern anchored straight at WIREMESH_ would skip it.
sudo sed -i -E 's#^([[:space:]]*)WIREMESH_DATA_DIR=.*#\1WIREMESH_DATA_DIR=/var/lib/wiremesh-controller#' \
  /etc/wiremesh/controller.env
grep -n WIREMESH_DATA_DIR /etc/wiremesh/controller.env   # confirm it took
sudo systemctl start wiremesh-controller

# 5. Confirm it is actually UP. `systemctl start` on a Type=simple unit returns
#    0 even if the process dies a moment later, so check, and read the log on
#    any doubt — a CA-guard refusal is printed there.
systemctl is-active wiremesh-controller
sudo journalctl -u wiremesh-controller -n 20 --no-pager

# 6. The fingerprint MUST equal the one recorded in step 2. (cp -p guarantees
#    the FILE matches; what this really confirms is that the controller came
#    up on the moved state rather than minting a replacement CA — so read it
#    together with step 5, not instead of it.)
sudo openssl x509 -in /var/lib/wiremesh-controller/ca.pem -noout -fingerprint -sha256
```

With the controller's state out of the way, you can finally give the shared
directory back to the gateway — the step the earlier bad `chown` made necessary
(skip the `chown` if a **relay** identity is still in there; migrate it to
`/var/lib/wiremesh-relay` first):

```sh
sudo chown root:root /var/lib/wiremesh
sudo systemctl restart wiremesh-gateway
```

If the controller ever starts against a data dir with no CA in it while one
still exists at `/var/lib/wiremesh`, it **refuses to start** rather than
generating a fresh CA (which would invalidate every enrolled gateway and relay).
The error names both directories and tells you how to resolve it.

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
