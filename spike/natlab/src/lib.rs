use anyhow::{bail, Context, Result};
use std::process::{Child, Command, Output, Stdio};

pub struct Lab { prefix: String, namespaces: Vec<String> }

#[derive(Clone)]
pub struct Ns { pub name: String, mountns: String }

fn run(cmd: &[&str]) -> Result<Output> {
    let out = Command::new(cmd[0]).args(&cmd[1..]).output()
        .with_context(|| format!("spawn {:?}", cmd))?;
    if !out.status.success() {
        bail!("{:?} failed: {}", cmd, String::from_utf8_lossy(&out.stderr));
    }
    Ok(out)
}

/// Directory holding one persistent mount-namespace reference file per `Ns`
/// (created via `unshare --mount=<file>`). `ip netns exec` only isolates the
/// *network* namespace — it does not give each namespace a private `/run`.
/// Filesystem-scoped daemons that key state off a fixed path under `/run`
/// (e.g. boringtun's WireGuard UAPI socket at `/var/run/wireguard/<ifname>.sock`,
/// see spike/tunnel's API-friction notes) would otherwise collide across
/// namespaces that use the same name. Giving each `Ns` its own persistent
/// mount namespace with a private `tmpfs` at `/var/run/wireguard` avoids that,
/// and mirrors how real gateway deployments are isolated (separate host/pod
/// per gateway, not just a separate network namespace).
const MOUNTNS_DIR: &str = "/run/natlab-mountns";

fn mountns_path(full_name: &str) -> String {
    format!("{MOUNTNS_DIR}/{full_name}")
}

impl Lab {
    pub fn new(prefix: &str) -> Result<Self> {
        Ok(Self { prefix: prefix.into(), namespaces: vec![] })
    }

    pub fn ns(&mut self, name: &str) -> Result<Ns> {
        let full = format!("{}-{}", self.prefix, name);
        run(&["ip", "netns", "add", &full])?;
        // Track immediately so Drop cleans up even if later steps fail.
        self.namespaces.push(full.clone());
        run(&["ip", "netns", "exec", &full, "ip", "link", "set", "lo", "up"])?;

        std::fs::create_dir_all(MOUNTNS_DIR).context("create natlab mountns dir")?;
        let mountns = mountns_path(&full);
        std::fs::File::create(&mountns).context("create mountns pin file")?;
        run(&[
            "unshare",
            &format!("--mount={mountns}"),
            "--",
            "bash",
            "-c",
            // --make-rprivate first: isolation must hold by construction, not
            // depend on the container's ambient mount-propagation default for
            // /run (if that were ever `shared`, the tmpfs would propagate to
            // sibling namespaces and silently reintroduce the wg0.sock
            // collision disguised as isolation).
            "mount --make-rprivate / && mkdir -p /var/run/wireguard && mount -t tmpfs tmpfs /var/run/wireguard",
        ])?;

        Ok(Ns { name: full, mountns })
    }

    pub fn veth(&mut self, a: (&Ns, &str, &str), b: (&Ns, &str, &str)) -> Result<()> {
        let (na, ia, addra) = a;
        let (nb, ib, addrb) = b;
        // unique temp names to avoid collisions across parallel labs
        let ta = format!("{}0", &self.prefix);
        let tb = format!("{}1", &self.prefix);
        run(&["ip", "link", "add", &ta, "type", "veth", "peer", "name", &tb])?;
        let setup = (|| -> Result<()> {
            run(&["ip", "link", "set", &ta, "netns", &na.name, "name", ia])?;
            run(&["ip", "link", "set", &tb, "netns", &nb.name, "name", ib])?;
            na.exec(&["ip", "addr", "add", addra, "dev", ia])?;
            nb.exec(&["ip", "addr", "add", addrb, "dev", ib])?;
            na.exec(&["ip", "link", "set", ia, "up"])?;
            nb.exec(&["ip", "link", "set", ib, "up"])?;
            Ok(())
        })();
        if let Err(e) = setup {
            // Best-effort reap of any end left in the root ns; deleting either
            // remaining end of a veth pair removes both. Exit status ignored.
            let deleted_ta = Command::new("ip")
                .args(["link", "del", &ta])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !deleted_ta {
                let _ = Command::new("ip").args(["link", "del", &tb]).status();
            }
            return Err(e);
        }
        Ok(())
    }
}

/// Which NAT mapping behavior a router cell exhibits, per the classic
/// STUN/RFC 4787 taxonomy. `PortRestricted` (endpoint-independent mapping,
/// port-restricted filtering) is what plain `masquerade` gives you; a real
/// symmetric NAT (endpoint-dependent mapping) requires per-destination port
/// randomization, which nftables approximates with `masquerade fully-random`.
#[derive(Clone, Copy)]
pub enum NatKind {
    PortRestricted,
    Symmetric,
}

impl Lab {
    /// Creates a router `Ns` with IPv4 forwarding enabled and an nftables
    /// masquerade rule installed on egress. Convention: callers wire the
    /// router's outside (public-facing) interface as `out0` and its inside
    /// (private-facing) interface as `in0` via `Lab::veth`.
    pub fn nat_router(&mut self, name: &str, kind: NatKind) -> Result<Ns> {
        let ns = self.ns(name)?;
        ns.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
        let flags = match kind {
            NatKind::PortRestricted => "",
            NatKind::Symmetric => " fully-random",
        };
        // nft's block syntax needs a newline (or semicolon) between the
        // `type nat hook ...` chain header and the rule that follows it, and
        // will not accept a bare `;}}` — closing braces must be preceded by
        // a statement terminator on their own line. A fully inline one-liner
        // (`{ ... ; } }`) fails with "syntax error, unexpected '}'".
        let ruleset = format!(
            "table ip nat {{\n  chain post {{\n    type nat hook postrouting priority 100;\n    oifname \"out0\" masquerade{flags};\n  }}\n}}\n"
        );
        let ruleset_path = format!("/tmp/{}.nft", ns.name);
        std::fs::write(&ruleset_path, &ruleset)
            .with_context(|| format!("write nft ruleset {ruleset_path}"))?;
        ns.exec(&["nft", "-f", &ruleset_path])?;
        Ok(ns)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for ns in &self.namespaces {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
            let mountns = mountns_path(ns);
            let _ = Command::new("umount").arg(&mountns).status();
            let _ = std::fs::remove_file(&mountns);
        }
    }
}

impl Ns {
    /// `nsenter --mount=<pin>` enters this Ns's private, persistent mount
    /// namespace *before* handing off to `ip netns exec`, so the private
    /// `/var/run/wireguard` tmpfs (set up in `Lab::ns`) is part of the mount
    /// table `ip netns exec`'s own internal unshare(CLONE_NEWNS) copies —
    /// see the MOUNTNS_DIR doc comment above.
    pub fn exec(&self, cmd: &[&str]) -> Result<Output> {
        let mount_arg = format!("--mount={}", self.mountns);
        let mut full = vec!["nsenter", &mount_arg, "--", "ip", "netns", "exec", &self.name];
        full.extend_from_slice(cmd);
        run(&full)
    }
    pub fn spawn(&self, cmd: &[&str]) -> Result<Child> {
        Command::new("nsenter")
            .arg(format!("--mount={}", self.mountns))
            .args(["--", "ip", "netns", "exec", &self.name])
            .args(cmd)
            .stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().context("spawn in netns")
    }
}
