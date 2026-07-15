use anyhow::{bail, Context, Result};
use std::process::{Child, Command, Output, Stdio};

pub struct Lab { prefix: String, namespaces: Vec<String> }

#[derive(Clone)]
pub struct Ns { pub name: String }

fn run(cmd: &[&str]) -> Result<Output> {
    let out = Command::new(cmd[0]).args(&cmd[1..]).output()
        .with_context(|| format!("spawn {:?}", cmd))?;
    if !out.status.success() {
        bail!("{:?} failed: {}", cmd, String::from_utf8_lossy(&out.stderr));
    }
    Ok(out)
}

impl Lab {
    pub fn new(prefix: &str) -> Result<Self> {
        Ok(Self { prefix: prefix.into(), namespaces: vec![] })
    }

    pub fn ns(&mut self, name: &str) -> Result<Ns> {
        let full = format!("{}-{}", self.prefix, name);
        run(&["ip", "netns", "add", &full])?;
        // Track immediately so Drop cleans up even if lo-up fails below.
        self.namespaces.push(full.clone());
        run(&["ip", "netns", "exec", &full, "ip", "link", "set", "lo", "up"])?;
        Ok(Ns { name: full })
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

impl Drop for Lab {
    fn drop(&mut self) {
        for ns in &self.namespaces {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
        }
    }
}

impl Ns {
    pub fn exec(&self, cmd: &[&str]) -> Result<Output> {
        let mut full = vec!["ip", "netns", "exec", &self.name];
        full.extend_from_slice(cmd);
        run(&full)
    }
    pub fn spawn(&self, cmd: &[&str]) -> Result<Child> {
        Command::new("ip")
            .args(["netns", "exec", &self.name])
            .args(cmd)
            .stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().context("spawn in netns")
    }
}
