//! The operator's admin transport — how a reconcile reaches the controller's
//! Admin API (`Apply`/`MintToken`/`RegisterRelay`/`Drain`/…).
//!
//! **Two transports, one surface.** The controller's Admin TCP listener binds
//! loopback-only (plaintext bearer), so a separate-pod operator can NOT dial it
//! in-cluster (spec §0 / `operator-admin-channel-gap.md`).
//!
//! - [`AdminExec::Grpc`] — a direct gRPC client to the Admin TCP port; usable
//!   only where that port is loopback-reachable (local runs + the integration
//!   tests against a `TestController`).
//! - [`AdminExec::Exec`] — the **production** transport: `kube exec` of
//!   `wiremesh-operator operator-admin <op>` in the controller pod's
//!   `admin-exec` sidecar, which talks to the controller's implicit-admin UDS
//!   (no bearer token). The sidecar's JSON stdout is parsed back here.
//!
//! Reconcilers depend on this enum, not on either transport, so swapping is a
//! config change (`WIREMESH_ADMIN_ADDR` opts into gRPC).

use crate::admin::FabricAdmin;
use anyhow::{anyhow, Context};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{AttachParams, ListParams};
use kube::{Api, Client};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A gateway roster row — the shape both transports return (the gRPC path maps
/// the proto `GatewayInfo`; the exec path parses the sidecar's JSON).
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayRow {
    pub id: u64,
    #[allow(dead_code)]
    pub name: String,
    pub segment: String,
    pub status: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub applied_version: u64,
}

pub enum AdminExec {
    /// Direct gRPC to `addr` (host:port) with a bearer `token`.
    Grpc { addr: String, token: String },
    /// Production: `kube exec` `operator-admin` in the controller pod.
    Exec {
        client: Client,
        namespace: String,
        /// Label selector identifying the controller pod.
        pod_label: String,
        /// The admin-exec sidecar container name.
        container: String,
        /// The controller UDS path inside the pod.
        uds: String,
    },
}

impl AdminExec {
    async fn grpc(&self) -> anyhow::Result<FabricAdmin> {
        match self {
            AdminExec::Grpc { addr, token } => FabricAdmin::connect(addr, token).await,
            AdminExec::Exec { .. } => unreachable!("grpc() on Exec transport"),
        }
    }

    /// Bound on a single admin exec so a stuck controller/socket can't wedge
    /// the reconcile loop forever.
    const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Run `operator-admin <op_args>` in the controller sidecar (exec transport)
    /// and parse its JSON stdout. `stdin` feeds the process (used by `apply`).
    async fn exec_json(
        &self,
        op_args: &[&str],
        stdin: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        tokio::time::timeout(Self::EXEC_TIMEOUT, self.exec_json_inner(op_args, stdin))
            .await
            .map_err(|_| anyhow!("operator-admin exec timed out after {:?}", Self::EXEC_TIMEOUT))?
    }

    async fn exec_json_inner(
        &self,
        op_args: &[&str],
        stdin: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        let (client, namespace, pod_label, container, uds) = match self {
            AdminExec::Exec { client, namespace, pod_label, container, uds } => {
                (client, namespace, pod_label, container, uds)
            }
            AdminExec::Grpc { .. } => unreachable!("exec_json() on Grpc transport"),
        };
        let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
        let running = pods
            .list(&ListParams::default().labels(pod_label))
            .await?
            .items
            .into_iter()
            .find(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"))
            .ok_or_else(|| anyhow!("no Running controller pod matching {pod_label}"))?;
        let pod_name = running.metadata.name.ok_or_else(|| anyhow!("controller pod has no name"))?;

        let mut cmd: Vec<String> = vec!["wiremesh-operator".into(), "operator-admin".into()];
        cmd.extend(op_args.iter().map(|s| s.to_string()));
        cmd.push("--socket".into());
        cmd.push(uds.clone());

        let ap = AttachParams::default()
            .container(container)
            .stdin(stdin.is_some())
            .stdout(true)
            .stderr(true);
        let mut proc = pods.exec(&pod_name, cmd, &ap).await?;

        if let Some(input) = stdin {
            let mut sin = proc.stdin().ok_or_else(|| anyhow!("exec stdin unavailable"))?;
            sin.write_all(input.as_bytes()).await?;
            sin.shutdown().await?;
        }
        let mut out = String::new();
        if let Some(mut so) = proc.stdout() {
            so.read_to_string(&mut out).await?;
        }
        let mut err = String::new();
        if let Some(mut se) = proc.stderr() {
            se.read_to_string(&mut err).await?;
        }
        proc.join().await.context("operator-admin exec failed")?;
        serde_json::from_str(out.trim())
            .with_context(|| format!("parsing operator-admin JSON (stdout={out:?} stderr={err:?})"))
    }

    fn is_grpc(&self) -> bool {
        matches!(self, AdminExec::Grpc { .. })
    }

    /// Apply a fabric (segments + policy) in one transaction.
    pub async fn apply(&self, fabric_yaml: &str) -> anyhow::Result<()> {
        if self.is_grpc() {
            self.grpc().await?.apply(fabric_yaml).await?;
        } else {
            self.exec_json(&["apply"], Some(fabric_yaml)).await?;
        }
        Ok(())
    }

    /// Mint a single-use gateway enrollment token bound to `cidrs`.
    pub async fn mint_gateway_token(&self, cidrs: &[String]) -> anyhow::Result<String> {
        if self.is_grpc() {
            return self.grpc().await?.mint_gateway_token(cidrs).await;
        }
        let mut args = vec!["mint-token", "--kind", "gateway"];
        for c in cidrs {
            args.push("--cidr");
            args.push(c);
        }
        token_of(self.exec_json(&args, None).await?)
    }

    /// Mint a single-use relay enrollment token.
    pub async fn mint_relay_token(&self) -> anyhow::Result<String> {
        if self.is_grpc() {
            return self.grpc().await?.mint_relay_token().await;
        }
        token_of(self.exec_json(&["mint-token", "--kind", "relay"], None).await?)
    }

    /// Register a relay; returns its id. (Not used by the reconcilers, which
    /// mint a relay token and let the pod self-enroll; kept for completeness.)
    pub async fn register_relay(&self, name: &str, endpoint: &str) -> anyhow::Result<u64> {
        if self.is_grpc() {
            return self.grpc().await?.register_relay(name, endpoint).await;
        }
        let v = self
            .exec_json(&["register-relay", "--name", name, "--endpoint", endpoint], None)
            .await?;
        v.get("id").and_then(|x| x.as_u64()).ok_or_else(|| anyhow!("register-relay: no id in {v}"))
    }

    /// Delete a segment by name (driven by the Segment finalizer).
    pub async fn delete_segment_by_name(&self, name: &str) -> anyhow::Result<()> {
        if self.is_grpc() {
            return self.grpc().await?.delete_segment_by_name(name).await;
        }
        self.exec_json(&["delete-segment", "--name", name], None).await?;
        Ok(())
    }

    /// The controller's gateway roster.
    pub async fn list_gateways(&self) -> anyhow::Result<Vec<GatewayRow>> {
        if self.is_grpc() {
            let rows = self.grpc().await?.list_gateways().await?;
            return Ok(rows
                .into_iter()
                .map(|g| GatewayRow {
                    id: g.id,
                    name: g.name,
                    segment: g.segment,
                    status: g.status,
                    applied_version: g.applied_version,
                })
                .collect());
        }
        let v = self.exec_json(&["list-gateways"], None).await?;
        Ok(serde_json::from_value(v).context("parsing gateway roster")?)
    }

    /// Drain a gateway by id (driven by the Gateway finalizer).
    pub async fn drain(&self, gateway_id: u64) -> anyhow::Result<()> {
        if self.is_grpc() {
            return self.grpc().await?.drain(gateway_id).await;
        }
        let id = gateway_id.to_string();
        self.exec_json(&["drain", "--id", &id], None).await?;
        Ok(())
    }
}

fn token_of(v: serde_json::Value) -> anyhow::Result<String> {
    v.get("token")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("mint-token: no token in {v}"))
}
