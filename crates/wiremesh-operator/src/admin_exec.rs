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
use kube::api::ListParams;
use kube::{Api, Client};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

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

/// The exec-transport argv for a REBIND mint (past `operator-admin`; the
/// `--socket` flag is appended by the exec caller) — the exec-side twin of
/// [`crate::admin::rebind_mint_request`], which `operator_admin.rs` forwards
/// verbatim into `MintTokenRequest`. Keeps ONE definition of the encoding per
/// transport: `--kind rebind` (never `gateway`), the segment id, and NO
/// `--cidr` (a rebind token carries no CIDR binding).
pub fn rebind_mint_args(rebind_segment_id: u64) -> Vec<String> {
    vec![
        "mint-token".to_string(),
        "--kind".to_string(),
        crate::admin::REBIND_TOKEN_KIND.to_string(),
        "--rebind-segment-id".to_string(),
        rebind_segment_id.to_string(),
    ]
}

/// A relay roster row — the shape both transports return (the gRPC path maps
/// the proto `Relay`; the exec path parses the sidecar's JSON).
#[derive(Debug, Clone, Deserialize)]
pub struct RelayRow {
    #[allow(dead_code)]
    pub id: u64,
    #[allow(dead_code)]
    pub name: String,
    /// The relay's advertised `ip:port` — the ONLY field the operator can match
    /// a `WiremeshRelay` CR against: the controller names an enrolled relay
    /// `relay-<token-hash>` (`services/enrollment.rs`), never the CR's name,
    /// whereas the endpoint is the CR's `spec.endpoint` verbatim.
    pub endpoint: String,
    #[allow(dead_code)]
    pub status: String,
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
        // Resolve the controller pod by label (regular API — works fine).
        let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
        let running = pods
            .list(&ListParams::default().labels(pod_label))
            .await?
            .items
            .into_iter()
            .find(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"))
            .ok_or_else(|| anyhow!("no Running controller pod matching {pod_label}"))?;
        let pod_name = running.metadata.name.ok_or_else(|| anyhow!("controller pod has no name"))?;

        // Exec via the bundled `kubectl` rather than kube-rs's WebSocket exec:
        // kube-rs 0.95's WS upgrade fails auth against real API servers (403),
        // whereas kubectl carries the ServiceAccount token correctly and falls
        // back to SPDY. kubectl uses the pod's in-cluster config automatically
        // (KUBERNETES_SERVICE_HOST + the mounted SA token). `--cache-dir=/tmp`
        // keeps it happy under readOnlyRootFilesystem.
        let mut kc = tokio::process::Command::new("kubectl");
        // kill_on_drop: if the EXEC_TIMEOUT fires, exec_json's future (and this
        // Child) is dropped — kill the kubectl process rather than orphan it.
        kc.kill_on_drop(true)
            .arg("--cache-dir=/tmp/.kube-cache")
            .arg("-n").arg(namespace)
            .arg("exec").arg(&pod_name)
            .arg("-c").arg(container);
        if stdin.is_some() {
            kc.arg("-i");
        }
        kc.arg("--")
            .arg("wiremesh-operator").arg("operator-admin")
            .args(op_args)
            .arg("--socket").arg(uds);
        kc.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = kc.spawn().context("spawning kubectl exec")?;
        if let Some(input) = stdin {
            let mut sin = child.stdin.take().ok_or_else(|| anyhow!("kubectl stdin unavailable"))?;
            sin.write_all(input.as_bytes()).await?;
            sin.shutdown().await?; // EOF so operator-admin's stdin read completes
        } else {
            // Close stdin immediately for non-stdin ops.
            drop(child.stdin.take());
        }
        let output = child.wait_with_output().await.context("kubectl exec failed")?;
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            return Err(anyhow!("kubectl exec exited {:?}: stderr={err:?}", output.status.code()));
        }
        serde_json::from_str(out.trim())
            .with_context(|| format!("parsing operator-admin JSON (stdout={out:?} stderr={err:?})"))
    }

    /// Whether this is the direct-gRPC transport (`WIREMESH_ADMIN_ADDR` set).
    /// Public because a caller may need to know the admin API is reachable
    /// WITHOUT an in-cluster controller pod — see
    /// `controllers::controller_cleanup_skip`.
    pub fn is_grpc(&self) -> bool {
        matches!(self, AdminExec::Grpc { .. })
    }

    /// The label selector this transport resolves the controller pod with
    /// (honoring `WIREMESH_CONTROLLER_LABEL`), or `None` on the gRPC transport,
    /// which needs no pod. Callers that probe for the controller pod must use
    /// THIS selector rather than re-deriving the default, or they can conclude
    /// "controller gone" while the admin channel is healthy.
    pub fn pod_label(&self) -> Option<&str> {
        match self {
            AdminExec::Exec { pod_label, .. } => Some(pod_label),
            AdminExec::Grpc { .. } => None,
        }
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

    /// Mint a single-use REBIND token scoped to `rebind_segment_id` (non-zero).
    /// At redemption the controller replaces the segment's active gateway
    /// instead of rejecting the enroll with `SegmentAlreadyBound`.
    ///
    /// Wire encoding: [`rebind_mint_args`] / [`crate::admin::rebind_mint_request`]
    /// — `kind = "rebind"` + EMPTY `bound_cidrs` + the segment id. The
    /// controller keys rebind off the KIND alone and only reads
    /// `rebind_segment_id` in that arm.
    pub async fn mint_gateway_rebind_token(
        &self,
        rebind_segment_id: u64,
    ) -> anyhow::Result<String> {
        if self.is_grpc() {
            return self.grpc().await?.mint_gateway_rebind_token(rebind_segment_id).await;
        }
        anyhow::ensure!(
            rebind_segment_id != 0,
            "a rebind token needs a non-zero segment id (0 means 'no rebind' on the wire)"
        );
        let owned = rebind_mint_args(rebind_segment_id);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        token_of(self.exec_json(&args, None).await?)
    }

    /// Resolve a segment's controller-side id by name (`None` if unregistered).
    pub async fn segment_id_by_name(&self, name: &str) -> anyhow::Result<Option<u64>> {
        if self.is_grpc() {
            return self.grpc().await?.segment_id_by_name(name).await;
        }
        let v = self.exec_json(&["segment-id", "--name", name], None).await?;
        match v.get("id") {
            Some(serde_json::Value::Null) | None => Ok(None),
            Some(id) => id
                .as_u64()
                .map(Some)
                .ok_or_else(|| anyhow!("segment-id: non-numeric id in {v}")),
        }
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

    /// The controller's relay roster.
    pub async fn list_relays(&self) -> anyhow::Result<Vec<RelayRow>> {
        if self.is_grpc() {
            let rows = self.grpc().await?.list_relays().await?;
            return Ok(rows
                .into_iter()
                .map(|r| RelayRow {
                    id: r.id,
                    name: r.name,
                    endpoint: r.endpoint,
                    status: r.status,
                })
                .collect());
        }
        let v = self.exec_json(&["list-relays"], None).await?;
        Ok(serde_json::from_value(v).context("parsing relay roster")?)
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
