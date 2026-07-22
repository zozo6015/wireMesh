//! The operator's admin transport — how a reconcile reaches the controller's
//! Admin API (`Apply`/`MintToken`/`RegisterRelay`/`Drain`/…).
//!
//! **Two transports, one surface.** The controller's Admin TCP listener binds
//! loopback-only by design (plaintext bearer), so a separate-pod operator can
//! NOT dial it in-cluster (spec §0 amendment / `operator-admin-channel-gap.md`).
//!
//! - [`AdminExec::Grpc`] — a direct gRPC client to the Admin TCP port. Usable
//!   only where that port is reachable on loopback: local runs and the
//!   integration tests (against a `wiremesh_testkit::TestController`). This is
//!   what the reconciler unit/integration tests exercise.
//! - [`AdminExec::Exec`] — the **production** transport: `kube exec` of
//!   `fabricctl --socket <uds>` in the controller pod's admin-exec sidecar,
//!   over the pod-local implicit-admin UDS. **Not yet implemented** — it is the
//!   cluster-only piece (needs `pods/exec` RBAC and, for enrollment-token
//!   minting, a `fabricctl` surface that MintToken currently lacks). Tracked in
//!   `operator-admin-channel-gap.md`; the reconcilers are written against this
//!   enum so swapping it in requires no reconciler change.

use crate::admin::FabricAdmin;
use anyhow::bail;
use wiremesh_proto::v1::{ApplyDiff, GatewayInfo};

/// The admin transport (see module docs).
pub enum AdminExec {
    /// Direct gRPC to `addr` (host:port) with a bearer `token`. Loopback-only
    /// reachable in practice — tests + local use.
    Grpc { addr: String, token: String },
    /// Production: exec `fabricctl` in the controller pod over the UDS. Config
    /// carried for the (not-yet-implemented) transport.
    Exec {
        namespace: String,
        pod_label: String,
        container: String,
        uds: String,
    },
}

impl AdminExec {
    /// Build a fresh gRPC admin client (Grpc transport only). Reconnecting
    /// per-call keeps the transport stateless and avoids a shared mutable
    /// client across concurrent reconciles.
    async fn grpc(&self) -> anyhow::Result<FabricAdmin> {
        match self {
            AdminExec::Grpc { addr, token } => FabricAdmin::connect(addr, token).await,
            AdminExec::Exec { .. } => bail!(
                "in-cluster admin-exec transport not yet implemented — see \
                 docs/research/operator-admin-channel-gap.md (spec §0)"
            ),
        }
    }

    /// Declaratively apply a fabric (segments + policy) in one transaction.
    pub async fn apply(&self, fabric_yaml: &str) -> anyhow::Result<ApplyDiff> {
        self.grpc().await?.apply(fabric_yaml).await
    }

    /// Mint a single-use gateway enrollment token bound to `cidrs`.
    pub async fn mint_gateway_token(&self, cidrs: &[String]) -> anyhow::Result<String> {
        self.grpc().await?.mint_gateway_token(cidrs).await
    }

    /// Mint a single-use relay enrollment token.
    pub async fn mint_relay_token(&self) -> anyhow::Result<String> {
        self.grpc().await?.mint_relay_token().await
    }

    /// Register a relay; returns its assigned id.
    pub async fn register_relay(&self, name: &str, endpoint: &str) -> anyhow::Result<u64> {
        self.grpc().await?.register_relay(name, endpoint).await
    }

    /// Delete a segment by name (Apply is create/update-only, so deletion is
    /// explicit — driven by the Segment finalizer).
    pub async fn delete_segment_by_name(&self, name: &str) -> anyhow::Result<()> {
        self.grpc().await?.delete_segment_by_name(name).await
    }

    /// Current gateway rows (id, name, segment, status, applied_version).
    pub async fn list_gateways(&self) -> anyhow::Result<Vec<GatewayInfo>> {
        self.grpc().await?.list_gateways().await
    }

    /// Drain (withdraw + revoke) a gateway by id — driven by the Gateway
    /// finalizer.
    pub async fn drain(&self, gateway_id: u64) -> anyhow::Result<()> {
        self.grpc().await?.drain(gateway_id).await
    }
}
