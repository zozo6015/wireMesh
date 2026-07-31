//! Thin wrapper over the controller's Admin gRPC API (the same surface
//! `fabricctl` drives). The TCP Admin listener is bearer-auth over plaintext
//! gRPC — the operator authenticates with a token minted during controller
//! bootstrap (see `controllers::controller`).

use anyhow::Context;
use std::time::Duration;
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::Channel;
use tonic::{Request, Status};
use wiremesh_proto::v1::admin_client::AdminClient;
use wiremesh_proto::v1::{
    ApplyDiff, ApplyRequest, DeleteSegmentRequest, DrainRequest, GatewayInfo, ListGatewaysRequest,
    ListSegmentsRequest, MintTokenRequest, RegisterRelayRequest,
};

/// The token `kind` the controller keys the REBIND path off
/// (`wiremesh-controller/src/db.rs`: `let is_rebind = kind == "rebind";`).
///
/// Load-bearing: `rebind_segment_id` is read ONLY inside that arm, so a token
/// minted as `"gateway"` with a segment id set is an ORDINARY token whose
/// stored id is dead data — redeeming it against the (still-occupied) segment
/// is refused with `SegmentAlreadyBound`. Any value but `"rebind"` silently
/// degrades the mint.
pub const REBIND_TOKEN_KIND: &str = "rebind";

/// The exact `MintTokenRequest` an operator rebind mint must send — the single
/// definition both transports encode.
///
/// Byte-for-byte the encoding `crates/wiremesh-controller/tests/rebind.rs`
/// proves end-to-end: [`REBIND_TOKEN_KIND`], **empty** `bound_cidrs`, and the
/// segment id. `bound_cidrs` must stay empty: for a rebind token the controller
/// skips the bound-CIDR scope check entirely and authorizes by segment id
/// alone, so CIDRs there would be dead, misleading data. (The operator records
/// the segment's new CIDRs in its own token Secret instead — see
/// `controllers::gateway::token_secret_body`.)
pub fn rebind_mint_request(rebind_segment_id: u64) -> MintTokenRequest {
    MintTokenRequest {
        kind: REBIND_TOKEN_KIND.to_string(),
        bound_cidrs: Vec::new(),
        rebind_segment_id,
    }
}

/// A `tonic` interceptor that adds `authorization: Bearer <token>` to every
/// request — byte-for-byte the header `fabricctl`'s `AuthMode::Bearer` sets.
#[derive(Clone)]
pub struct BearerAuth(pub String);

impl Interceptor for BearerAuth {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let value = format!("Bearer {}", self.0)
            .parse()
            .map_err(|_| Status::invalid_argument("bearer token is not a valid header value"))?;
        req.metadata_mut().insert("authorization", value);
        Ok(req)
    }
}

/// Admin client bound to one controller with a bearer token.
pub struct FabricAdmin {
    client: AdminClient<InterceptedService<Channel, BearerAuth>>,
}

impl FabricAdmin {
    /// Connect to the controller's Admin TCP listener (`host:port`, plaintext
    /// gRPC + bearer auth).
    pub async fn connect(admin_tcp_addr: &str, bearer_token: &str) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(format!("http://{admin_tcp_addr}"))
            .context("controller Admin TCP addr must form a valid URI")?
            // tonic applies no connect/request timeout by default — without
            // these a reconcile that dials an unreachable controller hangs
            // forever, wedging the reconcile loop.
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .connect()
            .await
            .with_context(|| format!("connecting to controller Admin TCP at {admin_tcp_addr}"))?;
        let client = AdminClient::with_interceptor(channel, BearerAuth(bearer_token.to_string()));
        Ok(Self { client })
    }

    /// Declaratively apply a fabric (segments + policy) in one transaction.
    pub async fn apply(&mut self, fabric_yaml: &str) -> anyhow::Result<ApplyDiff> {
        Ok(self
            .client
            .apply(ApplyRequest { fabric_yaml: fabric_yaml.to_string() })
            .await
            .context("Admin.Apply")?
            .into_inner())
    }

    /// Mint a single-use enrollment token for a gateway bound to `bound_cidrs`.
    pub async fn mint_gateway_token(&mut self, bound_cidrs: &[String]) -> anyhow::Result<String> {
        self.mint_token("gateway", bound_cidrs).await
    }

    /// Mint a single-use enrollment token for a relay (relays have no
    /// segment/CIDR binding).
    pub async fn mint_relay_token(&mut self) -> anyhow::Result<String> {
        self.mint_token("relay", &[]).await
    }

    /// Mint a single-use REBIND token scoped to `rebind_segment_id` (non-zero).
    /// At redemption the controller REPLACES the segment's active gateway
    /// instead of rejecting the enroll with `SegmentAlreadyBound`.
    ///
    /// Wire encoding: [`rebind_mint_request`] — `kind = "rebind"` + EMPTY
    /// `bound_cidrs` + the segment id. The controller keys rebind off the KIND
    /// alone and only reads `rebind_segment_id` in that arm.
    pub async fn mint_gateway_rebind_token(
        &mut self,
        rebind_segment_id: u64,
    ) -> anyhow::Result<String> {
        anyhow::ensure!(
            rebind_segment_id != 0,
            "a rebind token needs a non-zero segment id (0 means 'no rebind' on the wire)"
        );
        self.mint(rebind_mint_request(rebind_segment_id)).await
    }

    async fn mint_token(&mut self, kind: &str, bound_cidrs: &[String]) -> anyhow::Result<String> {
        self.mint(MintTokenRequest {
            kind: kind.to_string(),
            bound_cidrs: bound_cidrs.to_vec(),
            rebind_segment_id: 0,
        })
        .await
    }

    /// Send one `MintTokenRequest` — the single place the RPC is issued, so
    /// every mint shape (gateway, relay, rebind) travels the same path.
    async fn mint(&mut self, req: MintTokenRequest) -> anyhow::Result<String> {
        Ok(self
            .client
            .mint_token(req)
            .await
            .context("Admin.MintToken")?
            .into_inner()
            .token)
    }

    /// Register a relay; returns its assigned relay id.
    pub async fn register_relay(&mut self, name: &str, endpoint: &str) -> anyhow::Result<u64> {
        Ok(self
            .client
            .register_relay(RegisterRelayRequest { name: name.to_string(), endpoint: endpoint.to_string() })
            .await
            .context("Admin.RegisterRelay")?
            .into_inner()
            .id)
    }

    /// Resolve a segment's controller-side id by `name` (`None` if the segment
    /// is not registered).
    pub async fn segment_id_by_name(&mut self, name: &str) -> anyhow::Result<Option<u64>> {
        let segments = self
            .client
            .list_segments(ListSegmentsRequest {})
            .await
            .context("Admin.ListSegments")?
            .into_inner()
            .segments;
        Ok(segments.into_iter().find(|s| s.name == name).map(|s| s.id))
    }

    /// Delete a segment by its `name` (resolves name→id via `ListSegments`,
    /// since `DeleteSegment` takes a `segment_id`). No-op if absent.
    pub async fn delete_segment_by_name(&mut self, name: &str) -> anyhow::Result<()> {
        if let Some(segment_id) = self.segment_id_by_name(name).await? {
            self.client
                .delete_segment(DeleteSegmentRequest { segment_id })
                .await
                .context("Admin.DeleteSegment")?;
        }
        Ok(())
    }

    /// Current gateway rows (id, name, segment, status, applied_version).
    pub async fn list_gateways(&mut self) -> anyhow::Result<Vec<GatewayInfo>> {
        Ok(self
            .client
            .list_gateways(ListGatewaysRequest {})
            .await
            .context("Admin.ListGateways")?
            .into_inner()
            .gateways)
    }

    /// Drain (withdraw + revoke) a gateway by id.
    pub async fn drain(&mut self, gateway_id: u64) -> anyhow::Result<()> {
        self.client
            .drain(DrainRequest { gateway_id })
            .await
            .context("Admin.Drain")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_interceptor_sets_authorization() {
        let mut auth = BearerAuth("T".to_string());
        let req = auth.call(Request::new(())).unwrap();
        assert_eq!(req.metadata().get("authorization").unwrap(), "Bearer T");
    }
}
