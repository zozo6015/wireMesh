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
        Ok(self
            .client
            .mint_token(MintTokenRequest {
                kind: "gateway".to_string(),
                bound_cidrs: bound_cidrs.to_vec(),
                rebind_segment_id: 0,
            })
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

    /// Delete a segment by its `name` (resolves name→id via `ListSegments`,
    /// since `DeleteSegment` takes a `segment_id`). No-op if absent.
    pub async fn delete_segment_by_name(&mut self, name: &str) -> anyhow::Result<()> {
        let segments = self
            .client
            .list_segments(ListSegmentsRequest {})
            .await
            .context("Admin.ListSegments")?
            .into_inner()
            .segments;
        if let Some(seg) = segments.into_iter().find(|s| s.name == name) {
            self.client
                .delete_segment(DeleteSegmentRequest { segment_id: seg.id })
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
