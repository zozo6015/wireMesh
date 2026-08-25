//! Enforcer wiring (spec §5, §4). Thin adapter over `wiremesh-enforcer`: probe
//! the backend on the tun, feed it the snapshot's `policy_ir`, gate re-apply on
//! the policy version.
use crate::state::DesiredState;
use anyhow::Context;
use wiremesh_enforcer::{probe, BackendKind, Counters, DenyEvent, Enforcer, EnforcerConfig};
use wiremesh_policy::PolicyIR;

pub struct GatewayEnforcer {
    inner: Box<dyn Enforcer>,
    applied_version: Option<u64>,
}

impl GatewayEnforcer {
    pub fn attach(ifname: &str) -> anyhow::Result<Self> {
        let inner = probe(ifname, EnforcerConfig::default())
            .with_context(|| format!("probing enforcer backend on {ifname}"))?;
        Ok(GatewayEnforcer {
            inner,
            applied_version: None,
        })
    }

    pub fn kind(&self) -> BackendKind {
        self.inner.kind()
    }

    /// The backend's published apply deadline (see
    /// [`wiremesh_enforcer::Enforcer::apply_ready_at`]). `&self` and
    /// non-blocking on purpose: `crate::policy_apply`'s adapter reads this
    /// across every live epoch's enforcer under the map lock and then DROPS
    /// that lock before waiting the deadline out, so the metrics scrape,
    /// retire, Role-B collapse and rotation-insert paths keep the map
    /// available for the whole grace.
    pub fn apply_ready_at(&self) -> Option<std::time::Instant> {
        self.inner.apply_ready_at()
    }

    /// The policy version this enforcer currently has live, or `None` before
    /// its first apply. Exposed (Backlog item 1) so `crate::policy_apply`'s
    /// adapter can tell which entries an install would actually WRITE:
    /// the reap deadline of an entry already on `ds.policy_version` is
    /// irrelevant, because [`GatewayEnforcer::apply_if_changed`] will not
    /// touch it.
    pub fn applied_version(&self) -> Option<u64> {
        self.applied_version
    }

    /// Deserialize + apply the desired IR iff its version changed (or first
    /// apply). Empty `policy_ir` bytes mean "no policy yet" -> empty IR v1.
    pub fn apply_if_changed(&mut self, ds: &DesiredState) -> anyhow::Result<bool> {
        if self.applied_version == Some(ds.policy_version) {
            return Ok(false);
        }
        let ir = if ds.policy_ir.is_empty() {
            PolicyIR {
                schema: 1,
                version: ds.policy_version,
                blocks: vec![],
            }
        } else {
            PolicyIR::from_json(&ds.policy_ir).context("deserializing policy_ir from snapshot")?
        };
        self.inner
            .apply(&ir)
            .context("applying policy IR to enforcer")?;
        self.applied_version = Some(ds.policy_version);
        Ok(true)
    }

    pub fn counters(&mut self) -> anyhow::Result<Counters> {
        self.inner.counters()
    }

    pub fn deny_events(&mut self) -> anyhow::Result<Vec<DenyEvent>> {
        self.inner.deny_events()
    }
}
