//! WireMesh Kubernetes operator — a thin, declarative front-end over the
//! existing `wiremesh-controller` Admin API. See
//! `docs/superpowers/specs/2026-07-22-kubernetes-operator-design.md`.

pub mod crd;

/// Liveness/readiness signal for the operator's HTTP probe endpoint. Returns
/// the HTTP status code and body the `/healthz` handler serves.
pub fn healthz() -> (u16, &'static str) {
    (200, "ok")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_ok() {
        let (code, body) = healthz();
        assert_eq!(code, 200);
        assert_eq!(body, "ok");
    }
}
