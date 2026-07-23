# syntax=docker/dockerfile:1
#
# Multi-stage build for the WireMesh binaries + per-component runtime images.
# One `builder` stage compiles the whole workspace in release mode (including
# the embedded eBPF program, which needs the nightly + bpf-linker toolchain —
# mirrors dev/Dockerfile); each runtime target is a minimal debian-slim image
# carrying exactly one binary plus only the OS tools that binary shells out to.
#
# Build a single image:  docker build -f deploy/docker/Dockerfile --target gateway -t wiremesh-gateway .
# CI (.github/workflows/container-images.yml) builds all four targets and
# pushes them to ghcr.io/<owner>/wiremesh-{controller,gateway,relay,fabricctl}.
#
# Base images are pinned by digest for reproducibility (refresh with
# `docker buildx imagetools inspect <ref>`); the runtime servers drop to a
# non-root user, the privileged gateway is the documented exception (below).

# ---------------------------------------------------------------------------
# builder — release binaries for the whole workspace (glibc/bookworm; the
# servers use rustls+ring so no OpenSSL is linked, but pkg-config/libssl-dev
# match dev/Dockerfile in case a transitive dep probes for them).
# ---------------------------------------------------------------------------
FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# eBPF toolchain: nightly rustc (BPF codegen) + rust-src + bpf-linker.
# NOTE: nightly + bpf-linker are intentionally left floating here to match
# dev/Dockerfile — the proven build toolchain the whole test suite runs on.
# Pinning them to a dated nightly + an explicit bpf-linker version is a tracked
# follow-up: capture the known-good versions from a green CI run first, since an
# unverified nightly can break aya_build's eBPF compilation.
RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker

WORKDIR /src
COPY . .

# Build every workspace binary in release mode. The `wiremesh-enforcer` build
# script compiles the eBPF object via the nightly BPF target during this step.
# BuildKit caches keep the cargo registry + target dir warm across builds; the
# binaries are copied OUT of the cache-mounted target dir within the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace \
    && mkdir -p /out \
    && cp target/release/wiremesh-controller \
          target/release/wiremesh-gateway \
          target/release/relay \
          target/release/mkcerts \
          target/release/fabricctl \
          target/release/wiremesh-operator \
          /out/

# ---------------------------------------------------------------------------
# controller — single-tenant control plane (gRPC/mTLS, embedded CA, sqlite via
# rusqlite `bundled` so no libsqlite3 at runtime; rustls+ring so no libssl).
# Runs as a non-root user; mount the data dir as a volume/PVC.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS controller
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --user-group --no-create-home wiremesh \
    && mkdir -p /var/lib/wiremesh && chown wiremesh:wiremesh /var/lib/wiremesh
COPY --from=builder /out/wiremesh-controller /usr/local/bin/wiremesh-controller
VOLUME ["/var/lib/wiremesh"]
USER wiremesh
ENTRYPOINT ["/usr/local/bin/wiremesh-controller"]

# ---------------------------------------------------------------------------
# relay — QUIC-datagram WG relay (quinn/rustls+ring). Ships the `mkcerts`
# helper alongside for local identity bootstrap. Runs as a non-root user.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS relay
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --user-group --no-create-home wiremesh \
    && mkdir -p /var/lib/wiremesh && chown wiremesh:wiremesh /var/lib/wiremesh
COPY --from=builder /out/relay /usr/local/bin/relay
COPY --from=builder /out/mkcerts /usr/local/bin/mkcerts
# Relay identity (cert/key/ca, each 0600) is expected under /var/lib/wiremesh.
VOLUME ["/var/lib/wiremesh"]
USER wiremesh
ENTRYPOINT ["/usr/local/bin/relay"]

# ---------------------------------------------------------------------------
# fabricctl — admin CLI (talks to the controller Admin API). Non-root.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS fabricctl
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --user-group --no-create-home wiremesh
COPY --from=builder /out/fabricctl /usr/local/bin/fabricctl
USER wiremesh
ENTRYPOINT ["/usr/local/bin/fabricctl"]

# ---------------------------------------------------------------------------
# gateway — per-segment data plane. Embeds boringtun (no `wg` needed) but
# programs routes/links and the nftables MSS clamp by shelling out to `ip`
# (iproute2) and `nft` (nftables); the nftables enforcer backend flushes state
# with `conntrack` (conntrack-tools).
#
# Runs as ROOT by design (deliberate exception to the non-root policy above):
# it loads eBPF (tc/BPF), creates the tun device, and programs routes/nft, all
# of which require CAP_NET_ADMIN + CAP_BPF (or root) plus /dev/net/tun. Running
# it unprivileged is untested and risks the data plane failing to start; the
# deployment scopes it via a privileged / NET_ADMIN securityContext instead.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS gateway
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates iproute2 nftables conntrack \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/wiremesh-gateway /usr/local/bin/wiremesh-gateway
# Gateway identity + fail-static state.json live here (per-file 0600).
VOLUME ["/var/lib/wiremesh"]
ENTRYPOINT ["/usr/local/bin/wiremesh-gateway"]

# ---------------------------------------------------------------------------
# operator — Kubernetes operator (kube-rs). Talks to the K8s apiserver + the
# controller Admin API; needs no privileged host access. Non-root.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS operator
# `TARGETARCH` is set per-platform by buildx (amd64 / arm64).
ARG TARGETARCH
# kubectl is bundled because the operator execs `operator-admin` in the
# controller sidecar via kubectl (kube-rs 0.95's WebSocket exec fails SA auth
# against real API servers). Keep this near the cluster's minor version.
ARG KUBECTL_VERSION=v1.32.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSLo /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
    && chmod 0755 /usr/local/bin/kubectl \
    && kubectl version --client=true 2>/dev/null | head -1 \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --user-group --no-create-home wiremesh
COPY --from=builder /out/wiremesh-operator /usr/local/bin/wiremesh-operator
USER wiremesh
ENTRYPOINT ["/usr/local/bin/wiremesh-operator"]
