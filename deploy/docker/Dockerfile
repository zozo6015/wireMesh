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

# ---------------------------------------------------------------------------
# builder — release binaries for the whole workspace (glibc/bookworm; the
# servers use rustls+ring so no OpenSSL is linked, but pkg-config/libssl-dev
# match dev/Dockerfile in case a transitive dep probes for them).
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# eBPF toolchain: nightly rustc (BPF codegen) + rust-src + bpf-linker.
# Identical to dev/Dockerfile so the release build matches what CI/tests prove.
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
          /out/

# ---------------------------------------------------------------------------
# controller — single-tenant control plane (gRPC/mTLS, embedded CA, sqlite via
# rusqlite `bundled` so no libsqlite3 at runtime; rustls+ring so no libssl).
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS controller
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/wiremesh-controller /usr/local/bin/wiremesh-controller
# Data dir (DB, embedded CA, secrets); mount a volume/PVC here in production.
VOLUME ["/var/lib/wiremesh"]
ENTRYPOINT ["/usr/local/bin/wiremesh-controller"]

# ---------------------------------------------------------------------------
# relay — QUIC-datagram WG relay (quinn/rustls+ring). Ships the `mkcerts`
# helper alongside for local identity bootstrap.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS relay
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/relay /usr/local/bin/relay
COPY --from=builder /out/mkcerts /usr/local/bin/mkcerts
# Relay identity (cert/key/ca, each 0600) is expected under /var/lib/wiremesh.
VOLUME ["/var/lib/wiremesh"]
ENTRYPOINT ["/usr/local/bin/relay"]

# ---------------------------------------------------------------------------
# fabricctl — admin CLI (talks to the controller Admin API).
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS fabricctl
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/fabricctl /usr/local/bin/fabricctl
ENTRYPOINT ["/usr/local/bin/fabricctl"]

# ---------------------------------------------------------------------------
# gateway — per-segment data plane. Embeds boringtun (no `wg` needed) but
# programs routes/links and the nftables MSS clamp by shelling out to `ip`
# (iproute2) and `nft` (nftables); the nftables enforcer backend flushes state
# with `conntrack` (conntrack-tools). MUST run privileged with NET_ADMIN and a
# /dev/net/tun device (eBPF tc + tun); see deploy/ manifests.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS gateway
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates iproute2 nftables conntrack \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/wiremesh-gateway /usr/local/bin/wiremesh-gateway
# Gateway identity + fail-static state.json live here (per-file 0600).
VOLUME ["/var/lib/wiremesh"]
ENTRYPOINT ["/usr/local/bin/wiremesh-gateway"]
