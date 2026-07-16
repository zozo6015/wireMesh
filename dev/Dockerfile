# dev/Dockerfile
FROM rust:1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables iperf3 wireguard-tools tcpdump jq \
    pkg-config libssl-dev ca-certificates kmod procps bpftool iputils-ping \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# eBPF toolchain: nightly rustc (BPF codegen) + bpf-linker + cargo-generate
RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker cargo-generate

# bash -lc sources /etc/profile which resets PATH; keep cargo/rustup visible in login shells
RUN echo 'export PATH=/usr/local/cargo/bin:/usr/local/rustup/bin:$PATH' > /etc/profile.d/cargo.sh

WORKDIR /work
