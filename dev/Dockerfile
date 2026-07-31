# dev/Dockerfile
FROM rust:1-bookworm

# `conntrack` (conntrack-tools): NftEnforcer::flush_flows (Task 12 addendum)
# shells out to it to flush conntrack state and force re-evaluation of
# already-established fabric flows -- nftables has no built-in ruleset-level
# primitive for this, unlike the eBPF backend's own FLOWS map.
#
# `python3`: the netns gateway suites shell out to it for the TCP policy probes
# (mesh_milestone, key_rotation) and the boringtun UAPI `get=1` probe. It has
# always arrived transitively with the rust:1-bookworm base, so a base-image
# bump could silently remove it and turn every such probe into a misleading
# "socket never answered" timeout -- pin it explicitly instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables iperf3 wireguard-tools tcpdump jq \
    pkg-config libssl-dev ca-certificates kmod procps bpftool iputils-ping \
    protobuf-compiler conntrack python3 \
    && rm -rf /var/lib/apt/lists/*

# eBPF toolchain: nightly rustc (BPF codegen) + bpf-linker + cargo-generate
RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker cargo-generate

# bash -lc sources /etc/profile which resets PATH; keep cargo/rustup visible in login shells
RUN echo 'export PATH=/usr/local/cargo/bin:/usr/local/rustup/bin:$PATH' > /etc/profile.d/cargo.sh

WORKDIR /work
