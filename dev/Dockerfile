# dev/Dockerfile
# The compiler is PINNED to an exact patch, not the floating `rust:1-bookworm`
# tag, and this is the same discipline the bpf-linker pin below already
# follows: capture the known-good version from a green run instead of letting a
# rebuild silently adopt one the suite has never run on. It becomes
# load-bearing with B4 (PR3), which will add the repo's first `cargo fmt
# --check` and `cargo clippy -D warnings` jobs -- no workflow runs either today
# (`grep -rn "cargo fmt\|clippy\|rustfmt" .github/` returns nothing). Both
# produce toolchain-dependent output, so a floating base would make an
# unchanged tree red on the day a new stable ships.
#
# WHY THE PIN LIVES HERE AND NOT IN A ROOT `rust-toolchain.toml`. That was
# tried and had to be reverted. Rustup consults a toolchain file by walking up
# from wherever cargo was invoked, and it outranks the `rustup default` that
# `dtolnay/rust-toolchain@stable` sets -- so a root file would have governed
# EVERY cargo invocation in the checkout, including `release.yml`'s macOS and
# Windows jobs. The macOS job builds `--target x86_64-apple-darwin`, and that
# action installs requested targets into the toolchain IT installs; under a
# root pin the build would have run on a different toolchain with no
# darwin-x86_64 std, failing with `E0463 can't find crate for std` and taking
# the x86_64 tarball and the universal .pkg with it. A toolchain file also
# cannot carry per-platform targets, so there is no version of it that works.
# Pinning the IMAGE instead reaches every job that needs pinning -- B4's jobs
# will all run in this image -- and leaves the mac/windows release jobs on
# `@stable`, exactly as they were before.
#
# TWO LINES MUST MOVE TOGETHER, and they are named here because a version-tag
# pin and a digest pin cannot drift together on their own -- this comment is
# the only instrument that couples them:
#
#     dev/Dockerfile            FROM rust:1.97.1-bookworm
#     deploy/docker/Dockerfile  FROM rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder
#
# The digest was measured to carry rustc 1.97.1 (8bab26f4f 2026-07-14) -- the
# same stable this tag installs -- so today the compiler that TESTS the code
# and the compiler that SHIPS the Linux artifacts are identical. Change one and
# you must change the other, or that stops being true silently.
#
# SCOPE OF THAT EQUIVALENCE: stable/userspace ON LINUX, and nothing wider.
# The macOS and Windows release artifacts are built on their own runners by a
# floating `dtolnay/rust-toolchain@stable`, so which compiler produced them is
# recorded nowhere. That is pre-existing, not introduced here, and is filed
# rather than fixed -- the design's "the compiler the suite is proven on" only
# ever described Linux, which is precisely why the pin belongs to the images
# and not to a root toolchain file.
#
# TWO ACCEPTED COSTS of naming an exact patch, stated rather than discovered.
# (1) This tag no longer picks up base-OS security patches that
# `rust:1-bookworm` would have rolled in; the release image is equally frozen
# (its base is digest-pinned), so this does not make the shipped artifacts
# staler than they already were, but it does mean base updates are now a
# deliberate act. (2) A version tag is still a MUTABLE reference -- the
# official images rebuild `rust:1.97.1-bookworm` in place -- so this pins the
# compiler, not the layer. A digest would pin both; that is a bigger change
# than PR0 and is filed as a follow-up, together with adding
# `.github/dependabot.yml` (`package-ecosystem: docker`) so base bumps arrive
# as reviewable PRs instead of never.
#
# The equivalence does not cover the eBPF half either: both Dockerfiles ALSO
# `rustup toolchain install nightly` UNDATED, the object that nightly produces
# is baked into the shipped gateway via `include_bytes_aligned!`, and those two
# nightlies float independently, resolving at each image's last COLD build.
# That is deliberate, and left undated on purpose.
FROM rust:1.97.1-bookworm

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

# eBPF toolchain: nightly rustc (BPF codegen) + bpf-linker + cargo-generate.
# bpf-linker is PINNED to the version this image already carries and the whole
# suite is proven against. Unpinned, it broke the v0.10.0 release: 0.11.0 links
# against system LLVM and its build script aborts without llvm-config. Existing
# dev images are unaffected (the layer is cached); this stops a rebuild from
# silently picking up a toolchain the suite has never run on. Keep in step with
# deploy/docker/Dockerfile, which carries the same pin and the full reasoning.
#
# `rustfmt` and `clippy` are added explicitly on BOTH toolchains. Neither was
# present before: `cargo fmt` in this image failed with "'cargo-fmt' is not
# installed for the toolchain '1.97.1-…'". B4's `fmt` and `clippy` jobs will
# run in this image, and relying on a `rust-toolchain.toml` `components` list
# to auto-install them at runtime is not an option — containers run `--rm`, so
# every invocation would re-download them.
#
# NIGHTLY needs `rustfmt` for a non-obvious reason, found by running it:
# `crates/wiremesh-enforcer-ebpf` carries its own `rust-toolchain.toml` naming
# nightly, so `cargo fmt` in THAT directory resolves to nightly's rustfmt, not
# stable's. Without this, B4's `fmt` job would die on its second invocation
# with "'cargo-fmt' is not installed for the toolchain 'nightly-...'" against a
# perfectly formatted tree. Nightly also gets `clippy` so a later
# `bpfel-unknown-none` lint of the eBPF classifier needs no new image.
#
# `--allow-downgrade` is REQUIRED, not defensive. `clippy` and `rustfmt` are
# toolstate-gated on nightly: on any nightly where one of them failed to build,
# `rustup toolchain install nightly --component clippy --component rustfmt`
# hard-fails rather than skipping the missing piece -- and because this is one
# `RUN`, that failure would take the `cargo install bpf-linker` below with it
# and break a cold `./dev.sh build` for reasons unrelated to this repo.
# `--allow-downgrade` makes rustup step back to the most recent nightly that
# has every requested component. `dtolnay/rust-toolchain` does exactly this for
# nightly-plus-components, for exactly this reason.
RUN rustup toolchain install nightly --component rust-src --component clippy --component rustfmt --allow-downgrade \
    && rustup component add rustfmt clippy \
    && cargo install bpf-linker --version 0.10.4 --locked \
    && cargo install cargo-generate

# bash -lc sources /etc/profile which resets PATH; keep cargo/rustup visible in login shells
RUN echo 'export PATH=/usr/local/cargo/bin:/usr/local/rustup/bin:$PATH' > /etc/profile.d/cargo.sh

WORKDIR /work
