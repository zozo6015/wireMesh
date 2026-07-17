#![no_std]

// This file exists to enable the library target (graduated from
// `spike/enforcer/enforcer-ebpf/src/lib.rs`): `crates/wiremesh-enforcer`'s
// `build.rs` names this package as a path build-dependency purely so cargo
// tracks source changes for rebuild purposes (cargo requires a lib target
// to do so, since a build-dependency resolves to the package's `[lib]`,
// never its `[[bin]]`) — the real `#![no_std] #![no_main]` tc-classifier
// logic lives in `src/main.rs`, compiled only via `aya_build::build_ebpf`
// (cross-compiled to the `bpfel-unknown-none` target), never via this lib
// target or a plain host `cargo build`.
