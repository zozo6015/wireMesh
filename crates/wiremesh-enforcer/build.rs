//! Adapted from `spike/enforcer/enforcer/build.rs` (Task 7 brief). The
//! spike's `enforcer` and `enforcer-ebpf` were members of the SAME cargo
//! workspace, so (a) a plain `MetadataCommand::new().exec()` (no explicit
//! manifest path) found `enforcer-ebpf` automatically, and (b) when
//! `aya_build::build_ebpf` internally shells out to
//! `cargo build --package enforcer-ebpf --target bpfel-unknown-none ...`
//! (inheriting the build script's own cwd, which cargo sets to the
//! package's manifest directory), that subprocess naturally resolved
//! `enforcer-ebpf` by name because it was already walking that same
//! workspace.
//!
//! `wiremesh-enforcer` and `wiremesh-enforcer-program` are NOT in the same
//! workspace -- the eBPF program lives in the sibling STANDALONE workspace
//! `crates/wiremesh-enforcer-ebpf` (excluded from the root workspace because
//! the aya template ships its own `[workspace]` -- see CLAUDE.md). Two
//! adaptations follow from that:
//!  1. `MetadataCommand` is pointed explicitly at that workspace's own
//!     `Cargo.toml` via `manifest_path`, instead of relying on the default
//!     cwd-based discovery.
//!  2. Before calling `aya_build::build_ebpf`, this build script changes
//!     ITS OWN current directory to that sibling workspace's root. Without
//!     this, `aya_build`'s internal `cargo build --package
//!     wiremesh-enforcer-program ...` subprocess would inherit this crate's
//!     cwd (`crates/wiremesh-enforcer`, ROOT-workspace territory) and fail
//!     to resolve `wiremesh-enforcer-program` by name at all (it isn't a
//!     root-workspace package) -- and even if it were somehow resolvable,
//!     it would miss the sibling workspace's own `[workspace.dependencies]`
//!     pins and `[profile.release.package.wiremesh-enforcer-program]`
//!     settings, since those live in a Cargo.toml the root workspace never
//!     reads. Switching cwd makes the nested `cargo` invocation walk up
//!     from the RIGHT place and pick up the RIGHT workspace, exactly as the
//!     spike's single-workspace layout did for free.

use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let workspace_manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../wiremesh-enforcer-ebpf/Cargo.toml");
    println!(
        "cargo:rerun-if-changed={}",
        workspace_manifest_path.display()
    );

    let cargo_metadata::Metadata {
        packages,
        workspace_root,
        ..
    } = cargo_metadata::MetadataCommand::new()
        .manifest_path(&workspace_manifest_path)
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let program_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "wiremesh-enforcer-program")
        .ok_or_else(|| anyhow!("wiremesh-enforcer-program package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = program_package;
    println!("cargo:rerun-if-changed={manifest_path}");
    let program_root_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
        .to_owned();
    let program_package = aya_build::Package {
        name: name.as_str(),
        root_dir: program_root_dir.as_str(),
        ..Default::default()
    };

    // (Review finding) `aya_build::build_ebpf` tracks `program_root_dir`
    // (`program/src`) via its own `root_dir`, but the sibling `common/`
    // crate -- shared `#[repr(C)]` types (FlowKey/RuleMeta/...) the program
    // and this host crate both depend on -- is NOT under that root_dir, so
    // editing it alone wouldn't trigger a rebuild here and this crate would
    // link a stale BPF object. Track both explicitly, relative to the
    // sibling workspace root this build script already resolved above.
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("common/src").as_str()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("program/src").as_str()
    );

    // Adaptation 2 (see module doc): run the nested cargo invocation from
    // the sibling standalone workspace's own root, not this crate's.
    std::env::set_current_dir(&workspace_root)
        .with_context(|| format!("cd into sibling workspace root {workspace_root}"))?;

    aya_build::build_ebpf([program_package], Toolchain::default())
}
