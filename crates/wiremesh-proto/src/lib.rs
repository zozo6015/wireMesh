pub mod v1 {
    tonic::include_proto!("wiremesh.v1");

    // (Task 14) `total_changes` already sums every diff field server-side
    // (see `admin.proto`'s `ApplyDiff` doc comment), so `is_empty()` is just
    // that check — kept as an inherent method (rather than making every
    // caller re-derive it) since a caller checking "was this apply a no-op"
    // is common (the idempotence contract `tests/apply.rs` exercises, and
    // `fabricctl apply`'s printed summary).
    impl ApplyDiff {
        pub fn is_empty(&self) -> bool {
            self.total_changes == 0
        }
    }
}
