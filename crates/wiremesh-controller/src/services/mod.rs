//! tonic service implementations. Each submodule owns one gRPC service
//! defined in `wiremesh-proto`.

pub mod admin;
pub mod enrollment;
pub mod sync;
