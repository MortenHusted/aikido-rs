//! Shared Aikido Security API core: OAuth client-credentials auth, credential
//! storage, and the public-API client. Both the `aikido` CLI and the
//! `aikido-mcp` server build on this crate so auth and API behaviour cannot
//! drift between them.

pub mod api;
pub mod auth;
pub mod client;
pub mod credentials;
pub mod error;
pub mod session;
pub mod until;
