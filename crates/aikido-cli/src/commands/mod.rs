//! Command implementations. Each returns `Result<(), ApiError>` after
//! rendering its own success output; `main` renders errors and maps exit
//! codes in one place.

pub mod api;
pub mod auth;
pub mod containers;
pub mod issues;
pub mod repos;

use aikido_core::credentials::CredentialStore;
use aikido_core::error::ApiError;
use aikido_core::session::{self, Session};

use crate::output::GlobalFlags;

/// Resolve the authenticated session for a command.
pub fn require_session(flags: &GlobalFlags) -> Result<Session, ApiError> {
    session::resolve(&CredentialStore::default(), flags.verbose)
}
