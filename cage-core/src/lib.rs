#![forbid(unsafe_code)]

mod backend;
mod error;
mod paths;
mod policy;

pub use backend::{OutputMode, ProcessStatus, SandboxBackend, SandboxOutcome, SandboxRequest};
pub use error::{CageError, CageResult, PolicyViolation, SetupFailure};
pub use paths::canonical_existing_path_without_symlinks;
pub use policy::{
    Environment, NetworkAccess, SandboxPolicy, is_allowed_host_environment_name,
    is_allowed_sandbox_environment_name, is_sensitive_environment_name,
};
