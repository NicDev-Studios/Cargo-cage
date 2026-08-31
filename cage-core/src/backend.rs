use crate::error::CageResult;
use crate::policy::{Environment, SandboxPolicy};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// How a sandboxed process should be connected to the caller's stdio.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    /// Keep the normal Cargo terminal behaviour.
    Inherit,
    /// Capture stdout and stderr for discovery commands.
    Capture,
}

/// The part of a child exit status that is portable across backends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessStatus {
    pub code: Option<i32>,
}

impl ProcessStatus {
    pub const fn success() -> Self {
        Self { code: Some(0) }
    }

    pub const fn successfully_exited(self) -> bool {
        matches!(self.code, Some(0))
    }
}

/// Result of running a process through a sandbox backend.
#[derive(Debug, Default)]
pub struct SandboxOutcome {
    pub status: ProcessStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A command and policy to execute inside a sandbox.
#[derive(Clone, Debug)]
pub struct SandboxRequest {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub current_dir: PathBuf,
    pub environment: Environment,
    pub policy: SandboxPolicy,
    pub output: OutputMode,
}

impl SandboxRequest {
    pub fn new(program: impl Into<PathBuf>, current_dir: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: current_dir.into(),
            environment: Environment::clean(),
            policy: SandboxPolicy::default(),
            output: OutputMode::Inherit,
        }
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }
}

/// OS-specific implementation of the process sandbox.
pub trait SandboxBackend {
    fn run(&self, request: &SandboxRequest) -> CageResult<SandboxOutcome>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_requests_default_to_a_clean_environment() {
        assert!(!SandboxRequest::new("/bin/sh", "/").environment.inherit);
    }
}
