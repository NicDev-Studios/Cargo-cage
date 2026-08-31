use crate::backend::ProcessStatus;
use std::fmt;
use std::io;
use std::path::PathBuf;

pub type CageResult<T> = Result<T, CageError>;

#[derive(Debug)]
pub enum CageError {
    InvalidInvocation(String),
    Policy(String),
    UnsupportedPlatform,
    BackendUnavailable(String),
    SandboxSetup(String),
    ProcessSpawn {
        program: PathBuf,
        source: io::Error,
    },
    ProcessFailed {
        status: ProcessStatus,
        detail: String,
    },
    Io {
        context: String,
        source: io::Error,
    },
}

impl CageError {
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

impl fmt::Display for CageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvocation(message) => write!(f, "invalid invocation: {message}"),
            Self::Policy(message) => write!(f, "sandbox policy error: {message}"),
            Self::UnsupportedPlatform => {
                write!(f, "cargo-cage v0.1 supports Linux only")
            }
            Self::BackendUnavailable(message) => {
                write!(f, "Linux sandbox backend unavailable: {message}")
            }
            Self::SandboxSetup(message) => write!(f, "sandbox setup failed: {message}"),
            Self::ProcessSpawn { program, source } => {
                write!(f, "could not start {}: {source}", program.display())
            }
            Self::ProcessFailed { status, detail } => {
                write!(
                    f,
                    "sandboxed process failed with {:?}: {detail}",
                    status.code
                )
            }
            Self::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for CageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProcessSpawn { source, .. } | Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
