use crate::backend::ProcessStatus;
use std::fmt;
use std::io;
use std::path::PathBuf;

pub type CageResult<T> = Result<T, CageError>;

#[derive(Debug)]
pub struct PolicyViolation {
    pub subject: String,
    pub rule: String,
    pub remedy: String,
}

impl PolicyViolation {
    pub fn new(
        subject: impl Into<String>,
        rule: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            rule: rule.into(),
            remedy: remedy.into(),
        }
    }
}

#[derive(Debug)]
pub enum CageError {
    InvalidInvocation(String),
    Policy(PolicyViolation),
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
    pub fn policy(
        subject: impl Into<String>,
        rule: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self::Policy(PolicyViolation::new(subject, rule, remedy))
    }

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
            Self::Policy(violation) => write!(
                f,
                "sandbox policy error for {}: {}; remedy: {}",
                violation.subject, violation.rule, violation.remedy
            ),
            Self::UnsupportedPlatform => {
                write!(f, "cargo-cage v0.2 supports Linux only")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_errors_explain_subject_rule_and_remedy() {
        let error = CageError::policy(
            "/workspace/target-link",
            "writable target paths must not contain symlinks",
            "replace the symlink with a real directory",
        );
        let text = error.to_string();
        assert!(text.contains("/workspace/target-link"));
        assert!(text.contains("must not contain symlinks"));
        assert!(text.contains("remedy:"));
        assert!(text.contains("replace the symlink"));
    }
}
