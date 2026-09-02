use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

const FORWARDED_HOST_ENVIRONMENT_NAMES: &[&str] = &[
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_ADDRESS",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
    "TERM",
    "COLORTERM",
    "COLUMNS",
    "LINES",
    "CARGO_TERM_COLOR",
    "CARGO_TERM_VERBOSE",
    "CARGO_TERM_PROGRESS_WHEN",
    "CARGO_INCREMENTAL",
    "CARGO_BUILD_JOBS",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CC",
    "CXX",
    "AR",
    "RANLIB",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "PKG_CONFIG",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_SYSROOT_DIR",
];

const SANDBOX_ONLY_ENVIRONMENT_NAMES: &[&str] = &[
    "HOME",
    "PATH",
    "PWD",
    "RUSTC",
    "RUSTDOC",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "CARGO_NET_OFFLINE",
    "TMPDIR",
];

#[derive(Clone, Debug, Default)]
pub struct Environment {
    /// Whether the backend should inherit the caller's environment first.
    ///
    /// This is `false` by default. Sandboxed Cargo requests should add only
    /// the variables they explicitly need. Setting it to `true` is an
    /// explicit opt-in to host-environment inheritance.
    pub inherit: bool,
    pub set: Vec<(OsString, OsString)>,
    pub remove: Vec<OsString>,
}

impl Environment {
    /// Start with an empty environment instead of inheriting host variables.
    pub fn clean() -> Self {
        Self::default()
    }

    pub fn set(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.set.push((key.into(), value.into()));
        self
    }

    pub fn remove(mut self, key: impl Into<OsString>) -> Self {
        self.remove.push(key.into());
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NetworkAccess {
    #[default]
    Deny,
    Allow,
}

/// Platform-neutral description of the capabilities a child process receives.
#[derive(Clone, Debug)]
pub struct SandboxPolicy {
    pub network: NetworkAccess,
    /// Host paths that may be modified persistently.
    pub writable_paths: Vec<PathBuf>,
    /// Host paths that must not be visible to the child.
    pub hidden_paths: Vec<PathBuf>,
    /// Paths replaced by private, non-persistent filesystems.
    pub private_paths: Vec<PathBuf>,
    /// Source roots that must remain readable when a private path masks them.
    pub read_only_paths: Vec<PathBuf>,
    /// Environment variables removed before the child is started.
    pub remove_environment: Vec<OsString>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            network: NetworkAccess::Deny,
            writable_paths: Vec::new(),
            hidden_paths: Vec::new(),
            private_paths: Vec::new(),
            read_only_paths: Vec::new(),
            remove_environment: Vec::new(),
        }
    }
}

/// Returns whether an environment variable name commonly carries a secret,
/// credential, or host-agent endpoint.
///
/// This deliberately errs on the side of removing a variable. It is shared by
/// the platform-neutral policy layer and every backend so a later backend does
/// not accidentally grow a weaker secret filter.
pub fn is_sensitive_environment_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        let name = name.to_ascii_uppercase();
        name.starts_with("AWS_")
            || name == "TOKEN"
            || name.ends_with("_TOKEN")
            || name.ends_with("_TOKENS")
            || name == "PASSWORD"
            || name.ends_with("_PASSWORD")
            || name == "PASS"
            || name.ends_with("_PASS")
            || name == "SECRET"
            || name.ends_with("_SECRET")
            || name.ends_with("_SECRET_KEY")
            || name == "CREDENTIAL"
            || name.ends_with("_CREDENTIAL")
            || name == "PRIVATE_KEY"
            || name.ends_with("_PRIVATE_KEY")
            || name == "API_KEY"
            || name.ends_with("_API_KEY")
            || name == "ACCESS_KEY"
            || name.ends_with("_ACCESS_KEY")
            || name.starts_with("SSH_")
            || name.starts_with("GPG_")
            || name.ends_with("_AGENT")
            || name.ends_with("_AGENT_INFO")
            || name.ends_with("_AGENT_PID")
            || name.ends_with("_AUTH_SOCK")
    })
}

/// Returns whether a variable is part of the deliberately small environment
/// that a sandboxed Cargo process may receive.
pub fn is_allowed_sandbox_environment_name(name: &OsStr) -> bool {
    is_allowed_host_environment_name(name)
        || name
            .to_str()
            .is_some_and(|name| SANDBOX_ONLY_ENVIRONMENT_NAMES.contains(&name))
}

/// Returns whether a variable may be copied from the caller into a Cargo
/// request. Sandbox-internal values such as `HOME` and `CARGO_TARGET_DIR` are
/// intentionally excluded; the caller constructs those values itself.
pub fn is_allowed_host_environment_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| FORWARDED_HOST_ENVIRONMENT_NAMES.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_is_denied_by_default() {
        assert_eq!(SandboxPolicy::default().network, NetworkAccess::Deny);
    }

    #[test]
    fn environment_builder_preserves_set_and_remove_rules() {
        let environment = Environment::default()
            .set("CARGO_NET_OFFLINE", "true")
            .remove("SSH_AUTH_SOCK");
        assert!(!environment.inherit);
        assert_eq!(
            environment.set,
            vec![(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"))]
        );
        assert_eq!(environment.remove, vec![OsString::from("SSH_AUTH_SOCK")]);
    }

    #[test]
    fn clean_environment_does_not_inherit_host_variables() {
        assert!(!Environment::clean().inherit);
    }

    #[test]
    fn sensitive_environment_filter_is_conservative() {
        for name in [
            "AWS_PROFILE",
            "SERVICE_TOKEN",
            "SERVICE_PASSWORD",
            "SERVICE_SECRET_KEY",
            "SERVICE_PRIVATE_KEY",
            "SERVICE_API_KEY",
            "SSH_AUTH_SOCK",
            "CUSTOM_AGENT_INFO",
        ] {
            assert!(is_sensitive_environment_name(OsStr::new(name)), "{name}");
        }
        assert!(!is_sensitive_environment_name(OsStr::new(
            "CARGO_TARGET_DIR"
        )));
    }

    #[test]
    fn sandbox_environment_allowlist_includes_runtime_but_not_host_control() {
        for name in ["PATH", "HOME", "CARGO_HOME", "RUSTC", "CARGO_NET_OFFLINE"] {
            assert!(
                is_allowed_sandbox_environment_name(OsStr::new(name)),
                "{name}"
            );
        }
        for name in ["SHELL", "SSH_AUTH_SOCK", "DOCKER_HOST", "RANDOM_HOST_VALUE"] {
            assert!(
                !is_allowed_sandbox_environment_name(OsStr::new(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn host_environment_allowlist_excludes_sandbox_owned_values() {
        for name in ["USER", "LANG", "CARGO_BUILD_JOBS", "PKG_CONFIG_PATH"] {
            assert!(is_allowed_host_environment_name(OsStr::new(name)), "{name}");
        }
        for name in ["HOME", "PATH", "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTC"] {
            assert!(
                !is_allowed_host_environment_name(OsStr::new(name)),
                "{name}"
            );
        }
    }
}
