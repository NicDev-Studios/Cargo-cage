use std::ffi::OsString;
use std::path::PathBuf;

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
}
