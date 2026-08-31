use cage_core::{CageError, CageResult, NetworkAccess, SandboxPolicy};
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub fn cargo_policy(main_build: bool) -> CageResult<SandboxPolicy> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CageError::Policy("HOME is not set".to_owned()))?;
    if !home.is_absolute() {
        return Err(CageError::Policy(
            "HOME must be an absolute path".to_owned(),
        ));
    }

    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cargo"));
    let mut hidden_paths = Vec::new();
    for name in [
        ".ssh",
        ".aws",
        ".config",
        ".gnupg",
        ".kube",
        ".docker",
        ".password-store",
        ".netrc",
    ] {
        hidden_paths.push(home.join(name));
    }
    hidden_paths.push(cargo_home.join("credentials"));
    hidden_paths.push(cargo_home.join("credentials.toml"));

    let private_paths = if main_build {
        vec![PathBuf::from("/tmp"), PathBuf::from("/run")]
    } else {
        Vec::new()
    };

    Ok(SandboxPolicy {
        network: NetworkAccess::Deny,
        writable_paths: Vec::new(),
        hidden_paths,
        private_paths,
        read_only_paths: Vec::new(),
        remove_environment: sensitive_environment_names(),
    })
}

fn sensitive_environment_names() -> Vec<OsString> {
    let mut names = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "RUSTUP_TOKEN",
        "SSH_AUTH_SOCK",
        "GPG_AGENT_INFO",
        "DBUS_SESSION_BUS_ADDRESS",
        "DOCKER_HOST",
        "KUBECONFIG",
        "NPM_TOKEN",
        "PYPI_TOKEN",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    for (name, _) in env::vars_os() {
        if is_sensitive_environment_name(&name) && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn is_sensitive_environment_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.starts_with("AWS_")
            || name.starts_with("CARGO_REGISTRIES_") && name.ends_with("_TOKEN")
            || name.ends_with("_PASSWORD")
            || name.ends_with("_SECRET")
    })
}
