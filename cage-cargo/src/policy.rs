use cage_core::{
    CageError, CageResult, NetworkAccess, SandboxPolicy, is_sensitive_environment_name,
};
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub fn cargo_policy(main_build: bool) -> CageResult<SandboxPolicy> {
    let home = env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        CageError::policy(
            "HOME",
            "HOME must be set to construct the sandbox policy",
            "set HOME to an absolute home directory before running cargo-cage",
        )
    })?;
    if !home.is_absolute() {
        return Err(CageError::policy(
            home.display().to_string(),
            "HOME must be an absolute path",
            "set HOME to the absolute path of the user home directory",
        ));
    }
    if home == Path::new(std::path::MAIN_SEPARATOR_STR) {
        return Err(CageError::policy(
            home.display().to_string(),
            "HOME must not be the filesystem root",
            "set HOME to a real user home directory",
        ));
    }

    let default_cargo_home = home.join(".cargo");
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_cargo_home.clone());
    let mut hidden_paths = vec![PathBuf::from("/etc/cargo")];
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
    let cargo_homes = if cargo_home == default_cargo_home {
        vec![cargo_home]
    } else {
        vec![cargo_home, default_cargo_home]
    };
    for cargo_home in cargo_homes {
        hidden_paths.push(cargo_home.join("credentials"));
        hidden_paths.push(cargo_home.join("credentials.toml"));
        hidden_paths.push(cargo_home.join("config"));
        hidden_paths.push(cargo_home.join("config.toml"));
    }

    let mut private_paths = vec![home];
    if main_build {
        private_paths.extend([
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/run"),
        ]);
    }

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
