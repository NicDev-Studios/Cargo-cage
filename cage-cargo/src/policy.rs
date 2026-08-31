use cage_core::{CageError, CageResult, NetworkAccess, SandboxPolicy};
use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

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

    let default_cargo_home = home.join(".cargo");
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_cargo_home.clone());
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
        let name = name.to_ascii_uppercase();
        name.starts_with("AWS_")
            || name == "TOKEN"
            || name.ends_with("_TOKEN")
            || name.ends_with("_TOKENS")
            || name == "PASSWORD"
            || name.ends_with("_PASSWORD")
            || name.ends_with("_PASS")
            || name == "SECRET"
            || name.ends_with("_SECRET")
            || name.ends_with("_SECRET_KEY")
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

#[cfg(test)]
mod tests {
    use super::is_sensitive_environment_name;
    use std::ffi::OsStr;

    #[test]
    fn identifies_secret_and_agent_environment_names() {
        for name in [
            "AWS_PROFILE",
            "SERVICE_TOKEN",
            "SERVICE_PASSWORD",
            "SERVICE_SECRET_KEY",
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
}
