use super::Toolchain;
use cage_core::{Environment, is_allowed_host_environment_name};
use std::env;
use std::ffi::OsString;
use std::path::Path;

pub(super) fn cargo_environment(
    toolchain: &Toolchain,
    current_dir: &Path,
    overrides: Vec<(OsString, OsString)>,
) -> Environment {
    let mut environment = Environment::clean();
    for (key, value) in safe_host_environment() {
        environment = environment.set(key, value);
    }
    environment = environment
        .set("HOME", toolchain.home.clone())
        .set("PATH", toolchain.path.clone())
        .set("PWD", current_dir.as_os_str())
        .set("RUSTC", toolchain.rustc.clone());
    if let Some(rustdoc) = &toolchain.rustdoc {
        environment = environment.set("RUSTDOC", rustdoc.clone());
    }
    for (key, value) in overrides {
        environment = environment.set(key, value);
    }
    environment
}

fn safe_host_environment() -> Vec<(OsString, OsString)> {
    let mut values = Vec::new();
    for (key, value) in env::vars_os() {
        if is_allowed_host_environment_name(&key) {
            values.push((key, value));
        }
    }
    values
}
