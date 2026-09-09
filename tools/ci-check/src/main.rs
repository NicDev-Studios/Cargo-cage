#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let require_linux = match parse_args() {
        Ok(require_linux) => require_linux,
        Err(error) => {
            eprintln!("cargo-cage local-check: {error}");
            eprintln!(
                "usage: cargo run --manifest-path tools/ci-check/Cargo.toml -- [--require-linux]"
            );
            std::process::exit(2);
        }
    };

    if let Err(error) = run(require_linux) {
        eprintln!("cargo-cage local-check: FAILED: {error}");
        std::process::exit(1);
    }
}

fn parse_args() -> Result<bool, String> {
    let mut require_linux = false;
    for argument in env::args_os().skip(1) {
        match argument.to_str() {
            Some("--require-linux") => require_linux = true,
            Some("--help") | Some("-h") => {
                println!(
                    "usage: cargo run --manifest-path tools/ci-check/Cargo.toml -- [--require-linux]"
                );
                std::process::exit(0);
            }
            Some(argument) => return Err(format!("unknown option {argument}")),
            None => return Err("arguments must be valid UTF-8".to_owned()),
        }
    }
    Ok(require_linux)
}

fn run(require_linux: bool) -> Result<(), String> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;

    validate_release_workflow(&repo_root)?;

    step(
        &repo_root,
        "format workspace",
        "cargo",
        ["fmt", "--all", "--", "--check"],
    )?;
    step(
        &repo_root,
        "format independent red-team runner",
        "cargo",
        [
            "fmt",
            "--manifest-path",
            "security/redteam/Cargo.toml",
            "--",
            "--check",
        ],
    )?;
    step(
        &repo_root,
        "format local CI runner",
        "cargo",
        [
            "fmt",
            "--manifest-path",
            "tools/ci-check/Cargo.toml",
            "--",
            "--check",
        ],
    )?;
    step(
        &repo_root,
        "fetch locked dependencies",
        "cargo",
        ["fetch", "--locked"],
    )?;
    step(
        &repo_root,
        "clippy workspace",
        "cargo",
        [
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    step(
        &repo_root,
        "clippy local-check runner",
        "cargo",
        [
            "clippy",
            "--manifest-path",
            "tools/ci-check/Cargo.toml",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    step(
        &repo_root,
        "test workspace",
        "cargo",
        ["test", "--workspace", "--locked", "--", "--nocapture"],
    )?;

    if !cfg!(target_os = "linux") {
        run_linux_compile_checks(&repo_root)?;
    }

    if cfg!(target_os = "linux") {
        step(
            &repo_root,
            "doctor",
            "cargo",
            [
                "run",
                "--quiet",
                "--package",
                "cargo-cage",
                "--bin",
                "cargo-cage",
                "--",
                "doctor",
            ],
        )?;
        run_redteam(&repo_root)?;
    } else {
        step(
            &repo_root,
            "clippy independent red-team runner",
            "cargo",
            [
                "clippy",
                "--manifest-path",
                "security/redteam/Cargo.toml",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        )?;
        if require_linux {
            return Err(
                "Linux runtime checks were required, but this host is not Linux; use an Ubuntu VM or runner"
                    .to_owned(),
            );
        }
        eprintln!(
            "cargo-cage local-check: SKIP Linux runtime checks (use --require-linux on Ubuntu)"
        );
    }

    eprintln!("cargo-cage local-check: all applicable checks passed");
    Ok(())
}

fn validate_release_workflow(repo_root: &Path) -> Result<(), String> {
    const AUTH_ACTION: &str =
        "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18";
    const REGISTRY_TOKEN_OUTPUT: &str =
        "CARGO_REGISTRY_TOKEN: ${{ steps.crates_io_auth.outputs.token }}";

    let path = repo_root.join(".github/workflows/release.yml");
    let workflow = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;

    if workflow.contains("secrets.CARGO_REGISTRY_TOKEN") {
        return Err(
            "release workflow still references the long-lived CARGO_REGISTRY_TOKEN secret"
                .to_owned(),
        );
    }
    if workflow.matches("id-token: write").count() != 1 {
        return Err(
            "release workflow must grant id-token: write exactly to the publish job".to_owned(),
        );
    }
    if !workflow.contains(AUTH_ACTION) {
        return Err(format!(
            "release workflow must pin the crates.io auth action to {AUTH_ACTION}"
        ));
    }
    if !workflow.contains(REGISTRY_TOKEN_OUTPUT) {
        return Err(
            "release workflow must pass only the short-lived crates.io auth output to cargo publish"
                .to_owned(),
        );
    }

    let dry_run = workflow
        .find("name: Dry-run packages without registry credentials")
        .ok_or_else(|| {
            "release workflow is missing the credential-free package dry-run".to_owned()
        })?;
    let auth = workflow
        .find("name: Authenticate with crates.io")
        .ok_or_else(|| "release workflow is missing the crates.io OIDC auth step".to_owned())?;
    let publish = workflow
        .find("name: Publish packages in dependency order")
        .ok_or_else(|| "release workflow is missing the publish step".to_owned())?;
    if !(dry_run < auth && auth < publish) {
        return Err(
            "release workflow must dry-run packages before OIDC auth and publish".to_owned(),
        );
    }
    if !workflow.contains("cargo publish --locked --package \"$package\" --dry-run") {
        return Err("release workflow dry-run must use locked Cargo packages".to_owned());
    }
    for package in [
        "cargo-cage-core",
        "cargo-cage-cargo",
        "cargo-cage-linux",
        "cargo-cage",
    ] {
        let upload = format!("cargo publish --locked --package {package} --no-verify");
        if !workflow.contains(&upload) {
            return Err(format!(
                "release workflow is missing the --no-verify upload for {package}"
            ));
        }
    }
    for package in ["cargo-cage-cargo", "cargo-cage-linux", "cargo-cage"] {
        let dry_run = format!("cargo publish --locked --package {package} --dry-run");
        if !workflow.contains(&dry_run) {
            return Err(format!(
                "release workflow is missing the dependency-aware dry-run for {package}"
            ));
        }
    }

    if !workflow.contains("gh api --include") || !workflow.contains("--json isDraft") {
        return Err(
            "release workflow must inspect existing releases before editing or creating them"
                .to_owned(),
        );
    }
    if !workflow.contains("immutable releases must never be edited or moved") {
        return Err(
            "release workflow must fail when the existing release is already published".to_owned(),
        );
    }
    if !workflow.contains("- \"v*.*.*\"") || workflow.contains("- \"v*\"") {
        return Err(
            "release workflow must trigger only on semver-shaped tags, not the moving v1 action tag"
                .to_owned(),
        );
    }

    eprintln!("cargo-cage local-check: release workflow policy: ok");
    Ok(())
}

fn run_linux_compile_checks(repo_root: &Path) -> Result<(), String> {
    const TARGET: &str = "x86_64-unknown-linux-gnu";
    let cargo = rustup_tool("cargo").unwrap_or_else(|| PathBuf::from("cargo"));
    let rustc = rustup_tool("rustc").unwrap_or_else(|| PathBuf::from("rustc"));
    let target_libdir = Command::new(&rustc)
        .args(["--print", "target-libdir", "--target", TARGET])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()));
    if !target_libdir.is_some_and(|path| path.is_dir()) {
        eprintln!(
            "cargo-cage local-check: SKIP Linux compile checks (install with `rustup target add {TARGET}`)"
        );
        return Ok(());
    }

    step_with_rust_toolchain(
        repo_root,
        "compile Linux workspace",
        &cargo,
        [
            "check",
            "--workspace",
            "--target",
            TARGET,
            "--tests",
            "--locked",
        ],
        cargo.parent(),
    )?;
    step_with_rust_toolchain(
        repo_root,
        "clippy Linux workspace",
        &cargo,
        [
            "clippy",
            "--workspace",
            "--target",
            TARGET,
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        cargo.parent(),
    )
}

fn rustup_tool(tool: &str) -> Option<PathBuf> {
    let output = Command::new("rustup")
        .args(["which", tool])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.is_file().then_some(path)
}

fn step_with_rust_toolchain<const N: usize>(
    repo_root: &Path,
    name: &str,
    cargo: &Path,
    args: [&str; N],
    toolchain_bin: Option<&Path>,
) -> Result<(), String> {
    eprintln!("cargo-cage local-check: {name} ...");
    let mut command = Command::new(cargo);
    command.args(args).current_dir(repo_root);
    if let Some(toolchain_bin) = toolchain_bin {
        let existing_path = env::var_os("PATH").unwrap_or_default();
        let path = env::join_paths(
            std::iter::once(toolchain_bin.to_path_buf()).chain(env::split_paths(&existing_path)),
        )
        .map_err(|error| format!("{name}: could not prepare the Rust toolchain PATH: {error}"))?;
        command.env("PATH", path);
    }
    let status = command
        .status()
        .map_err(|error| format!("{name}: could not start {}: {error}", cargo.display()))?;
    if !status.success() {
        return Err(format!(
            "{name}: {} exited with {}",
            cargo.display(),
            status
                .code()
                .map_or_else(|| "a signal".to_owned(), |code| code.to_string())
        ));
    }
    eprintln!("cargo-cage local-check: {name}: ok");
    Ok(())
}

fn run_redteam(repo_root: &Path) -> Result<(), String> {
    step(
        repo_root,
        "clippy independent red-team runner",
        "cargo",
        [
            "clippy",
            "--manifest-path",
            "security/redteam/Cargo.toml",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    step(
        repo_root,
        "build cargo-cage for red-team runner",
        "cargo",
        ["build", "--package", "cargo-cage", "--locked"],
    )?;
    let cargo_cage = repo_root.join("target/debug/cargo-cage");
    let cargo_cage = cargo_cage.to_str().ok_or_else(|| {
        "cargo-cage executable path is not valid UTF-8; use a normal repository path".to_owned()
    })?;
    step(
        repo_root,
        "run independent red-team runner",
        "cargo",
        [
            "run",
            "--manifest-path",
            "security/redteam/Cargo.toml",
            "--locked",
            "--",
            "--cargo-cage",
            cargo_cage,
            "--iterations",
            "64",
        ],
    )
}

fn step<const N: usize>(
    repo_root: &Path,
    name: &str,
    program: &str,
    args: [&str; N],
) -> Result<(), String> {
    eprintln!("cargo-cage local-check: {name} ...");
    let status = Command::new(program)
        .args(args)
        .current_dir(repo_root)
        .status()
        .map_err(|error| format!("{name}: could not start {program}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "{name}: {program} exited with {}",
            status
                .code()
                .map_or_else(|| "a signal".to_owned(), |code| code.to_string())
        ));
    }
    eprintln!("cargo-cage local-check: {name}: ok");
    Ok(())
}
