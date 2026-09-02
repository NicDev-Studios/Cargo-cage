#![forbid(unsafe_code)]

use std::env;
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
