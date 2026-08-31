#![forbid(unsafe_code)]

mod args;
mod paths;
mod policy;

use cage_core::{CageError, CageResult, Environment, OutputMode, SandboxBackend, SandboxRequest};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use args::{CargoCommand, CargoInvocation, help_text, is_help_request, parse_invocation};
pub use paths::{inspect_lockfile, prepare_lockfile, prepare_target_dir, validate_target_dir};

const SAFE_ENVIRONMENT_NAMES: &[&str] = &[
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
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
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

const STANDARD_RUNTIME_DIRECTORIES: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
];

#[derive(Clone, Debug)]
struct Toolchain {
    cargo: PathBuf,
    rustc: PathBuf,
    rustdoc: Option<PathBuf>,
    sysroot: PathBuf,
    home: PathBuf,
    path: OsString,
    read_only_paths: Vec<PathBuf>,
}

/// Run the supported Cargo subcommand through the supplied platform backend.
pub fn run<I>(args: I, backend: &dyn SandboxBackend) -> CageResult<i32>
where
    I: IntoIterator<Item = OsString>,
{
    let invocation = parse_invocation(args)?;
    match invocation {
        CargoInvocation::Help => Ok(0),
        CargoInvocation::Doctor { verbose } => run_doctor(verbose, backend),
        CargoInvocation::Cargo { command, args } => run_cargo(command, args, backend),
    }
}

fn run_cargo(
    command: CargoCommand,
    cargo_args: Vec<OsString>,
    backend: &dyn SandboxBackend,
) -> CageResult<i32> {
    let current_dir = canonical_current_dir()?;
    let cargo = resolve_cargo(&current_dir)?;
    let toolchain = resolve_toolchain(&cargo, &current_dir, command == CargoCommand::Doc)?;
    let workspace = locate_workspace(&toolchain, &current_dir, &cargo_args, backend)?;
    let target_dir = paths::target_dir_arg(&cargo_args, &current_dir, &workspace)?;
    let target_dir = prepare_target_dir(target_dir, &workspace)?;
    let build_dir = prepare_target_dir(target_dir.join("build"), &workspace)?;
    let lockfile = prepare_lockfile(&workspace)?;
    let sandbox_current_dir = sandbox_current_dir(&current_dir, &workspace, &cargo_args)?;
    let cargo_args =
        rewrite_relative_cargo_paths(&cargo_args, &current_dir, &sandbox_current_dir, &target_dir)?;

    let mut sandbox_policy = policy::cargo_policy(true)?;
    sandbox_policy.read_only_paths.push(workspace.clone());
    if current_dir != workspace && current_dir.starts_with(&workspace) {
        sandbox_policy.read_only_paths.push(current_dir.clone());
    }
    sandbox_policy
        .read_only_paths
        .extend(toolchain.read_only_paths.iter().cloned());
    sandbox_policy.writable_paths.push(target_dir.clone());
    sandbox_policy.writable_paths.push(lockfile.clone());

    let mut command_args = Vec::with_capacity(cargo_args.len() + 1);
    command_args.push(OsString::from(command.as_str()));
    command_args.extend(cargo_args);

    let mut request = SandboxRequest::new(&toolchain.cargo, &sandbox_current_dir);
    request.args = command_args;
    request.policy = sandbox_policy;
    request.environment = cargo_environment(
        &toolchain,
        &sandbox_current_dir,
        vec![
            (
                OsString::from("CARGO_TARGET_DIR"),
                target_dir.clone().into_os_string(),
            ),
            (
                OsString::from("CARGO_BUILD_BUILD_DIR"),
                build_dir.into_os_string(),
            ),
            (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
            (OsString::from("TMPDIR"), OsString::from("/tmp")),
        ],
    );
    request.output = OutputMode::Inherit;

    let outcome = backend.run(&request)?;
    if outcome.status.successfully_exited() {
        return Ok(0);
    }

    eprintln!(
        "cargo-cage: Cargo {} failed inside the Linux sandbox (exit code {}).",
        command.as_str(),
        outcome
            .status
            .code
            .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
    );
    eprintln!(
        "cargo-cage: policy active: clean allowlisted environment, private HOME, network denied, and persistent writes limited to {} and {}.",
        target_dir.display(),
        lockfile.display()
    );
    eprintln!(
        "cargo-cage: a Cargo/build-script error such as Permission denied, Read-only file system, or Network is unreachable may indicate a denied operation; missing dependencies must be fetched separately with `cargo fetch`."
    );

    Ok(outcome.status.code.unwrap_or(1))
}

fn run_doctor(verbose: bool, backend: &dyn SandboxBackend) -> CageResult<i32> {
    println!("cargo-cage doctor");
    let mut failed = false;

    let current_dir = match canonical_current_dir() {
        Ok(path) => {
            println!("  OK   current directory: {}", path.display());
            path
        }
        Err(error) => {
            println!("  FAIL current directory: {error}");
            return Ok(1);
        }
    };

    let cargo = match resolve_cargo(&current_dir) {
        Ok(path) => {
            println!("  OK   Cargo executable: {}", path.display());
            path
        }
        Err(error) => {
            println!("  FAIL Cargo executable: {error}");
            return Ok(1);
        }
    };

    let toolchain = match resolve_toolchain(&cargo, &current_dir, true) {
        Ok(toolchain) => {
            println!("  OK   Rust toolchain: {}", toolchain.sysroot.display());
            println!("  OK   sandbox environment: clean allowlist");
            println!("  OK   home directory: private mount");
            println!("  OK   runtime filesystem: explicit read-only mounts");
            toolchain
        }
        Err(error) => {
            println!("  FAIL Rust toolchain: {error}");
            return Ok(1);
        }
    };

    let workspace = match locate_workspace(&toolchain, &current_dir, &[], backend) {
        Ok(path) => {
            println!("  OK   workspace: {}", path.display());
            path
        }
        Err(error) => {
            println!("  FAIL workspace discovery: {error}");
            return Ok(1);
        }
    };

    let target = match paths::target_dir_arg(&[], &current_dir, &workspace) {
        Ok(path) => match paths::validate_target_dir(&path, &workspace) {
            Ok(path) => {
                let exists = fs::symlink_metadata(&path).is_ok();
                if exists {
                    println!("  OK   target directory: {}", path.display());
                } else {
                    println!(
                        "  WARN target directory: {} (will be created by the build)",
                        path.display()
                    );
                }
                Some((path, exists))
            }
            Err(error) => {
                println!("  FAIL target directory: {error}");
                failed = true;
                None
            }
        },
        Err(error) => {
            println!("  FAIL target directory: {error}");
            failed = true;
            None
        }
    };

    if let Some((target, _)) = target.as_ref() {
        match paths::validate_target_dir(&target.join("build"), &workspace) {
            Ok(build_dir) if fs::symlink_metadata(&build_dir).is_ok() => {
                println!("  OK   target build directory: {}", build_dir.display())
            }
            Ok(build_dir) => println!(
                "  WARN target build directory: {} (will be created by the build)",
                build_dir.display()
            ),
            Err(error) => {
                println!("  FAIL target build directory: {error}");
                failed = true;
            }
        }
    }

    let lockfile = workspace.join("Cargo.lock");
    let lockfile_present = match paths::inspect_lockfile(&workspace) {
        Ok(true) => {
            println!("  OK   workspace lockfile: {}", lockfile.display());
            true
        }
        Ok(false) => {
            println!(
                "  WARN workspace lockfile: {} (will be created by the build)",
                lockfile.display()
            );
            false
        }
        Err(error) => {
            println!("  FAIL workspace lockfile: {error}");
            failed = true;
            false
        }
    };

    if cargo_cache_present() {
        println!("  OK   Cargo registry/Git cache roots are present");
    } else {
        println!(
            "  WARN Cargo registry/Git caches are missing; offline builds may need `cargo fetch`"
        );
    }

    println!("  OK   Cargo configuration is intentionally not mounted");
    println!("  OK   network access denied; persistent writes limited to target and Cargo.lock");

    let policy = match policy::cargo_policy(true) {
        Ok(mut policy) => {
            policy.read_only_paths.push(workspace.clone());
            if current_dir != workspace {
                policy.read_only_paths.push(current_dir.clone());
            }
            policy
                .read_only_paths
                .extend(toolchain.read_only_paths.iter().cloned());
            if let Some((target, true)) = target.as_ref() {
                policy.writable_paths.push(target.clone());
            }
            if lockfile_present {
                policy.writable_paths.push(lockfile.clone());
            }
            Some(policy)
        }
        Err(error) => {
            println!("  FAIL sandbox policy: {error}");
            failed = true;
            None
        }
    };

    if let Some(policy) = policy {
        let mut probe = SandboxRequest::new("/bin/sh", &current_dir);
        probe.args = vec![OsString::from("-c"), OsString::from("exit 0")];
        probe.policy = policy;
        probe.environment = cargo_environment(
            &toolchain,
            &current_dir,
            vec![
                (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
                (OsString::from("TMPDIR"), OsString::from("/tmp")),
            ],
        );
        probe.output = OutputMode::Capture;
        match backend.run(&probe) {
            Ok(outcome) if outcome.status.successfully_exited() => {
                println!("  OK   Bubblewrap namespaces and sandbox preflight");
            }
            Ok(outcome) => {
                println!(
                    "  FAIL Bubblewrap sandbox probe: process exited with {:?}",
                    outcome.status.code
                );
                failed = true;
            }
            Err(error) => {
                println!("  FAIL Bubblewrap sandbox probe: {error}");
                failed = true;
            }
        }
    }

    if verbose {
        println!("  INFO no automatic dependency fetch is performed");
        println!("  INFO generated artifacts under target are not trusted automatically");
        println!("  INFO path checks are not race-free against concurrent host changes");
    }

    if failed {
        println!("doctor: one or more checks failed");
        Ok(1)
    } else {
        println!("doctor: environment is ready for an offline sandboxed Cargo command");
        Ok(0)
    }
}

fn canonical_current_dir() -> CageResult<PathBuf> {
    fs::canonicalize(
        env::current_dir()
            .map_err(|error| CageError::io("could not determine the current directory", error))?,
    )
    .map_err(|error| CageError::io("could not canonicalize the current directory", error))
}

fn cargo_cache_present() -> bool {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let Some(cargo_home) = cargo_home else {
        return false;
    };

    ["registry", "git"].into_iter().any(|name| {
        fs::symlink_metadata(cargo_home.join(name)).is_ok_and(|metadata| metadata.is_dir())
    })
}

fn locate_workspace(
    toolchain: &Toolchain,
    current_dir: &Path,
    cargo_args: &[OsString],
    backend: &dyn SandboxBackend,
) -> CageResult<PathBuf> {
    let mut locate_request = SandboxRequest::new(&toolchain.cargo, current_dir);
    locate_request.args.push(OsString::from("locate-project"));
    locate_request.args.push(OsString::from("--workspace"));
    locate_request.args.push(OsString::from("--message-format"));
    locate_request.args.push(OsString::from("plain"));
    if let Some(manifest_path) = paths::manifest_path_arg(cargo_args)? {
        locate_request.args.push(OsString::from("--manifest-path"));
        locate_request.args.push(manifest_path);
    }
    let mut policy = policy::cargo_policy(false)?;
    policy.read_only_paths.push(current_dir.to_path_buf());
    if let Some(manifest_parent) = manifest_parent_path(cargo_args, current_dir)? {
        policy.read_only_paths.push(manifest_parent);
    }
    policy
        .read_only_paths
        .extend(toolchain.read_only_paths.iter().cloned());
    locate_request.policy = policy;
    locate_request.environment = cargo_environment(toolchain, current_dir, Vec::new());
    locate_request.output = OutputMode::Capture;

    let locate_outcome = backend.run(&locate_request)?;
    if !locate_outcome.status.successfully_exited() {
        let detail = output_detail(&locate_outcome.stderr);
        return Err(CageError::ProcessFailed {
            status: locate_outcome.status,
            detail: format!("Cargo workspace discovery failed{detail}"),
        });
    }

    workspace_from_output(&locate_outcome.stdout, current_dir)
}

fn cargo_environment(
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
        if is_safe_environment_name(&key) {
            values.push((key, value));
        }
    }
    values
}

fn is_safe_environment_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| SAFE_ENVIRONMENT_NAMES.contains(&name))
}

fn manifest_parent_path(args: &[OsString], current_dir: &Path) -> CageResult<Option<PathBuf>> {
    let Some(manifest) = resolved_manifest_path(args, current_dir)? else {
        return Ok(None);
    };
    if !fs::metadata(&manifest).is_ok_and(|metadata| metadata.is_file()) {
        return Err(CageError::policy(
            manifest.display().to_string(),
            "the manifest path must be a regular file",
            "pass an existing real Cargo.toml path",
        ));
    }
    Ok(manifest.parent().map(Path::to_path_buf))
}

fn resolved_manifest_path(args: &[OsString], current_dir: &Path) -> CageResult<Option<PathBuf>> {
    let Some(value) = paths::manifest_path_arg(args)? else {
        return Ok(None);
    };
    let manifest = PathBuf::from(value);
    let manifest = if manifest.is_absolute() {
        manifest
    } else {
        current_dir.join(manifest)
    };
    Ok(Some(canonical_existing_path_without_symlinks(
        &manifest,
        "manifest path",
    )?))
}

fn sandbox_current_dir(
    current_dir: &Path,
    workspace: &Path,
    cargo_args: &[OsString],
) -> CageResult<PathBuf> {
    if current_dir == workspace || current_dir.starts_with(workspace) {
        return Ok(current_dir.to_path_buf());
    }

    if let Some(manifest_parent) = manifest_parent_path(cargo_args, current_dir)? {
        if manifest_parent == workspace || manifest_parent.starts_with(workspace) {
            return Ok(manifest_parent);
        }
    }
    Ok(workspace.to_path_buf())
}

fn rewrite_relative_cargo_paths(
    args: &[OsString],
    current_dir: &Path,
    sandbox_current_dir: &Path,
    target_dir: &Path,
) -> CageResult<Vec<OsString>> {
    if current_dir == sandbox_current_dir {
        return Ok(args.to_vec());
    }

    let mut rewritten = args.to_vec();
    let mut index = 0;
    while index < rewritten.len() {
        if rewritten[index] == OsStr::new("--") {
            break;
        }
        if rewritten[index] == OsStr::new("--manifest-path") {
            if let Some(value) = rewritten.get_mut(index + 1) {
                let path = PathBuf::from(&*value);
                if !path.is_absolute() {
                    *value = resolved_manifest_path(args, current_dir)
                        .and_then(|manifest| {
                            manifest.ok_or_else(|| {
                                CageError::InvalidInvocation(
                                    "--manifest-path needs a value".to_owned(),
                                )
                            })
                        })?
                        .into_os_string();
                }
            }
            index += 2;
            continue;
        }
        if let Some(value) = rewritten[index]
            .to_str()
            .and_then(|arg| arg.strip_prefix("--manifest-path="))
        {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                let manifest = resolved_manifest_path(args, current_dir)?.ok_or_else(|| {
                    CageError::InvalidInvocation("--manifest-path needs a value".to_owned())
                })?;
                rewritten[index] = OsString::from("--manifest-path=");
                rewritten[index].push(manifest.into_os_string());
            }
        }
        if rewritten[index] == OsStr::new("--target-dir") {
            if let Some(value) = rewritten.get_mut(index + 1) {
                let path = PathBuf::from(&*value);
                if !path.is_absolute() {
                    *value = target_dir.as_os_str().to_os_string();
                }
            }
            index += 2;
            continue;
        }
        if rewritten[index]
            .to_str()
            .is_some_and(|arg| arg.starts_with("--target-dir=") && arg.len() > 13)
        {
            let value = rewritten[index]
                .to_str()
                .expect("checked UTF-8 target-dir argument")
                .strip_prefix("--target-dir=")
                .expect("checked target-dir argument");
            if !Path::new(value).is_absolute() {
                rewritten[index] = OsString::from("--target-dir=");
                rewritten[index].push(target_dir.as_os_str());
            }
        }
        index += 1;
    }
    Ok(rewritten)
}

fn resolve_toolchain(
    cargo: &Path,
    current_dir: &Path,
    require_rustdoc: bool,
) -> CageResult<Toolchain> {
    let home = canonical_home()?;
    let host_rustc = resolve_program("rustc", "RUSTC", current_dir)?;
    let rustc_for_toolchain = resolve_rustup_rustc(&host_rustc, &home, current_dir)?;
    let sysroot = query_sysroot(&rustc_for_toolchain, &home, current_dir)?;
    let sysroot_bin = sysroot.join("bin");

    let rustc = select_toolchain_program("rustc", &rustc_for_toolchain, &sysroot_bin, true)?;
    let rustdoc = if sysroot_bin.join("rustdoc").is_file() {
        Some(select_toolchain_program(
            "rustdoc",
            &sysroot_bin.join("rustdoc"),
            &sysroot_bin,
            true,
        )?)
    } else if require_rustdoc {
        let host_rustdoc = resolve_program("rustdoc", "RUSTDOC", current_dir)?;
        Some(select_toolchain_program(
            "rustdoc",
            &host_rustdoc,
            &sysroot_bin,
            true,
        )?)
    } else {
        None
    };

    let cargo = if is_rustup_proxy(cargo) {
        select_toolchain_program("cargo", cargo, &sysroot_bin, true)?
    } else {
        cargo.to_path_buf()
    };

    let (path, path_directories) = sandbox_path(
        &home,
        current_dir,
        [&cargo, &rustc].into_iter().chain(rustdoc.as_ref()),
    )?;
    let mut read_only_paths = toolchain_mount_paths(
        &sysroot,
        [&cargo, &rustc].into_iter().chain(rustdoc.as_ref()),
    )?;
    for directory in path_directories {
        if !is_standard_runtime_path(&directory) && !read_only_paths.contains(&directory) {
            read_only_paths.push(directory);
        }
    }

    Ok(Toolchain {
        cargo,
        rustc,
        rustdoc,
        sysroot,
        home,
        path,
        read_only_paths,
    })
}

fn canonical_home() -> CageResult<PathBuf> {
    let home = env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        CageError::policy(
            "HOME",
            "HOME must be set to construct the sandbox environment",
            "set HOME to an absolute user home directory before running cargo-cage",
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
    let metadata = fs::symlink_metadata(&home).map_err(|error| {
        CageError::io(
            format!("could not inspect home directory {}", home.display()),
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CageError::policy(
            home.display().to_string(),
            "HOME must be an existing real directory without symlink resolution",
            "set HOME to an existing real user home directory",
        ));
    }
    canonical_existing_path_without_symlinks(&home, "home directory")
}

fn select_toolchain_program(
    name: &str,
    fallback: &Path,
    sysroot_bin: &Path,
    required: bool,
) -> CageResult<PathBuf> {
    let candidate = sysroot_bin.join(name);
    if candidate.is_file() {
        validate_executable_path(candidate)
    } else if required && is_rustup_proxy(fallback) {
        Err(CageError::BackendUnavailable(format!(
            "the selected Rust sysroot has no {name} executable; install the complete Rust toolchain or select a system toolchain"
        )))
    } else if required {
        validate_executable_path(fallback.to_path_buf())
    } else {
        Ok(fallback.to_path_buf())
    }
}

fn resolve_rustup_rustc(host_rustc: &Path, home: &Path, current_dir: &Path) -> CageResult<PathBuf> {
    if !is_rustup_proxy(host_rustc) {
        return Ok(host_rustc.to_path_buf());
    }

    let rustup = fs::canonicalize(host_rustc).map_err(|error| {
        CageError::io(
            format!(
                "could not resolve the rustup executable {}",
                host_rustc.display()
            ),
            error,
        )
    })?;
    let rustup_home = canonical_rustup_home(home)?;
    let mut command = Command::new(&rustup);
    command
        .env_clear()
        .env("HOME", home)
        .env("RUSTUP_HOME", &rustup_home)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .current_dir(current_dir)
        .args(["which", "rustc"]);
    if let Some(rustup_toolchain) = env::var_os("RUSTUP_TOOLCHAIN") {
        command.env("RUSTUP_TOOLCHAIN", rustup_toolchain);
    }
    let output = command.output().map_err(|source| CageError::ProcessSpawn {
        program: rustup.clone(),
        source,
    })?;
    if !output.status.success() {
        return Err(CageError::BackendUnavailable(format!(
            "rustup could not resolve a preinstalled rustc{}; install the selected toolchain before running cargo-cage",
            output_detail(&output.stderr),
        )));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let value = text.trim();
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(CageError::BackendUnavailable(
            "rustup returned an invalid rustc path; select a preinstalled Rust toolchain"
                .to_owned(),
        ));
    }
    let compiler =
        canonical_existing_path_without_symlinks(Path::new(value), "Rustup-selected rustc")?;
    if !fs::metadata(&compiler).is_ok_and(|metadata| metadata.is_file()) {
        return Err(CageError::policy(
            compiler.display().to_string(),
            "the Rustup-selected compiler must be a regular file",
            "install a complete preinstalled Rust toolchain and retry",
        ));
    }
    let toolchains = rustup_home.join("toolchains");
    if !is_trusted_rustup_compiler(&compiler, &toolchains) {
        return Err(CageError::policy(
            compiler.display().to_string(),
            "a project Rust toolchain must resolve inside the trusted Rustup toolchains or system runtime",
            "remove the project path override and select an installed toolchain under RUSTUP_HOME",
        ));
    }
    Ok(compiler)
}

fn canonical_rustup_home(home: &Path) -> CageResult<PathBuf> {
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".rustup"));
    if !rustup_home.is_absolute() {
        return Err(CageError::policy(
            rustup_home.display().to_string(),
            "RUSTUP_HOME must be an absolute path",
            "set RUSTUP_HOME to the absolute path of a real Rustup directory",
        ));
    }
    if rustup_home == Path::new(std::path::MAIN_SEPARATOR_STR) {
        return Err(CageError::policy(
            rustup_home.display().to_string(),
            "RUSTUP_HOME must not be the filesystem root",
            "set RUSTUP_HOME to a real Rustup directory",
        ));
    }
    let metadata = fs::symlink_metadata(&rustup_home).map_err(|error| {
        CageError::io(
            format!("could not inspect Rustup home {}", rustup_home.display()),
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CageError::policy(
            rustup_home.display().to_string(),
            "RUSTUP_HOME must be an existing real directory without symlink resolution",
            "set RUSTUP_HOME to an existing real Rustup directory",
        ));
    }
    canonical_existing_path_without_symlinks(&rustup_home, "Rustup home")
}

fn is_trusted_rustup_compiler(path: &Path, toolchains: &Path) -> bool {
    is_standard_runtime_path(path) || path.starts_with(toolchains)
}

fn query_sysroot(rustc: &Path, home: &Path, current_dir: &Path) -> CageResult<PathBuf> {
    let mut command = Command::new(rustc);
    command
        .env_clear()
        .env("HOME", home)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .current_dir(current_dir)
        .args(["--print", "sysroot"]);
    if let Some(rustup_home) = env::var_os("RUSTUP_HOME") {
        command.env("RUSTUP_HOME", rustup_home);
    }
    if let Some(rustup_toolchain) = env::var_os("RUSTUP_TOOLCHAIN") {
        command.env("RUSTUP_TOOLCHAIN", rustup_toolchain);
    }
    let output = command.output().map_err(|source| CageError::ProcessSpawn {
        program: rustc.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return Err(CageError::BackendUnavailable(format!(
            "{} --print sysroot failed with {:?}; install or select a working Rust toolchain",
            rustc.display(),
            output.status.code(),
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text.trim();
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(CageError::BackendUnavailable(
            "Rust returned an invalid sysroot path; select a working Rust toolchain".to_owned(),
        ));
    }
    let sysroot = PathBuf::from(value);
    if !sysroot.is_absolute() {
        return Err(CageError::BackendUnavailable(format!(
            "Rust returned a relative sysroot {}; select a working Rust toolchain",
            sysroot.display()
        )));
    }
    let sysroot = canonical_existing_path_without_symlinks(&sysroot, "Rust sysroot")?;
    if !fs::metadata(&sysroot).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(CageError::BackendUnavailable(format!(
            "Rust sysroot {} is not a directory; select a working Rust toolchain",
            sysroot.display()
        )));
    }
    Ok(sysroot)
}

fn is_rustup_proxy(path: &Path) -> bool {
    fs::canonicalize(path)
        .ok()
        .and_then(|path| path.file_name().map(|name| name == OsStr::new("rustup")))
        .unwrap_or(false)
}

fn toolchain_mount_paths<I>(sysroot: &Path, executables: I) -> CageResult<Vec<PathBuf>>
where
    I: IntoIterator,
    I::Item: AsRef<Path>,
{
    let mut paths = Vec::new();
    if sysroot != Path::new(std::path::MAIN_SEPARATOR_STR) {
        paths.push(sysroot.to_path_buf());
    }
    for executable in executables {
        let executable = executable.as_ref();
        let parent = executable.parent().ok_or_else(|| {
            CageError::BackendUnavailable(format!(
                "toolchain executable {} has no parent directory",
                executable.display()
            ))
        })?;
        let parent = fs::canonicalize(parent).map_err(|error| {
            CageError::io(
                format!(
                    "could not canonicalize toolchain directory {}",
                    parent.display()
                ),
                error,
            )
        })?;
        if !fs::metadata(&parent).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(CageError::BackendUnavailable(format!(
                "toolchain path {} is not a directory; select a working Rust toolchain",
                parent.display()
            )));
        }
        if parent != Path::new(std::path::MAIN_SEPARATOR_STR)
            && !is_standard_runtime_path(&parent)
            && !paths.contains(&parent)
        {
            paths.push(parent);
        }
    }
    Ok(paths)
}

fn sandbox_path<I>(
    home: &Path,
    current_dir: &Path,
    executables: I,
) -> CageResult<(OsString, Vec<PathBuf>)>
where
    I: IntoIterator,
    I::Item: AsRef<Path>,
{
    let required_directories = executables
        .into_iter()
        .filter_map(|executable| executable.as_ref().parent().map(Path::to_path_buf))
        .filter_map(|path| {
            let path = if path.is_absolute() {
                path
            } else {
                current_dir.join(path)
            };
            fs::canonicalize(path).ok()
        })
        .collect::<Vec<_>>();
    let mut paths = required_directories.clone();
    for runtime in STANDARD_RUNTIME_DIRECTORIES {
        let Ok(runtime) = fs::canonicalize(runtime) else {
            continue;
        };
        if fs::metadata(&runtime).is_ok_and(|metadata| metadata.is_dir())
            && !paths.contains(&runtime)
        {
            paths.push(runtime);
        }
    }
    if let Some(host_path) = env::var_os("PATH") {
        for path in env::split_paths(&host_path) {
            let path = if path.is_absolute() {
                path
            } else {
                current_dir.join(path)
            };
            let Ok(path) = fs::canonicalize(path) else {
                continue;
            };
            if !fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
                continue;
            }
            if is_private_host_path(&path, home) && !required_directories.contains(&path) {
                continue;
            }
            if !is_standard_runtime_path(&path) && !required_directories.contains(&path) {
                continue;
            }
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    if paths.is_empty() {
        return Err(CageError::BackendUnavailable(
            "could not construct a safe PATH for the Rust toolchain; set PATH to existing toolchain directories"
                .to_owned(),
        ));
    }
    let path = env::join_paths(paths.clone()).map_err(|error| {
        CageError::BackendUnavailable(format!(
            "could not construct a safe toolchain PATH: {error}"
        ))
    })?;
    Ok((path, paths))
}

fn is_private_host_path(path: &Path, home: &Path) -> bool {
    path.starts_with(home)
        || ["/tmp", "/var/tmp", "/run"].iter().any(|private| {
            let private = Path::new(private);
            path == private || path.starts_with(private)
        })
}

fn is_standard_runtime_path(path: &Path) -> bool {
    STANDARD_RUNTIME_DIRECTORIES
        .iter()
        .map(Path::new)
        .any(|runtime| path == runtime || path.starts_with(runtime))
}

fn resolve_cargo(current_dir: &Path) -> CageResult<PathBuf> {
    resolve_program("cargo", "CARGO", current_dir)
}

fn resolve_program(name: &str, variable: &str, current_dir: &Path) -> CageResult<PathBuf> {
    let requested = env::var_os(variable).unwrap_or_else(|| OsString::from(name));
    let requested_path = PathBuf::from(requested);

    if requested_path.is_absolute() || requested_path.components().count() > 1 {
        let path = if requested_path.is_absolute() {
            requested_path
        } else {
            current_dir.join(requested_path)
        };
        return validate_executable_path(path);
    }

    let path = env::var_os("PATH").ok_or_else(|| {
        CageError::BackendUnavailable(
            format!(
                "{variable} is not set and PATH is unavailable; set PATH or {variable} to a trusted {name} executable"
            ),
        )
    })?;
    for directory in env::split_paths(&path) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            current_dir.join(directory)
        };
        let candidate = directory.join(&requested_path);
        if candidate.is_file() {
            return validate_executable_path(candidate);
        }
    }

    Err(CageError::BackendUnavailable(format!(
        "could not find {name} executable `{}`; install {name} or set {variable} to a trusted executable",
        requested_path.display(),
    )))
}

fn validate_executable_path(path: PathBuf) -> CageResult<PathBuf> {
    let canonical = fs::canonicalize(&path).map_err(|error| {
        CageError::io(
            format!("could not resolve executable {}", path.display()),
            error,
        )
    })?;
    if !fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file()) {
        return Err(CageError::BackendUnavailable(format!(
            "executable {} is not a regular file; select a trusted executable",
            path.display(),
        )));
    }
    // Rustup dispatches based on argv[0]. Preserve a rustup proxy path so
    // `rustc` and `cargo` keep their proxy names; the selected sysroot
    // executable is resolved before the sandbox is started.
    if canonical.file_name() == Some(OsStr::new("rustup")) {
        Ok(path)
    } else {
        Ok(canonical)
    }
}

fn workspace_from_output(output: &[u8], current_dir: &Path) -> CageResult<PathBuf> {
    let output = String::from_utf8_lossy(output);
    let manifest = output.trim();
    if manifest.is_empty() || manifest.contains('\n') || manifest.contains('\r') {
        return Err(CageError::SandboxSetup(
            "Cargo returned an invalid workspace manifest path; verify the manifest and rerun the build"
                .to_owned(),
        ));
    }

    let manifest = PathBuf::from(manifest);
    let manifest = if manifest.is_absolute() {
        manifest
    } else {
        current_dir.join(manifest)
    };
    let manifest = canonical_existing_path_without_symlinks(&manifest, "workspace manifest")?;
    if !fs::metadata(&manifest).is_ok_and(|metadata| metadata.is_file()) {
        return Err(CageError::policy(
            manifest.display().to_string(),
            "workspace discovery must return a regular Cargo.toml file",
            "run cargo-cage from a workspace with a real Cargo.toml manifest",
        ));
    }
    if manifest.file_name() != Some(OsStr::new("Cargo.toml")) {
        return Err(CageError::policy(
            manifest.display().to_string(),
            "workspace discovery must return a Cargo.toml path",
            "run cargo-cage from a Cargo workspace or pass a valid --manifest-path",
        ));
    }
    manifest.parent().map(Path::to_path_buf).ok_or_else(|| {
        CageError::policy(
            manifest.display().to_string(),
            "the workspace manifest must have a parent directory",
            "use a valid Cargo workspace manifest path",
        )
    })
}

fn canonical_existing_path_without_symlinks(path: &Path, label: &str) -> CageResult<PathBuf> {
    if !path.is_absolute() {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("the {label} must be an absolute path"),
            "pass an absolute path or run cargo-cage from the intended workspace",
        ));
    }
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("the {label} must not contain parent-directory traversal"),
            "pass the canonical path without `..` components",
        ));
    }

    let mut current = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            CageError::io(
                format!("could not inspect {label} component {}", current.display()),
                error,
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CageError::policy(
                path.display().to_string(),
                format!("the {label} must not contain symlink components"),
                "replace the symlink with a real path and retry",
            ));
        }
        if components.peek().is_some() && !metadata.is_dir() {
            return Err(CageError::policy(
                current.display().to_string(),
                format!("{label} parent components must be directories"),
                "replace the conflicting file with a directory and retry",
            ));
        }
    }

    fs::canonicalize(path).map_err(|error| {
        CageError::io(
            format!("could not canonicalize {label} {}", path.display()),
            error,
        )
    })
}

fn output_detail(output: &[u8]) -> String {
    if output.is_empty() {
        return String::new();
    }
    let text = String::from_utf8_lossy(output);
    let text = text.trim();
    if text.is_empty() {
        String::new()
    } else {
        format!(": {}", text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cage_core::{ProcessStatus, SandboxOutcome};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_WORKSPACE_ID: AtomicU64 = AtomicU64::new(0);

    struct RecordingBackend {
        workspace: PathBuf,
        second_status: ProcessStatus,
        calls: RefCell<Vec<SandboxRequest>>,
    }

    impl SandboxBackend for RecordingBackend {
        fn run(&self, request: &SandboxRequest) -> CageResult<SandboxOutcome> {
            let call_number = self.calls.borrow().len();
            self.calls.borrow_mut().push(request.clone());
            if call_number == 0 {
                Ok(SandboxOutcome {
                    status: ProcessStatus::success(),
                    stdout: format!("{}\n", self.workspace.join("Cargo.toml").display()).into(),
                    stderr: Vec::new(),
                })
            } else {
                Ok(SandboxOutcome {
                    status: self.second_status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
        }
    }

    struct TestWorkspace(PathBuf);

    impl TestWorkspace {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let id = NEXT_TEST_WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!("cargo-cage-integration-test-{suffix}-{id}"));
            fs::create_dir(&path).expect("create test workspace");
            fs::write(
                path.join("Cargo.toml"),
                "[package]\nname = \"cargo-cage-test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .expect("write test manifest");
            Self(path)
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn forwards_build_arguments_and_returns_cargo_exit_code() {
        let workspace = TestWorkspace::new();
        let workspace = fs::canonicalize(&workspace.0).expect("canonical test workspace");
        let manifest = workspace.join("Cargo.toml");
        let target = workspace.join("target");
        let backend = RecordingBackend {
            workspace: workspace.clone(),
            second_status: ProcessStatus { code: Some(23) },
            calls: RefCell::new(Vec::new()),
        };

        let code = run(
            [
                OsString::from("build"),
                OsString::from("--release"),
                OsString::from("--manifest-path"),
                manifest.clone().into_os_string(),
                OsString::from("--target-dir"),
                target.clone().into_os_string(),
            ],
            &backend,
        )
        .expect("Cargo run result");

        assert_eq!(code, 23);
        let calls = backend.calls.into_inner();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].args[0], OsString::from("build"));
        assert_eq!(calls[1].args[1], OsString::from("--release"));
        assert_eq!(calls[1].args[2], OsString::from("--manifest-path"));
        assert_eq!(calls[1].args[3], manifest.into_os_string());
        assert_eq!(calls[1].args[4], OsString::from("--target-dir"));
        assert_eq!(calls[1].args[5], target.into_os_string());
        assert!(workspace.join("Cargo.lock").is_file());
    }

    #[test]
    fn forwards_all_supported_commands_and_returns_exit_codes() {
        for command in [
            CargoCommand::Build,
            CargoCommand::Check,
            CargoCommand::Test,
            CargoCommand::Doc,
        ] {
            let workspace = TestWorkspace::new();
            let workspace = fs::canonicalize(&workspace.0).expect("canonical test workspace");
            let manifest = workspace.join("Cargo.toml");
            let target = workspace.join("target");
            let backend = RecordingBackend {
                workspace: workspace.clone(),
                second_status: ProcessStatus { code: Some(23) },
                calls: RefCell::new(Vec::new()),
            };

            let code = run(
                [
                    OsString::from(command.as_str()),
                    OsString::from("--manifest-path"),
                    manifest.into_os_string(),
                    OsString::from("--target-dir"),
                    target.into_os_string(),
                ],
                &backend,
            )
            .expect("Cargo run result");

            assert_eq!(code, 23);
            let calls = backend.calls.into_inner();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[1].args[0], OsString::from(command.as_str()));
        }
    }

    #[test]
    fn narrows_external_working_directory_and_rewrites_relative_paths() {
        let workspace = TestWorkspace::new();
        let workspace = fs::canonicalize(&workspace.0).expect("canonical test workspace");
        let current_dir = workspace.parent().expect("workspace parent");
        let relative_workspace = PathBuf::from(workspace.file_name().expect("workspace name"));
        let relative_manifest = relative_workspace.join("Cargo.toml");
        let relative_target = relative_workspace.join("target");
        let sandbox_dir = sandbox_current_dir(
            current_dir,
            &workspace,
            &[
                OsString::from("--manifest-path"),
                relative_manifest.clone().into_os_string(),
            ],
        )
        .expect("safe sandbox working directory");
        assert_eq!(sandbox_dir, workspace);

        let target = workspace.join("target");
        let rewritten = rewrite_relative_cargo_paths(
            &[
                OsString::from("--manifest-path"),
                relative_manifest.into_os_string(),
                OsString::from("--target-dir"),
                relative_target.into_os_string(),
            ],
            current_dir,
            &sandbox_dir,
            &target,
        )
        .expect("rewrite safe relative paths");
        assert_eq!(rewritten[1], workspace.join("Cargo.toml").into_os_string());
        assert_eq!(rewritten[3], target.into_os_string());
    }

    #[test]
    fn doctor_returns_success_when_the_sandbox_probe_succeeds() {
        let workspace = TestWorkspace::new();
        let workspace = fs::canonicalize(&workspace.0).expect("canonical test workspace");
        let backend = RecordingBackend {
            workspace: workspace.clone(),
            second_status: ProcessStatus::success(),
            calls: RefCell::new(Vec::new()),
        };

        let code = run([OsString::from("doctor")], &backend).expect("doctor result");

        assert_eq!(code, 0);
        assert_eq!(backend.calls.borrow().len(), 2);
        assert!(!workspace.join("Cargo.lock").exists());
        assert!(!workspace.join("target").exists());
    }

    #[test]
    fn doctor_returns_one_when_the_sandbox_probe_fails() {
        let workspace = TestWorkspace::new();
        let workspace = fs::canonicalize(&workspace.0).expect("canonical test workspace");
        let backend = RecordingBackend {
            workspace: workspace.clone(),
            second_status: ProcessStatus { code: Some(23) },
            calls: RefCell::new(Vec::new()),
        };

        let code = run([OsString::from("doctor")], &backend).expect("doctor result");

        assert_eq!(code, 1);
        assert_eq!(backend.calls.borrow().len(), 2);
        assert!(!workspace.join("Cargo.lock").exists());
        assert!(!workspace.join("target").exists());
    }

    #[test]
    fn cargo_environment_starts_clean_and_sets_toolchain_values() {
        let toolchain = Toolchain {
            cargo: PathBuf::from("/toolchain/bin/cargo"),
            rustc: PathBuf::from("/toolchain/bin/rustc"),
            rustdoc: Some(PathBuf::from("/toolchain/bin/rustdoc")),
            sysroot: PathBuf::from("/toolchain"),
            home: PathBuf::from("/home/test"),
            path: OsString::from("/toolchain/bin"),
            read_only_paths: vec![PathBuf::from("/toolchain")],
        };

        let environment = cargo_environment(&toolchain, Path::new("/workspace"), Vec::new());
        assert!(!environment.inherit);
        assert!(
            environment
                .set
                .iter()
                .any(|(key, value)| key == "HOME" && value == "/home/test")
        );
        assert!(
            environment
                .set
                .iter()
                .any(|(key, value)| key == "PATH" && value == "/toolchain/bin")
        );
        assert!(
            environment
                .set
                .iter()
                .any(|(key, value)| key == "RUSTC" && value == "/toolchain/bin/rustc")
        );
        assert!(
            environment
                .set
                .iter()
                .any(|(key, value)| key == "RUSTDOC" && value == "/toolchain/bin/rustdoc")
        );
        assert!(!environment.set.iter().any(|(key, _)| key == "CARGO_HOME"));
    }

    #[test]
    fn environment_allowlist_excludes_host_control_and_secret_names() {
        for name in [
            "USER",
            "LANG",
            "CARGO_BUILD_JOBS",
            "RUSTFLAGS",
            "PKG_CONFIG_PATH",
            "LC_ALL",
        ] {
            assert!(is_safe_environment_name(OsStr::new(name)), "{name}");
        }
        for name in [
            "PATH",
            "HOME",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "RUSTUP_HOME",
            "AWS_SECRET_ACCESS_KEY",
            "CAGE_TEST_ARBITRARY_SECRET",
            "SSH_AUTH_SOCK",
            "LC_SECRET",
        ] {
            assert!(!is_safe_environment_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn host_path_filter_keeps_private_runtime_roots_hidden() {
        let home = Path::new("/home/test");
        for path in [
            "/home/test/bin",
            "/tmp/tools",
            "/var/tmp/tools",
            "/run/agent",
        ] {
            assert!(is_private_host_path(Path::new(path), home), "{path}");
        }
        assert!(!is_private_host_path(Path::new("/usr/bin"), home));
    }

    #[test]
    fn path_allowlist_keeps_only_standard_runtime_or_required_directories() {
        assert!(is_standard_runtime_path(Path::new("/usr/bin")));
        assert!(is_standard_runtime_path(Path::new("/usr/local/bin/tool")));
        assert!(!is_standard_runtime_path(Path::new("/opt/custom-bin")));
    }

    #[test]
    fn rejects_project_owned_rustup_compilers() {
        let toolchains = Path::new("/home/test/.rustup/toolchains");
        assert!(is_trusted_rustup_compiler(
            Path::new("/home/test/.rustup/toolchains/stable/bin/rustc"),
            toolchains
        ));
        assert!(!is_trusted_rustup_compiler(
            Path::new("/workspace/toolchain/bin/rustc"),
            toolchains
        ));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_manifest_symlinks_are_rejected_before_mounting() {
        use std::os::unix::fs::symlink;

        let workspace = TestWorkspace::new();
        let workspace = fs::canonicalize(&workspace.0).expect("canonical test workspace");
        let external = workspace.join("external-Cargo.toml");
        fs::write(&external, fs::read(workspace.join("Cargo.toml")).unwrap())
            .expect("write external manifest");
        let link = workspace.join("linked-Cargo.toml");
        symlink(&external, &link).expect("create manifest symlink");

        let error = manifest_parent_path(
            &[OsString::from("--manifest-path"), link.into_os_string()],
            &workspace,
        )
        .expect_err("symlinked manifest");
        let text = error.to_string();
        assert!(text.contains("manifest path"), "{text}");
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }
}
