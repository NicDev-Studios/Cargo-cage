#![forbid(unsafe_code)]

mod args;
mod paths;
mod policy;

use cage_core::{CageError, CageResult, Environment, OutputMode, SandboxBackend, SandboxRequest};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

pub use args::{CargoInvocation, help_text, is_help_request, parse_invocation};
pub use paths::{prepare_lockfile, prepare_target_dir};

/// Run the supported Cargo subcommand through the supplied platform backend.
pub fn run<I>(args: I, backend: &dyn SandboxBackend) -> CageResult<i32>
where
    I: IntoIterator<Item = OsString>,
{
    let invocation = parse_invocation(args)?;
    let CargoInvocation::Build { args: build_args } = invocation else {
        return Ok(0);
    };

    let current_dir = fs::canonicalize(
        env::current_dir()
            .map_err(|error| CageError::io("could not determine the current directory", error))?,
    )
    .map_err(|error| CageError::io("could not canonicalize the current directory", error))?;
    let cargo = resolve_cargo(&current_dir)?;

    let mut locate_request = SandboxRequest::new(&cargo, &current_dir);
    locate_request.args.push(OsString::from("locate-project"));
    locate_request.args.push(OsString::from("--workspace"));
    locate_request.args.push(OsString::from("--message-format"));
    locate_request.args.push(OsString::from("plain"));
    if let Some(manifest_path) = paths::manifest_path_arg(&build_args)? {
        locate_request.args.push(OsString::from("--manifest-path"));
        locate_request.args.push(manifest_path);
    }
    locate_request.current_dir = current_dir.clone();
    locate_request.policy = policy::cargo_policy(false)?;
    locate_request.environment = cargo_environment(Vec::new());
    locate_request.output = OutputMode::Capture;

    let locate_outcome = backend.run(&locate_request)?;
    if !locate_outcome.status.successfully_exited() {
        let detail = output_detail(&locate_outcome.stderr);
        return Err(CageError::ProcessFailed {
            status: locate_outcome.status,
            detail: format!("Cargo workspace discovery failed{detail}"),
        });
    }

    let workspace = workspace_from_output(&locate_outcome.stdout, &current_dir)?;
    let target_dir = paths::target_dir_arg(&build_args, &current_dir, &workspace)?;
    let target_dir = prepare_target_dir(target_dir, &workspace)?;
    let build_dir = prepare_target_dir(target_dir.join("build"), &workspace)?;
    let lockfile = prepare_lockfile(&workspace)?;

    let mut sandbox_policy = policy::cargo_policy(true)?;
    sandbox_policy.read_only_paths.push(workspace.clone());
    if current_dir != workspace {
        sandbox_policy.read_only_paths.push(current_dir.clone());
    }
    sandbox_policy.writable_paths.push(target_dir.clone());
    sandbox_policy.writable_paths.push(lockfile.clone());

    let mut cargo_args = Vec::with_capacity(build_args.len() + 1);
    cargo_args.push(OsString::from("build"));
    cargo_args.extend(build_args);

    let mut request = SandboxRequest::new(&cargo, &current_dir);
    request.args = cargo_args;
    request.policy = sandbox_policy;
    request.environment = cargo_environment(vec![
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
    ]);
    request.output = OutputMode::Inherit;

    let outcome = backend.run(&request)?;
    if outcome.status.successfully_exited() {
        return Ok(0);
    }

    eprintln!(
        "cargo-cage: Cargo build failed inside the Linux sandbox (exit code {}).",
        outcome
            .status
            .code
            .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
    );
    eprintln!(
        "cargo-cage: policy active: network denied, sensitive home paths hidden, and persistent writes limited to {} and {}.",
        target_dir.display(),
        lockfile.display()
    );
    eprintln!(
        "cargo-cage: a Cargo/build-script error such as Permission denied, Read-only file system, or Network is unreachable may indicate a denied operation; missing dependencies must be fetched separately with `cargo fetch`."
    );

    Ok(outcome.status.code.unwrap_or(1))
}

fn cargo_environment(set: Vec<(OsString, OsString)>) -> Environment {
    Environment {
        set,
        remove: Vec::new(),
    }
}

fn resolve_cargo(current_dir: &Path) -> CageResult<PathBuf> {
    let requested = env::var_os("CARGO").or_else(|| Some(OsString::from("cargo")));
    let requested = requested.expect("cargo fallback is always present");
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
            "CARGO is not set and PATH is unavailable; set PATH or CARGO to a trusted Cargo executable"
                .to_owned(),
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
        "could not find Cargo executable `{}`; install Cargo or set CARGO to a trusted executable",
        requested_path.display(),
    )))
}

fn validate_executable_path(path: PathBuf) -> CageResult<PathBuf> {
    let metadata = fs::metadata(&path).map_err(|error| {
        CageError::io(
            format!("could not resolve Cargo executable {}", path.display()),
            error,
        )
    })?;
    if !metadata.is_file() {
        return Err(CageError::BackendUnavailable(format!(
            "Cargo executable {} is not a regular file; set CARGO to a regular Cargo executable",
            path.display(),
        )));
    }
    Ok(path)
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
    let manifest = fs::canonicalize(&manifest).map_err(|error| {
        CageError::io(
            format!(
                "could not resolve workspace manifest {}",
                manifest.display()
            ),
            error,
        )
    })?;
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
    use std::time::{SystemTime, UNIX_EPOCH};

    struct RecordingBackend {
        workspace: PathBuf,
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
                    status: ProcessStatus { code: Some(23) },
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
            let path = env::temp_dir().join(format!("cargo-cage-integration-test-{suffix}"));
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
}
