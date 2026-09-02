use super::{Toolchain, cargo_environment};
use cage_core::{
    CageError, CageResult, OutputMode, SandboxBackend, SandboxRequest,
    canonical_existing_path_without_symlinks,
};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn canonical_current_dir() -> CageResult<PathBuf> {
    fs::canonicalize(
        env::current_dir()
            .map_err(|error| CageError::io("could not determine the current directory", error))?,
    )
    .map_err(|error| CageError::io("could not canonicalize the current directory", error))
}

pub(super) fn cargo_cache_present() -> bool {
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

pub(super) fn locate_workspace(
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
    if let Some(manifest_path) = crate::paths::manifest_path_arg(cargo_args)? {
        locate_request.args.push(OsString::from("--manifest-path"));
        locate_request.args.push(manifest_path);
    }
    let mut policy = crate::policy::cargo_policy(false)?;
    policy.read_only_paths.push(current_dir.to_path_buf());
    if let Some(manifest_parent) = manifest_parent_path(cargo_args, current_dir)? {
        policy.read_only_paths.push(manifest_parent);
    }
    policy
        .writable_paths
        .extend(discovery_writable_paths(cargo_args, current_dir)?);
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

    workspace_from_output(&locate_outcome.stdout, current_dir, cargo_args)
}

pub(super) fn discovery_writable_paths(
    cargo_args: &[OsString],
    current_dir: &Path,
) -> CageResult<Vec<PathBuf>> {
    let bases = if let Some(parent) = manifest_parent_path(cargo_args, current_dir)? {
        vec![parent]
    } else {
        vec![current_dir.to_path_buf()]
    };

    let mut candidates = bases
        .iter()
        .map(|base| base.join("target"))
        .collect::<Vec<_>>();
    if let Ok(target) = crate::paths::target_dir_arg(cargo_args, current_dir, current_dir) {
        if bases
            .iter()
            .any(|base| target == *base || target.starts_with(base))
        {
            candidates.push(target);
        }
    }

    candidates.retain(|path| fs::symlink_metadata(path).is_ok());
    candidates.dedup();
    Ok(candidates)
}

pub(super) fn manifest_parent_path(
    args: &[OsString],
    current_dir: &Path,
) -> CageResult<Option<PathBuf>> {
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

pub(super) fn resolved_manifest_path(
    args: &[OsString],
    current_dir: &Path,
) -> CageResult<Option<PathBuf>> {
    let Some(value) = crate::paths::manifest_path_arg(args)? else {
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

pub(super) fn sandbox_current_dir(
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

pub(super) fn rewrite_relative_cargo_paths(
    args: &[OsString],
    current_dir: &Path,
    sandbox_current_dir: &Path,
    target_dir: &Path,
    force_target_rewrite: bool,
) -> CageResult<Vec<OsString>> {
    let mut rewritten = args.to_vec();
    let needs_directory_rewrite = current_dir != sandbox_current_dir;
    let mut index = 0;
    while index < rewritten.len() {
        if rewritten[index] == OsStr::new("--") {
            break;
        }
        if rewritten[index] == OsStr::new("--manifest-path") {
            if let Some(value) = rewritten.get_mut(index + 1) {
                let path = PathBuf::from(&*value);
                if !path.is_absolute() && needs_directory_rewrite {
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
            if needs_directory_rewrite && !path.is_absolute() {
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
                if force_target_rewrite || !path.is_absolute() {
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
            let path = Path::new(value);
            if force_target_rewrite || !path.is_absolute() {
                rewritten[index] = OsString::from("--target-dir=");
                rewritten[index].push(target_dir.as_os_str());
            }
        }
        index += 1;
    }
    Ok(rewritten)
}

pub(super) fn workspace_from_output(
    output: &[u8],
    current_dir: &Path,
    cargo_args: &[OsString],
) -> CageResult<PathBuf> {
    let output = String::from_utf8_lossy(output);
    let manifest = output.trim();
    if manifest.is_empty() || manifest.contains('\n') || manifest.contains('\r') {
        return Err(CageError::sandbox_setup(
            "Cargo workspace discovery",
            "locate-project must return exactly one manifest path",
            "verify the manifest and rerun cargo-cage from the intended workspace",
            "Cargo returned an invalid workspace manifest path",
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
    let workspace = manifest.parent().map(Path::to_path_buf).ok_or_else(|| {
        CageError::policy(
            manifest.display().to_string(),
            "the workspace manifest must have a parent directory",
            "use a valid Cargo workspace manifest path",
        )
    })?;
    if let Some(requested_manifest) = resolved_manifest_path(cargo_args, current_dir)? {
        if !requested_manifest.starts_with(&workspace) {
            return Err(CageError::policy(
                workspace.display().to_string(),
                "workspace discovery returned a root that does not contain the requested manifest",
                "use a Cargo workspace or pass a manifest path inside the discovered workspace",
            ));
        }
    } else if current_dir != workspace && !current_dir.starts_with(&workspace) {
        return Err(CageError::policy(
            workspace.display().to_string(),
            "workspace discovery returned a root that does not contain the current directory",
            "run cargo-cage from the intended workspace or pass an explicit manifest path",
        ));
    }
    Ok(workspace)
}

pub(super) fn output_detail(output: &[u8]) -> String {
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
