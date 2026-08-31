use cage_core::{CageError, CageResult};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::path::{Component, Path, PathBuf};

pub fn manifest_path_arg(args: &[OsString]) -> CageResult<Option<OsString>> {
    let mut result = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == OsStr::new("--") {
            break;
        }
        if args[index] == OsStr::new("--manifest-path") {
            let value = args.get(index + 1).ok_or_else(|| {
                CageError::InvalidInvocation("--manifest-path needs a value".to_owned())
            })?;
            result = Some(value.clone());
            index += 2;
            continue;
        }
        if let Some(value) = args[index]
            .to_str()
            .and_then(|arg| arg.strip_prefix("--manifest-path="))
        {
            result = Some(OsString::from(value));
        }
        index += 1;
    }
    Ok(result)
}

pub fn target_dir_arg(
    args: &[OsString],
    current_dir: &Path,
    workspace: &Path,
) -> CageResult<PathBuf> {
    let mut cli_target = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == OsStr::new("--") {
            break;
        }
        if args[index] == OsStr::new("--target-dir") {
            let value = args.get(index + 1).ok_or_else(|| {
                CageError::InvalidInvocation("--target-dir needs a value".to_owned())
            })?;
            cli_target = Some(PathBuf::from(value));
            index += 2;
            continue;
        }
        if let Some(value) = args[index]
            .to_str()
            .and_then(|arg| arg.strip_prefix("--target-dir="))
        {
            cli_target = Some(PathBuf::from(value));
        }
        index += 1;
    }

    let target = if let Some(target) = cli_target {
        target
    } else if let Some(target) = env::var_os("CARGO_TARGET_DIR") {
        PathBuf::from(target)
    } else {
        workspace.join("target")
    };
    let target = if target.is_absolute() {
        target
    } else {
        current_dir.join(target)
    };
    Ok(target)
}

pub fn prepare_target_dir(path: PathBuf, workspace: &Path) -> CageResult<PathBuf> {
    let normalized = validate_target_dir(&path, workspace)?;
    create_directory_without_symlinks(&normalized)?;
    let target = fs::canonicalize(&normalized).map_err(|error| {
        CageError::io(
            format!(
                "could not canonicalize target directory {}",
                normalized.display()
            ),
            error,
        )
    })?;
    let workspace = fs::canonicalize(workspace).map_err(|error| {
        CageError::io(
            format!("could not canonicalize workspace {}", workspace.display()),
            error,
        )
    })?;
    if target == workspace || !target.starts_with(&workspace) {
        return Err(CageError::policy(
            target.display().to_string(),
            "the target directory must be inside the canonical workspace; paths outside the workspace are forbidden",
            "choose --target-dir below the workspace directory",
        ));
    }
    Ok(target)
}

/// Validate a target path without creating or modifying anything.
pub fn validate_target_dir(path: &Path, workspace: &Path) -> CageResult<PathBuf> {
    if !path.is_absolute() {
        return Err(CageError::policy(
            path.display().to_string(),
            "the target directory must be absolute after resolution",
            "pass an absolute --target-dir or use a target directory inside the workspace",
        ));
    }
    let workspace = fs::canonicalize(workspace).map_err(|error| {
        CageError::io(
            format!("could not canonicalize workspace {}", workspace.display()),
            error,
        )
    })?;
    let original_path = path;
    let normalized = lexical_normalize(original_path);
    let containment_path = canonicalize_with_missing_components(&normalized)?;
    if containment_path == workspace || !containment_path.starts_with(&workspace) {
        return Err(CageError::policy(
            containment_path.display().to_string(),
            "the target directory must be inside the canonical workspace; paths outside the workspace are forbidden",
            "choose --target-dir below the workspace directory",
        ));
    }
    // Inspect both component orders. The original order catches a symlink
    // hidden by `..`; the normalized order catches a symlink after a missing
    // component. The containment check above deliberately comes first so
    // platform aliases such as macOS `/var` still produce the useful outside
    // path error.
    validate_target_symlink_components(original_path, &workspace)?;
    validate_target_symlink_components(&normalized, &workspace)?;
    Ok(containment_path)
}

pub fn inspect_lockfile(workspace: &Path) -> CageResult<bool> {
    let lockfile = workspace.join("Cargo.lock");
    match fs::symlink_metadata(&lockfile) {
        Ok(metadata) => {
            validate_lockfile(&lockfile, &metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CageError::io(
            format!(
                "could not inspect workspace lockfile {}",
                lockfile.display()
            ),
            error,
        )),
    }
}

pub fn prepare_lockfile(workspace: &Path) -> CageResult<PathBuf> {
    let lockfile = workspace.join("Cargo.lock");
    if !inspect_lockfile(workspace)? {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lockfile)
            .map_err(|error| {
                CageError::io(
                    format!("could not create workspace lockfile {}", lockfile.display()),
                    error,
                )
            })?;
        inspect_lockfile(workspace)?;
    }
    Ok(lockfile)
}

fn validate_target_symlink_components(path: &Path, workspace: &Path) -> CageResult<()> {
    let mut current = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => current.push(".."),
            Component::Normal(part) => current.push(part),
        }

        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(CageError::io(
                    format!("could not inspect target path {}", current.display()),
                    error,
                ));
            }
        };
        let mut is_directory = metadata.is_dir();
        if metadata.file_type().is_symlink() {
            let parent = current.parent().unwrap_or_else(|| Path::new("/"));
            let parent = fs::canonicalize(parent).map_err(|error| {
                CageError::io(
                    format!(
                        "could not canonicalize target path parent {}",
                        parent.display()
                    ),
                    error,
                )
            })?;
            let resolved = fs::canonicalize(&current).map_err(|_| {
                CageError::policy(
                    current.display().to_string(),
                    "the writable target path must not contain unresolved symlink components",
                    "replace the dangling symlink with a real directory",
                )
            })?;
            if parent == workspace
                || parent.starts_with(workspace)
                || resolved == workspace
                || resolved.starts_with(workspace)
            {
                return Err(CageError::policy(
                    current.display().to_string(),
                    "the writable target path must not contain symlink components",
                    "replace the symlink with a real directory",
                ));
            }
            is_directory = fs::metadata(&current)
                .map(|metadata| metadata.is_dir())
                .map_err(|error| {
                    CageError::io(
                        format!("could not inspect target path {}", current.display()),
                        error,
                    )
                })?;
        }
        if components.peek().is_some() && !is_directory {
            return Err(CageError::policy(
                current.display().to_string(),
                "every target path component must be a directory",
                "remove the conflicting file and retry with a directory path",
            ));
        }
    }
    Ok(())
}

fn validate_lockfile(path: &Path, metadata: &fs::Metadata) -> CageResult<()> {
    if metadata.file_type().is_symlink() {
        return Err(CageError::policy(
            path.display().to_string(),
            "the workspace Cargo.lock must not be a symlink",
            "replace it with a regular file before running cargo-cage",
        ));
    }
    if !metadata.is_file() {
        return Err(CageError::policy(
            path.display().to_string(),
            "the workspace Cargo.lock must be a regular file",
            "replace the lockfile with a regular file before running cargo-cage",
        ));
    }
    Ok(())
}

fn create_directory_without_symlinks(path: &Path) -> CageResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => current.push(".."),
            Component::Normal(part) => current.push(part),
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(CageError::policy(
                        current.display().to_string(),
                        "the writable target path must not contain symlink components",
                        "replace the symlink with a real directory",
                    ));
                }
                if !metadata.is_dir() {
                    return Err(CageError::policy(
                        current.display().to_string(),
                        "every target path component must be a directory",
                        "remove the conflicting file and retry with a directory path",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    CageError::io(
                        format!("could not create target directory {}", current.display()),
                        error,
                    )
                })?;
            }
            Err(error) => {
                return Err(CageError::io(
                    format!("could not inspect target path {}", current.display()),
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn canonicalize_with_missing_components(path: &Path) -> CageResult<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(&existing) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(CageError::policy(
                        existing.display().to_string(),
                        "the target path must not contain unresolved symlink components",
                        "replace the dangling symlink with a real directory",
                    ));
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = existing.file_name() else {
                    return Err(CageError::policy(
                        path.display().to_string(),
                        "the target path must have an existing parent",
                        "create the workspace directory before running cargo-cage",
                    ));
                };
                missing.push(name.to_os_string());
                existing.pop();
            }
            Err(error) => {
                return Err(CageError::io(
                    format!("could not inspect target path {}", existing.display()),
                    error,
                ));
            }
        }
    }
    let mut canonical = fs::canonicalize(&existing).map_err(|error| {
        CageError::io(
            format!(
                "could not canonicalize target parent {}",
                existing.display()
            ),
            error,
        )
    })?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!("cargo-cage-path-test-{suffix}-{id}"));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_target_and_lockfile_inside_workspace() {
        let root = TestDirectory::new();
        let workspace_path = root.path().join("workspace");
        fs::create_dir(&workspace_path).expect("create workspace");
        let workspace = fs::canonicalize(workspace_path).expect("canonical workspace");
        let target =
            prepare_target_dir(workspace.join("target"), &workspace).expect("target is safe");
        let lock = prepare_lockfile(&workspace).expect("lockfile is safe");
        assert_eq!(target, fs::canonicalize(workspace.join("target")).unwrap());
        assert!(lock.is_file());
    }

    #[test]
    fn validates_missing_paths_without_creating_them() {
        let root = TestDirectory::new();
        let workspace_path = root.path().join("workspace");
        fs::create_dir(&workspace_path).expect("create workspace");
        let workspace = fs::canonicalize(workspace_path).expect("canonical workspace");
        let target = workspace.join("target");

        let checked_target = validate_target_dir(&target, &workspace).expect("safe target");
        assert_eq!(checked_target, target);
        assert!(!target.exists());
        assert!(!inspect_lockfile(&workspace).expect("inspect missing lockfile"));
        assert!(!workspace.join("Cargo.lock").exists());
    }

    #[test]
    fn rejects_target_outside_workspace_before_creating_it() {
        let root = TestDirectory::new();
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).expect("create workspace");
        let outside = root.path().join("outside");
        let error = prepare_target_dir(outside.clone(), &workspace).expect_err("outside target");
        assert!(
            error.to_string().contains("outside the workspace"),
            "{error}"
        );
        assert!(!outside.exists());
    }

    #[test]
    fn rejects_target_traversal() {
        let root = TestDirectory::new();
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        fs::create_dir(&workspace).expect("create workspace");
        fs::create_dir(&outside).expect("create outside");

        let target = workspace
            .join("target")
            .join("..")
            .join("..")
            .join("outside");
        let error = prepare_target_dir(target, &workspace).expect_err("traversal target");
        assert!(
            error.to_string().contains("outside the workspace"),
            "{error}"
        );
        assert!(outside.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        fs::create_dir(&workspace).expect("create workspace");
        fs::create_dir(&outside).expect("create outside");
        symlink(&outside, workspace.join("target")).expect("create target symlink");
        let error =
            prepare_target_dir(workspace.join("target"), &workspace).expect_err("symlink target");
        assert!(error.to_string().contains("symlink") || error.to_string().contains("outside"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_hidden_by_parent_traversal() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        fs::create_dir(&workspace).expect("create workspace");
        fs::create_dir(&outside).expect("create outside");
        let workspace = fs::canonicalize(workspace).expect("canonical workspace");
        let target = prepare_target_dir(workspace.join("target"), &workspace)
            .expect("create target directory");
        symlink(&outside, target.join("link")).expect("create traversal symlink");

        let path = target.join("link").join("..").join("escape");
        let error = prepare_target_dir(path, &workspace).expect_err("symlink traversal");
        let text = error.to_string();
        assert!(
            text.contains("symlink") || text.contains("outside"),
            "{text}"
        );
        assert!(!outside.join("escape").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_build_directory() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        fs::create_dir(&workspace).expect("create workspace");
        fs::create_dir(&outside).expect("create outside");
        let workspace = fs::canonicalize(workspace).expect("canonical workspace");
        let target = prepare_target_dir(workspace.join("target"), &workspace)
            .expect("create target directory");
        symlink(&outside, target.join("build")).expect("create build symlink");

        let error = prepare_target_dir(target.join("build"), &workspace)
            .expect_err("symlinked build directory");
        let text = error.to_string();
        assert!(
            text.contains("symlink") || text.contains("outside"),
            "{text}"
        );
        assert!(outside.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_lockfile() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let workspace_path = root.path().join("workspace");
        let external = root.path().join("external-lock");
        fs::create_dir(&workspace_path).expect("create workspace");
        fs::write(&external, b"must remain untouched").expect("create external lock target");
        let workspace = fs::canonicalize(workspace_path).expect("canonical workspace");
        symlink(&external, workspace.join("Cargo.lock")).expect("create lockfile symlink");

        let error = prepare_lockfile(&workspace).expect_err("symlinked lockfile");
        let text = error.to_string();
        assert!(
            text.contains("Cargo.lock") && text.contains("symlink"),
            "{text}"
        );
        assert_eq!(
            fs::read(&external).expect("read external lock target"),
            b"must remain untouched"
        );
    }
}
