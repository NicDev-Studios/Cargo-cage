use crate::{CageError, CageResult};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Canonicalize an existing path without following any symlink component.
///
/// The caller still decides whether the resulting path is allowed by its
/// policy. This helper only provides the shared, fail-closed resolution rule so
/// Cargo integration and platform backends cannot accidentally disagree.
pub fn canonical_existing_path_without_symlinks(path: &Path, label: &str) -> CageResult<PathBuf> {
    if !path.is_absolute() {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("the {label} must be an absolute path"),
            "pass an absolute path before starting the sandbox",
        ));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
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
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => unreachable!("parent-directory components were rejected"),
            Component::Normal(part) => current.push(part),
        }
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
                "replace the symlink component with a real path and retry",
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
