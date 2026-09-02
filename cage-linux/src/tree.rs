use cage_core::{CageError, CageResult};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(super) fn validate_cache_tree(root: &Path) -> CageResult<()> {
    validate_tree(root, TreeKind::Cache, &[])
}

pub(super) fn validate_writable_tree(root: &Path) -> CageResult<()> {
    validate_tree(root, TreeKind::Writable, &[])
}

pub(super) fn validate_read_only_tree(root: &Path, excluded_paths: &[PathBuf]) -> CageResult<()> {
    validate_tree(root, TreeKind::ReadOnly, excluded_paths)
}

pub(super) fn unique_mount_roots(paths: &[PathBuf]) -> Vec<&PathBuf> {
    let mut sorted = paths.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|path| path.components().count());
    let mut roots = Vec::new();
    for path in sorted {
        if !roots.iter().any(|root| path.starts_with(root)) {
            roots.push(path);
        }
    }
    roots
}

#[derive(Clone, Copy)]
enum TreeKind {
    Cache,
    ReadOnly,
    Writable,
}

fn validate_tree(root: &Path, kind: TreeKind, excluded_paths: &[PathBuf]) -> CageResult<()> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        tree_setup_failure(
            root,
            kind,
            format!("could not inspect the tree root: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CageError::policy(
            root.display().to_string(),
            format!("{} roots must not be symlinks", tree_label(kind)),
            "replace the symlink with a real path before running cargo-cage",
        ));
    }
    if metadata.is_file() {
        if matches!(kind, TreeKind::Writable) {
            let files = vec![(root.to_path_buf(), metadata)];
            return validate_hardlink_aliases(&files, tree_label(kind));
        }
        return Err(CageError::policy(
            root.display().to_string(),
            format!("{} roots must be directories", tree_label(kind)),
            "replace the file with a real directory before running cargo-cage",
        ));
    }
    if !metadata.is_dir() {
        return Err(CageError::policy(
            root.display().to_string(),
            format!(
                "{} trees may contain only regular files and directories",
                tree_label(kind)
            ),
            "remove the special file before running cargo-cage",
        ));
    }

    validate_no_nested_mounts(root, tree_label(kind))?;
    let mut directories = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| {
            tree_setup_failure(
                &directory,
                kind,
                format!("could not read the directory: {error}"),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                tree_setup_failure(
                    &directory,
                    kind,
                    format!("could not read a directory entry: {error}"),
                )
            })?;
            let path = entry.path();
            if excluded_paths
                .iter()
                .any(|excluded| path == *excluded || path.starts_with(excluded))
            {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                tree_setup_failure(
                    &path,
                    kind,
                    format!("could not inspect a tree entry: {error}"),
                )
            })?;
            if metadata.file_type().is_symlink() {
                if matches!(kind, TreeKind::ReadOnly) {
                    let resolved = fs::canonicalize(&path).map_err(|error| {
                        tree_setup_failure(
                            &path,
                            kind,
                            format!("could not resolve a read-only symlink: {error}"),
                        )
                    })?;
                    if !resolved.starts_with(root) {
                        return Err(CageError::policy(
                            path.display().to_string(),
                            "read-only tree symlinks must resolve inside the validated tree",
                            "replace the external symlink with a real file or an in-tree link",
                        ));
                    }
                    continue;
                }
                return Err(CageError::policy(
                    path.display().to_string(),
                    format!("{} trees must not contain symlinks", tree_label(kind)),
                    "remove the symlink before running cargo-cage",
                ));
            }
            if metadata.is_dir() {
                directories.push(path);
            } else if metadata.is_file() {
                files.push((path, metadata));
            } else {
                return Err(CageError::policy(
                    path.display().to_string(),
                    format!(
                        "{} trees may contain only regular files and directories",
                        tree_label(kind)
                    ),
                    "remove the special file before running cargo-cage",
                ));
            }
        }
    }

    validate_hardlink_aliases(&files, tree_label(kind))
}

fn tree_label(kind: TreeKind) -> &'static str {
    match kind {
        TreeKind::Cache => "Cargo cache",
        TreeKind::ReadOnly => "read-only",
        TreeKind::Writable => "writable",
    }
}

fn tree_setup_failure(path: &Path, kind: TreeKind, detail: impl Into<String>) -> CageError {
    CageError::sandbox_setup(
        path.display().to_string(),
        format!(
            "{} trees must remain real, present, and stable during validation",
            tree_label(kind)
        ),
        "stop concurrent changes to the validated tree and retry",
        detail,
    )
}

pub(super) fn validate_hardlink_aliases(
    files: &[(PathBuf, fs::Metadata)],
    label: &str,
) -> CageResult<()> {
    let mut counts = HashMap::new();
    for (_, metadata) in files {
        let identity = (metadata.dev(), metadata.ino());
        *counts.entry(identity).or_insert(0_u64) += 1;
    }
    for (path, metadata) in files {
        let identity = (metadata.dev(), metadata.ino());
        if metadata.nlink() != counts[&identity] {
            return Err(CageError::policy(
                path.display().to_string(),
                format!("{label} contains a hardlink with an alias outside the validated tree"),
                "replace the hardlink with a copied regular file inside the validated tree",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_no_nested_mounts(root: &Path, label: &str) -> CageResult<()> {
    #[cfg(all(test, target_os = "linux"))]
    if !Path::new("/proc/self/mountinfo").exists() {
        // Linux-only code is also compiled under a forced cfg on macOS in
        // local CI checks. A real Linux run must always have procfs because
        // the namespace preflight depends on it as well.
        return Ok(());
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        CageError::io(
            format!("could not inspect mountpoints below {}", root.display()),
            error,
        )
    })?;
    for line in mountinfo.lines().filter(|line| !line.is_empty()) {
        let mountpoint = line.split_whitespace().nth(4).ok_or_else(|| {
            CageError::policy(
                root.display().to_string(),
                "the host mount table could not be parsed while validating a protected tree",
                "retry on a Linux host with a readable /proc/self/mountinfo",
            )
        })?;
        let mountpoint = decode_mountinfo_path(mountpoint).ok_or_else(|| {
            CageError::policy(
                root.display().to_string(),
                "the host mount table contained an invalid protected-tree path",
                "retry after removing invalid mountpoint metadata",
            )
        })?;
        if mountpoint != root && mountpoint.starts_with(root) {
            return Err(CageError::policy(
                mountpoint.display().to_string(),
                format!("{label} trees must not contain nested mountpoints"),
                "unmount the nested filesystem before running cargo-cage",
            ));
        }
    }
    Ok(())
}

pub(super) fn decode_mountinfo_path(encoded: &str) -> Option<PathBuf> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len() {
                return None;
            }
            let mut value = 0_u8;
            for offset in 1..=3 {
                let digit = bytes[index + offset];
                if !(b'0'..=b'7').contains(&digit) {
                    return None;
                }
                value = value * 8 + digit - b'0';
            }
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok().map(PathBuf::from)
}
