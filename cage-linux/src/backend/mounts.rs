use cage_core::{CageError, CageResult, NetworkAccess};
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use std::ffi::OsString;
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BindMount {
    pub(super) source: PathBuf,
    pub(super) destination: PathBuf,
}

#[derive(Clone, Debug)]
pub(super) enum MountSource {
    #[cfg(test)]
    Path(PathBuf),
    Fd(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MountKind {
    Directory,
    File,
    Executable,
    Special,
}

#[derive(Clone, Debug)]
pub(super) struct MountArgument {
    pub(super) source: MountSource,
    pub(super) destination: PathBuf,
    pub(super) kind: MountKind,
}

#[derive(Clone, Debug, Default)]
pub(super) struct MountArguments {
    pub(super) runtime: Vec<MountArgument>,
    pub(super) read_only: Vec<MountArgument>,
    pub(super) caches: Vec<MountArgument>,
    pub(super) hidden_files: Vec<MountArgument>,
    pub(super) writable: Vec<MountArgument>,
    pub(super) launcher: Option<MountArgument>,
}

pub(super) struct PreparedMounts {
    pub(super) arguments: MountArguments,
    pub(super) _source_fds: Vec<OwnedFd>,
}

impl PreparedMounts {
    pub(super) fn open(plan: &super::SandboxPlan, launcher: &Path) -> CageResult<Self> {
        let mut arguments = MountArguments::default();
        let mut source_fds = Vec::new();

        for mount in &plan.runtime_mounts {
            add_fd_mount(
                &mut arguments.runtime,
                &mut source_fds,
                &mount.source,
                &mount.destination,
                MountKind::Directory,
                "runtime mount",
            )?;
        }
        for path in &plan.read_only_paths {
            add_fd_mount(
                &mut arguments.read_only,
                &mut source_fds,
                path,
                path,
                MountKind::Directory,
                "read-only mount",
            )?;
        }
        for source in &plan.cargo_cache_paths {
            let destination = Path::new(super::CARGO_HOME_IN_SANDBOX).join(
                source
                    .file_name()
                    .expect("cache path has a final component"),
            );
            add_fd_mount(
                &mut arguments.caches,
                &mut source_fds,
                source,
                &destination,
                MountKind::Directory,
                "Cargo cache mount",
            )?;
        }
        for mask in &plan.hidden_paths {
            if let MaskPath::File(path) = mask {
                add_fd_mount(
                    &mut arguments.hidden_files,
                    &mut source_fds,
                    Path::new("/dev/null"),
                    path,
                    MountKind::Special,
                    "hidden-file mask",
                )?;
            }
        }
        for path in &plan.writable_paths {
            let kind = fs::symlink_metadata(path)
                .map(|metadata| {
                    if metadata.is_dir() {
                        MountKind::Directory
                    } else {
                        MountKind::File
                    }
                })
                .map_err(|error| {
                    CageError::io(
                        format!("could not inspect writable mount {}", path.display()),
                        error,
                    )
                })?;
            add_fd_mount(
                &mut arguments.writable,
                &mut source_fds,
                path,
                path,
                kind,
                "writable mount",
            )?;
        }
        let launcher_kind = fs::symlink_metadata(launcher)
            .map_err(|error| {
                CageError::io(
                    format!(
                        "could not inspect cargo-cage launcher {}",
                        launcher.display()
                    ),
                    error,
                )
            })?
            .is_file()
            .then_some(MountKind::Executable)
            .ok_or_else(|| {
                CageError::policy(
                    launcher.display().to_string(),
                    "the internal Landlock launcher must be a regular file",
                    "run cargo-cage from a real installed or freshly built executable",
                )
            })?;
        let mut launcher_mount = Vec::new();
        add_fd_mount(
            &mut launcher_mount,
            &mut source_fds,
            launcher,
            Path::new(crate::landlock::LAUNCHER_DESTINATION),
            launcher_kind,
            "Landlock launcher mount",
        )?;
        arguments.launcher = launcher_mount.pop();

        Ok(Self {
            arguments,
            _source_fds: source_fds,
        })
    }
}

fn add_fd_mount(
    arguments: &mut Vec<MountArgument>,
    source_fds: &mut Vec<OwnedFd>,
    source: &Path,
    destination: &Path,
    kind: MountKind,
    label: &str,
) -> CageResult<()> {
    let fd = open_mount_source(source, label)?;
    validate_opened_mount_kind(&fd, kind, source, label)?;
    let raw_fd = fd.as_raw_fd();
    source_fds.push(fd);
    arguments.push(MountArgument {
        source: MountSource::Fd(raw_fd),
        destination: destination.to_path_buf(),
        kind,
    });
    Ok(())
}

pub(super) fn validate_opened_mount_kind(
    fd: &OwnedFd,
    kind: MountKind,
    source: &Path,
    label: &str,
) -> CageResult<()> {
    let metadata = fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(|error| {
        CageError::sandbox_setup(
            source.display().to_string(),
            "the mounted FD type must match the validated path type",
            "retry with a stable regular file or directory",
            format!("could not verify the opened {label} source: {error}"),
        )
    })?;
    let valid = match kind {
        MountKind::Directory => metadata.is_dir(),
        MountKind::File => metadata.is_file() && metadata.nlink() == 1,
        MountKind::Executable => metadata.is_file(),
        MountKind::Special => metadata.file_type().is_char_device(),
    };
    if valid {
        return Ok(());
    }
    let expected = match kind {
        MountKind::Directory => "directory",
        MountKind::File => "single-link regular file",
        MountKind::Executable => "regular executable file",
        MountKind::Special => "character device",
    };
    Err(CageError::policy(
        source.display().to_string(),
        format!("the opened {label} source type is not the required {expected}"),
        "restore the validated source type and retry the sandboxed operation",
    ))
}

pub(super) fn open_mount_source(path: &Path, label: &str) -> CageResult<OwnedFd> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("{label} source must be an absolute non-root path without traversal"),
            "use the canonical source path produced by the preflight validator",
        ));
    }
    let relative = path.strip_prefix("/").map_err(|_| {
        CageError::policy(
            path.display().to_string(),
            format!("{label} source could not be made relative to the host root"),
            "use a canonical absolute source path",
        )
    })?;
    let root_fd = openat2(
        CWD,
        Path::new("/"),
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        CageError::sandbox_setup(
            path.display().to_string(),
            "mount sources must be resolved from a stable host-root descriptor",
            "run on a Linux kernel with openat2 support",
            format!("could not open the host root for {label} source with openat2: {error}"),
        )
    })?;
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let fd = openat2(
        &root_fd,
        relative,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        resolve,
    )
    .map_err(|error| {
        CageError::sandbox_setup(
            path.display().to_string(),
            "mount sources must be stable and symlink-free",
            "remove the symlink or run on a Linux kernel with openat2 support",
            format!("could not open {label} source with openat2: {error}"),
        )
    })?;
    let mut flags = fcntl_getfd(&fd).map_err(|error| {
        CageError::sandbox_setup(
            path.display().to_string(),
            "mount descriptors must be transferable only to Bubblewrap",
            "use a working Linux fcntl implementation",
            format!("could not inspect the {label} file descriptor: {error}"),
        )
    })?;
    flags.remove(FdFlags::CLOEXEC);
    fcntl_setfd(&fd, flags).map_err(|error| {
        CageError::sandbox_setup(
            path.display().to_string(),
            "Bubblewrap must receive the validated mount descriptor",
            "use a working Linux fcntl implementation",
            format!("could not prepare the {label} file descriptor: {error}"),
        )
    })?;
    Ok(fd)
}

#[derive(Clone, Debug)]
pub(super) enum MaskPath {
    Directory(PathBuf),
    File(PathBuf),
}

fn push_parent_directories(
    args: &mut Vec<OsString>,
    paths: &[PathBuf],
    blocked_paths: &[PathBuf],
    runtime_mounts: &[BindMount],
) {
    let directories = collect_parent_directories(paths, blocked_paths, runtime_mounts);
    for directory in directories {
        push_args(args, [OsString::from("--dir"), directory.into_os_string()]);
    }
}

fn collect_parent_directories(
    paths: &[PathBuf],
    blocked_paths: &[PathBuf],
    runtime_mounts: &[BindMount],
) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    for path in paths {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == Path::new("/") {
                break;
            }
            if blocked_paths
                .iter()
                .any(|blocked| directory == blocked || directory.starts_with(blocked))
                || runtime_mounts.iter().any(|mount| {
                    directory == mount.destination || directory.starts_with(&mount.destination)
                })
            {
                break;
            }
            if !directories.iter().any(|item| item == directory) {
                directories.push(directory.to_path_buf());
            }
            parent = directory.parent();
        }
    }
    directories.sort_by_key(|path| path.components().count());
    directories
}

pub(super) fn private_mount_order(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut ordered = paths.to_vec();
    ordered.sort_by_key(|path| path.components().count());
    ordered.dedup();
    ordered
}

#[cfg(test)]
pub(super) fn build_bwrap_args(
    plan: &super::SandboxPlan,
    program: &Path,
    args: &[OsString],
) -> Vec<OsString> {
    let mounts = path_mount_arguments(plan);
    build_bwrap_args_with_mounts(plan, &mounts, program, args, None)
        .expect("test mount arguments include the internal launcher")
}

#[cfg(test)]
fn path_mount_arguments(plan: &super::SandboxPlan) -> MountArguments {
    let runtime = plan
        .runtime_mounts
        .iter()
        .map(|mount| MountArgument {
            source: MountSource::Path(mount.source.clone()),
            destination: mount.destination.clone(),
            kind: MountKind::Directory,
        })
        .collect();
    let read_only = plan
        .read_only_paths
        .iter()
        .map(|path| MountArgument {
            source: MountSource::Path(path.clone()),
            destination: path.clone(),
            kind: MountKind::Directory,
        })
        .collect();
    let caches = plan
        .cargo_cache_paths
        .iter()
        .map(|source| MountArgument {
            source: MountSource::Path(source.clone()),
            destination: Path::new(super::CARGO_HOME_IN_SANDBOX).join(
                source
                    .file_name()
                    .expect("cache path has a final component"),
            ),
            kind: MountKind::Directory,
        })
        .collect();
    let hidden_files = plan
        .hidden_paths
        .iter()
        .filter_map(|mask| match mask {
            MaskPath::Directory(_) => None,
            MaskPath::File(path) => Some(MountArgument {
                source: MountSource::Path(PathBuf::from("/dev/null")),
                destination: path.clone(),
                kind: MountKind::Special,
            }),
        })
        .collect();
    let writable = plan
        .writable_paths
        .iter()
        .map(|path| MountArgument {
            source: MountSource::Path(path.clone()),
            destination: path.clone(),
            kind: writable_mount_kind(path),
        })
        .collect();
    MountArguments {
        runtime,
        read_only,
        caches,
        hidden_files,
        writable,
        launcher: Some(MountArgument {
            source: MountSource::Path(PathBuf::from("/proc/self/exe")),
            destination: PathBuf::from(crate::landlock::LAUNCHER_DESTINATION),
            kind: MountKind::Executable,
        }),
    }
}

#[cfg(test)]
fn writable_mount_kind(path: &Path) -> MountKind {
    fs::symlink_metadata(path)
        .map(|metadata| {
            if metadata.is_dir() {
                MountKind::Directory
            } else {
                MountKind::File
            }
        })
        .unwrap_or(MountKind::Directory)
}

pub(super) fn build_bwrap_args_with_mounts(
    plan: &super::SandboxPlan,
    mounts: &MountArguments,
    program: &Path,
    args: &[OsString],
    launcher_context_fd: Option<i32>,
) -> CageResult<Vec<OsString>> {
    let mut command = Vec::new();
    for mount in &mounts.runtime {
        push_mount_argument(&mut command, true, mount);
    }
    push_args(&mut command, ["--proc", "/proc"]);
    push_args(&mut command, ["--dev", "/dev"]);

    push_parent_directories(&mut command, &plan.private_paths, &[], &plan.runtime_mounts);

    for path in private_mount_order(&plan.private_paths) {
        push_args(
            &mut command,
            [OsString::from("--tmpfs"), path.into_os_string()],
        );
    }

    push_args(
        &mut command,
        [
            OsString::from("--dir"),
            OsString::from(super::CARGO_HOME_IN_SANDBOX),
        ],
    );
    push_parent_directories(
        &mut command,
        &plan.read_only_paths,
        &plan.private_paths,
        &plan.runtime_mounts,
    );
    for mount in &mounts.read_only {
        push_mount_argument(&mut command, true, mount);
    }

    for mount in &mounts.caches {
        push_mount_argument(&mut command, true, mount);
    }

    for mask in &plan.hidden_paths {
        if let MaskPath::Directory(path) = mask {
            push_args(
                &mut command,
                [OsString::from("--tmpfs"), path.clone().into_os_string()],
            );
        }
    }

    for mount in &mounts.hidden_files {
        push_mount_argument(&mut command, true, mount);
    }

    for mount in &mounts.writable {
        push_mount_argument(&mut command, false, mount);
    }

    if let Some(fd) = launcher_context_fd {
        push_args(
            &mut command,
            [
                OsString::from("--file"),
                OsString::from(fd.to_string()),
                OsString::from(crate::landlock::LAUNCHER_CONTEXT_DESTINATION),
            ],
        );
    }

    if plan.network == NetworkAccess::Deny {
        command.push(OsString::from("--unshare-net"));
    }
    push_args(
        &mut command,
        [
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--disable-userns",
            "--assert-userns-disabled",
            "--cap-drop",
            "ALL",
            "--new-session",
            "--die-with-parent",
            "--hostname",
            "cargo-cage",
            "--chdir",
        ],
    );
    command.push(plan.current_dir.clone().into_os_string());

    if !plan.environment.inherit {
        command.push(OsString::from("--clearenv"));
    }
    for key in &plan.environment.remove {
        push_args(&mut command, [OsString::from("--unsetenv"), key.clone()]);
    }
    for (key, value) in &plan.environment.set {
        push_args(
            &mut command,
            [OsString::from("--setenv"), key.clone(), value.clone()],
        );
    }
    if !plan
        .environment
        .remove
        .contains(&OsString::from("CARGO_HOME"))
    {
        push_args(
            &mut command,
            [
                OsString::from("--setenv"),
                OsString::from("CARGO_HOME"),
                OsString::from(super::CARGO_HOME_IN_SANDBOX),
            ],
        );
    }

    let launcher = mounts.launcher.as_ref().ok_or_else(|| {
        CageError::sandbox_setup(
            "/run/cargo-cage-landlock-launcher",
            "Cargo must start only after the internal Landlock launcher is mounted",
            "rebuild cargo-cage from a complete installation",
            "the launcher mount was not prepared",
        )
    })?;
    push_mount_argument(&mut command, true, launcher);

    command.push(OsString::from("--"));
    // dash (Ubuntu's /bin/sh) only accepts short file-descriptor numbers in
    // redirections. Bash handles the high descriptors Cargo's jobserver may
    // provide, while the script itself remains fixed and argument-safe.
    command.push(PathBuf::from(super::FD_SCRUBBER_SHELL).into_os_string());
    command.push(OsString::from("-c"));
    command.push(OsString::from(super::FD_SCRUBBER));
    command.push(OsString::from("cargo-cage-fd-scrubber"));
    command.push(OsString::from(crate::landlock::LAUNCHER_DESTINATION));
    command.push(OsString::from(crate::landlock::INTERNAL_LAUNCHER_ARG));
    command.extend(landlock_launcher_args(plan, mounts, program, args));
    Ok(command)
}

fn push_mount_argument(command: &mut Vec<OsString>, read_only: bool, mount: &MountArgument) {
    command.push(OsString::from(if read_only {
        match &mount.source {
            MountSource::Fd(_) => "--ro-bind-fd",
            #[cfg(test)]
            MountSource::Path(_) => "--ro-bind",
        }
    } else {
        match &mount.source {
            MountSource::Fd(_) => "--bind-fd",
            #[cfg(test)]
            MountSource::Path(_) => "--bind",
        }
    }));
    match &mount.source {
        MountSource::Fd(fd) => command.push(fd.to_string().into()),
        #[cfg(test)]
        MountSource::Path(path) => command.push(path.clone().into_os_string()),
    }
    command.push(mount.destination.clone().into_os_string());
}

fn landlock_launcher_args(
    plan: &super::SandboxPlan,
    mounts: &MountArguments,
    program: &Path,
    args: &[OsString],
) -> Vec<OsString> {
    let mut command = Vec::new();
    for mount in &mounts.runtime {
        push_args(
            &mut command,
            [
                OsString::from("--landlock-execute"),
                mount.destination.clone().into_os_string(),
            ],
        );
    }
    for mount in &mounts.read_only {
        push_args(
            &mut command,
            [
                OsString::from("--landlock-execute"),
                mount.destination.clone().into_os_string(),
            ],
        );
    }
    for mount in &mounts.caches {
        push_args(
            &mut command,
            [
                OsString::from("--landlock-read"),
                mount.destination.clone().into_os_string(),
            ],
        );
    }
    for mount in &mounts.writable {
        let option = match mount.kind {
            MountKind::Directory => "--landlock-write",
            MountKind::File => "--landlock-lockfile",
            MountKind::Executable => unreachable!("executables cannot be writable mounts"),
            MountKind::Special => unreachable!("special files cannot be writable mounts"),
        };
        push_args(
            &mut command,
            [
                OsString::from(option),
                mount.destination.clone().into_os_string(),
            ],
        );
    }
    for path in &plan.private_paths {
        push_args(
            &mut command,
            [
                OsString::from("--landlock-private"),
                path.clone().into_os_string(),
            ],
        );
    }
    push_args(
        &mut command,
        [
            OsString::from("--landlock-private"),
            OsString::from(super::CARGO_HOME_IN_SANDBOX),
            OsString::from("--landlock-proc"),
            OsString::from("/proc"),
            OsString::from("--landlock-device"),
            OsString::from("/dev"),
        ],
    );
    if plan.network == NetworkAccess::Deny {
        command.push(OsString::from("--landlock-network-deny"));
    }
    if plan.environment.inherit {
        command.push(OsString::from("--landlock-inherit-environment"));
    }
    command.push(OsString::from("--"));
    command.push(program.to_path_buf().into_os_string());
    command.extend(args.iter().cloned());
    command
}

fn push_args<I, T>(destination: &mut Vec<OsString>, values: I)
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    destination.extend(values.into_iter().map(Into::into));
}
