use cage_core::{CageError, CageResult, SandboxBackend, SandboxOutcome, SandboxRequest};
#[cfg(target_os = "linux")]
use cage_core::{Environment, NetworkAccess, OutputMode, ProcessStatus};
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::path::{Component, Path};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
const MIN_BWRAP_MAJOR: u32 = 0;
#[cfg(target_os = "linux")]
const MIN_BWRAP_MINOR: u32 = 8;
#[cfg(target_os = "linux")]
const CARGO_HOME_IN_SANDBOX: &str = "/run/cargo-cage-home";
#[cfg(target_os = "linux")]
const NAMESPACE_PREFLIGHT_OUTPUT: &[u8] = b"cargo-cage-namespace-preflight-ok\n";
#[cfg(target_os = "linux")]
const NAMESPACE_PREFLIGHT: &str = r#"set -eu
[ -x /usr/bin/readlink ]
mnt=$(/usr/bin/readlink /proc/self/ns/mnt)
user=$(/usr/bin/readlink /proc/self/ns/user)
pid=$(/usr/bin/readlink /proc/self/ns/pid)
ipc=$(/usr/bin/readlink /proc/self/ns/ipc)
uts=$(/usr/bin/readlink /proc/self/ns/uts)
net=$(/usr/bin/readlink /proc/self/ns/net)
[ -n "$mnt" ] && [ "$mnt" != "$1" ]
[ -n "$user" ] && [ "$user" != "$2" ]
[ -n "$pid" ] && [ "$pid" != "$3" ]
[ -n "$ipc" ] && [ "$ipc" != "$4" ]
[ -n "$uts" ] && [ "$uts" != "$5" ]
if [ -n "${6:-}" ]; then
  [ -n "$net" ] && [ "$net" != "$6" ]
fi
printf '%s\n' cargo-cage-namespace-preflight-ok
"#;

#[derive(Clone, Debug)]
pub struct LinuxSandbox {
    #[cfg(target_os = "linux")]
    bwrap: PathBuf,
}

impl LinuxSandbox {
    pub fn new() -> CageResult<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(CageError::UnsupportedPlatform)
        }

        #[cfg(target_os = "linux")]
        {
            let bwrap = find_bwrap()?;
            let version = bwrap_version(&bwrap)?;
            if !version_at_least(version, (MIN_BWRAP_MAJOR, MIN_BWRAP_MINOR, 0)) {
                return Err(CageError::BackendUnavailable(format!(
                    "{} is too old; Bubblewrap >= {}.{} is required; install a newer Bubblewrap or set CARGO_CAGE_BWRAP to a trusted absolute executable",
                    bwrap.display(),
                    MIN_BWRAP_MAJOR,
                    MIN_BWRAP_MINOR
                )));
            }
            Ok(Self { bwrap })
        }
    }

    #[cfg(target_os = "linux")]
    fn run_inner(
        &self,
        plan: &SandboxPlan,
        program: &Path,
        args: &[OsString],
        output_mode: OutputMode,
    ) -> CageResult<SandboxOutcome> {
        let mut command = Command::new(&self.bwrap);
        command.args(build_bwrap_args(plan, program, args));
        command.current_dir(&plan.current_dir);
        command.envs(plan.environment.set.iter().map(|(key, value)| (key, value)));
        for key in &plan.environment.remove {
            command.env_remove(key);
        }

        match output_mode {
            OutputMode::Inherit => {
                let status = command.status().map_err(|source| CageError::ProcessSpawn {
                    program: self.bwrap.clone(),
                    source,
                })?;
                Ok(SandboxOutcome {
                    status: ProcessStatus {
                        code: status.code(),
                    },
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            OutputMode::Capture => {
                let output = command.stdin(Stdio::null()).output().map_err(|source| {
                    CageError::ProcessSpawn {
                        program: self.bwrap.clone(),
                        source,
                    }
                })?;
                Ok(SandboxOutcome {
                    status: ProcessStatus {
                        code: output.status.code(),
                    },
                    stdout: output.stdout,
                    stderr: output.stderr,
                })
            }
        }
    }
}

impl SandboxBackend for LinuxSandbox {
    fn run(&self, request: &SandboxRequest) -> CageResult<SandboxOutcome> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(CageError::UnsupportedPlatform)
        }

        #[cfg(target_os = "linux")]
        {
            let plan = SandboxPlan::from_request(request)?;
            let mut namespace_markers = parent_namespace_markers()?;
            if plan.network == NetworkAccess::Allow {
                namespace_markers[5] = OsString::new();
            }
            let mut preflight_args = vec![
                OsString::from("-c"),
                OsString::from(NAMESPACE_PREFLIGHT),
                OsString::from("cargo-cage-namespace-preflight"),
            ];
            preflight_args.extend(namespace_markers);
            let preflight = self.run_inner(
                &plan,
                Path::new("/bin/sh"),
                &preflight_args,
                OutputMode::Capture,
            )?;
            if !preflight.status.successfully_exited()
                || preflight.stdout != NAMESPACE_PREFLIGHT_OUTPUT
            {
                let detail = sandbox_setup_detail(&preflight.stderr);
                return Err(CageError::SandboxSetup(format!(
                    "Bubblewrap could not activate the requested policy or complete its namespace preflight{}. Check unprivileged user namespaces and the host AppArmor policy before retrying",
                    detail,
                )));
            }
            self.run_inner(&plan, &request.program, &request.args, request.output)
        }
    }
}

#[cfg(target_os = "linux")]
struct SandboxPlan {
    current_dir: PathBuf,
    writable_paths: Vec<PathBuf>,
    hidden_paths: Vec<MaskPath>,
    private_paths: Vec<PathBuf>,
    read_only_paths: Vec<PathBuf>,
    cargo_cache_paths: Vec<PathBuf>,
    environment: Environment,
    network: NetworkAccess,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
enum MaskPath {
    Directory(PathBuf),
    File(PathBuf),
}

#[cfg(target_os = "linux")]
impl SandboxPlan {
    fn from_request(request: &SandboxRequest) -> CageResult<Self> {
        let current_dir = canonical_existing_dir(&request.current_dir, "current directory")?;
        let writable_paths = request
            .policy
            .writable_paths
            .iter()
            .map(|path| canonical_path_without_symlink(path, "writable path"))
            .collect::<CageResult<Vec<_>>>()?;
        let read_only_paths = request
            .policy
            .read_only_paths
            .iter()
            .map(|path| canonical_existing_dir(path, "read-only path"))
            .collect::<CageResult<Vec<_>>>()?;
        let mut private_paths = request
            .policy
            .private_paths
            .iter()
            .map(|path| canonical_existing_dir(path, "private path"))
            .collect::<CageResult<Vec<_>>>()?;
        let run_path = canonical_existing_dir(Path::new("/run"), "private path")?;
        if !private_paths.contains(&run_path) {
            private_paths.push(run_path);
        }
        let hidden_paths = request
            .policy
            .hidden_paths
            .iter()
            .map(|path| make_mask(path))
            .collect::<CageResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .filter(|mask| {
                let path: &Path = match mask {
                    MaskPath::Directory(path) | MaskPath::File(path) => path,
                };
                !private_paths.iter().any(|private| {
                    (path == private || path.starts_with(private))
                        && !read_only_paths
                            .iter()
                            .any(|visible| path == visible || path.starts_with(visible))
                })
            })
            .collect::<Vec<_>>();

        validate_read_only_paths(&read_only_paths, &private_paths)?;
        validate_writable_paths(
            &writable_paths,
            &hidden_paths,
            &private_paths,
            &read_only_paths,
        )?;
        let cargo_home = host_cargo_home()?;
        let cargo_cache_paths = cargo_home
            .as_deref()
            .map(|cargo_home| {
                validate_cargo_cache_paths(
                    cargo_home,
                    &writable_paths,
                    &hidden_paths,
                    &private_paths,
                    &read_only_paths,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let environment = merged_environment(request);

        Ok(Self {
            current_dir,
            writable_paths,
            hidden_paths,
            private_paths,
            read_only_paths,
            cargo_cache_paths,
            environment,
            network: request.policy.network,
        })
    }
}

#[cfg(target_os = "linux")]
fn build_bwrap_args(plan: &SandboxPlan, program: &Path, args: &[OsString]) -> Vec<OsString> {
    let mut command = Vec::new();
    push_args(&mut command, ["--ro-bind", "/", "/"]);
    push_args(&mut command, ["--proc", "/proc"]);
    push_args(&mut command, ["--dev", "/dev"]);

    for path in &plan.private_paths {
        push_args(
            &mut command,
            [OsString::from("--tmpfs"), path.clone().into_os_string()],
        );
    }

    push_args(
        &mut command,
        [
            OsString::from("--dir"),
            OsString::from(CARGO_HOME_IN_SANDBOX),
        ],
    );
    for path in &plan.read_only_paths {
        push_args(
            &mut command,
            [
                OsString::from("--ro-bind"),
                path.clone().into_os_string(),
                path.clone().into_os_string(),
            ],
        );
    }

    for source in &plan.cargo_cache_paths {
        let destination = Path::new(CARGO_HOME_IN_SANDBOX).join(
            source
                .file_name()
                .expect("cache path has a final component"),
        );
        push_args(
            &mut command,
            [
                OsString::from("--ro-bind"),
                source.clone().into_os_string(),
                destination.into_os_string(),
            ],
        );
    }

    for mask in &plan.hidden_paths {
        match mask {
            MaskPath::Directory(path) => push_args(
                &mut command,
                [OsString::from("--tmpfs"), path.clone().into_os_string()],
            ),
            MaskPath::File(path) => push_args(
                &mut command,
                [
                    OsString::from("--ro-bind"),
                    OsString::from("/dev/null"),
                    path.clone().into_os_string(),
                ],
            ),
        }
    }

    for path in &plan.writable_paths {
        push_args(
            &mut command,
            [
                OsString::from("--bind"),
                path.clone().into_os_string(),
                path.clone().into_os_string(),
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
                OsString::from(CARGO_HOME_IN_SANDBOX),
            ],
        );
    }

    command.push(OsString::from("--"));
    command.push(program.to_path_buf().into_os_string());
    command.extend(args.iter().cloned());
    command
}

#[cfg(target_os = "linux")]
fn push_args<I, T>(destination: &mut Vec<OsString>, values: I)
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    destination.extend(values.into_iter().map(Into::into));
}

#[cfg(target_os = "linux")]
fn merged_environment(request: &SandboxRequest) -> Environment {
    let mut remove = request.environment.remove.clone();
    for key in &request.policy.remove_environment {
        if !remove.contains(key) {
            remove.push(key.clone());
        }
    }
    let set = request
        .environment
        .set
        .iter()
        .filter(|(key, _)| !remove.contains(key))
        .cloned()
        .collect();
    Environment { set, remove }
}

#[cfg(target_os = "linux")]
fn parent_namespace_markers() -> CageResult<Vec<OsString>> {
    ["mnt", "user", "pid", "ipc", "uts", "net"]
        .into_iter()
        .map(|name| {
            fs::read_link(format!("/proc/self/ns/{name}"))
                .map(|marker| marker.to_string_lossy().into_owned().into())
                .map_err(|error| {
                    CageError::io(
                        format!("could not inspect the parent {name} namespace"),
                        error,
                    )
                })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn host_cargo_home() -> CageResult<Option<PathBuf>> {
    let path = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let Some(path) = path else {
        return Ok(None);
    };
    if !path.is_absolute() {
        return Err(CageError::policy(
            path.display().to_string(),
            "CARGO_HOME must be an absolute path",
            "set CARGO_HOME to the absolute path of a real Cargo home",
        ));
    }
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {
            Ok(Some(canonical_path_without_symlink(&path, "CARGO_HOME")?))
        }
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CageError::policy(
            path.display().to_string(),
            "CARGO_HOME must not be a symlink",
            "set CARGO_HOME to an existing real directory or unset it",
        )),
        Ok(_) => Err(CageError::policy(
            path.display().to_string(),
            "CARGO_HOME must be a directory",
            "remove the conflicting file and set CARGO_HOME to a real directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CageError::io(
            format!("could not inspect CARGO_HOME {}", path.display()),
            error,
        )),
    }
}

#[cfg(target_os = "linux")]
fn validate_cargo_cache_paths(
    cargo_home: &Path,
    writable_paths: &[PathBuf],
    hidden_paths: &[MaskPath],
    private_paths: &[PathBuf],
    read_only_paths: &[PathBuf],
) -> CageResult<Vec<PathBuf>> {
    let mut caches = Vec::new();
    for name in ["registry", "git"] {
        let path = cargo_home.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(CageError::io(
                    format!("could not inspect Cargo cache {}", path.display()),
                    error,
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(CageError::policy(
                path.display().to_string(),
                "Cargo cache mount sources must not be symlinks",
                "remove the symlink or point CARGO_HOME at a real Cargo home",
            ));
        }
        if !metadata.is_dir() {
            return Err(CageError::policy(
                path.display().to_string(),
                "Cargo cache mount sources must be directories",
                "remove the conflicting file or recreate the cache directory",
            ));
        }

        let cache = canonical_path_without_symlink(&path, "Cargo cache")?;
        validate_cache_source_policy(
            &cache,
            writable_paths,
            hidden_paths,
            private_paths,
            read_only_paths,
        )?;
        validate_cache_tree(&cache)?;
        caches.push(cache);
    }
    Ok(caches)
}

#[cfg(target_os = "linux")]
fn validate_cache_source_policy(
    cache: &Path,
    writable_paths: &[PathBuf],
    hidden_paths: &[MaskPath],
    private_paths: &[PathBuf],
    read_only_paths: &[PathBuf],
) -> CageResult<()> {
    if let Some(writable) = writable_paths
        .iter()
        .find(|writable| paths_overlap(cache, writable))
    {
        return Err(CageError::policy(
            cache.display().to_string(),
            format!(
                "a read-only Cargo cache must not overlap writable path {}",
                writable.display()
            ),
            "move CARGO_HOME outside the writable build target",
        ));
    }
    if let Some(hidden) = hidden_paths.iter().find(|hidden| {
        let hidden = match hidden {
            MaskPath::Directory(path) | MaskPath::File(path) => path,
        };
        paths_overlap(cache, hidden)
    }) {
        let hidden = match hidden {
            MaskPath::Directory(path) | MaskPath::File(path) => path,
        };
        return Err(CageError::policy(
            cache.display().to_string(),
            format!(
                "a Cargo cache must not overlap hidden path {}",
                hidden.display()
            ),
            "move CARGO_HOME outside protected home paths",
        ));
    }
    if let Some(private_path) = private_paths.iter().find(|private| {
        paths_overlap(cache, private)
            && !is_reexposed_below_private(cache, private, read_only_paths)
    }) {
        return Err(CageError::policy(
            cache.display().to_string(),
            format!(
                "a Cargo cache must not overlap private filesystem {}",
                private_path.display()
            ),
            "move CARGO_HOME to a persistent host directory outside /tmp and /run",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cache_tree(root: &Path) -> CageResult<()> {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| {
            CageError::io(
                format!("could not inspect Cargo cache {}", directory.display()),
                error,
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                CageError::io(
                    format!("could not inspect Cargo cache {}", directory.display()),
                    error,
                )
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                CageError::io(
                    format!("could not inspect Cargo cache entry {}", path.display()),
                    error,
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(CageError::policy(
                    path.display().to_string(),
                    "mounted Cargo caches must not contain symlinks",
                    "remove the symlink or run cargo fetch in a clean Cargo home",
                ));
            }
            if metadata.is_dir() {
                directories.push(path);
            } else if !metadata.is_file() {
                return Err(CageError::policy(
                    path.display().to_string(),
                    "mounted Cargo caches may contain only regular files and directories",
                    "remove the special file before running cargo-cage",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn canonical_existing_dir(path: &Path, label: &str) -> CageResult<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CageError::io(
            format!("could not inspect {label} {}", path.display()),
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("{label} must be a real directory without symlink resolution"),
            "replace the path with an existing real directory",
        ));
    }
    canonical_path_without_symlink(path, label)
}

#[cfg(target_os = "linux")]
fn canonical_path_without_symlink(path: &Path, label: &str) -> CageResult<PathBuf> {
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
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            CageError::io(
                format!("could not inspect {label} {}", current.display()),
                error,
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CageError::policy(
                path.display().to_string(),
                format!("{label} must not contain symlink components"),
                "replace the symlink component with a real directory or file",
            ));
        }
        if components.peek().is_some() && !metadata.is_dir() {
            return Err(CageError::policy(
                current.display().to_string(),
                format!("{label} parent components must be directories"),
                "remove the conflicting file and retry with a directory path",
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

#[cfg(target_os = "linux")]
fn make_mask(path: &Path) -> CageResult<Option<MaskPath>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CageError::io(
                format!("could not inspect hidden path {}", path.display()),
                error,
            ));
        }
    };
    let resolved = fs::canonicalize(path).map_err(|error| {
        CageError::io(
            format!("could not canonicalize hidden path {}", path.display()),
            error,
        )
    })?;
    if resolved == Path::new("/") {
        return Err(CageError::policy(
            path.display().to_string(),
            "a hidden path must not resolve to the filesystem root",
            "remove the invalid hidden-path entry and retry",
        ));
    }
    let target_metadata = if metadata.file_type().is_symlink() {
        fs::metadata(&resolved).map_err(|error| {
            CageError::io(
                format!(
                    "could not inspect hidden path target {}",
                    resolved.display()
                ),
                error,
            )
        })?
    } else {
        metadata.clone()
    };
    if target_metadata.is_dir() {
        Ok(Some(MaskPath::Directory(resolved)))
    } else {
        Ok(Some(MaskPath::File(resolved)))
    }
}

#[cfg(target_os = "linux")]
fn validate_writable_paths(
    paths: &[PathBuf],
    hidden: &[MaskPath],
    private: &[PathBuf],
    read_only: &[PathBuf],
) -> CageResult<()> {
    for writable in paths {
        if writable == Path::new("/") {
            return Err(CageError::policy(
                writable.display().to_string(),
                "the filesystem root cannot be writable",
                "limit writable_paths to the intended build output directory or lockfile",
            ));
        }
        for mask in hidden {
            let hidden_path = match mask {
                MaskPath::Directory(path) | MaskPath::File(path) => path,
            };
            if writable == hidden_path || writable.starts_with(hidden_path) {
                return Err(CageError::policy(
                    writable.display().to_string(),
                    format!(
                        "the writable path is hidden by policy path {}",
                        hidden_path.display()
                    ),
                    "choose a writable path outside the protected home path",
                ));
            }
            if hidden_path.starts_with(writable) {
                return Err(CageError::policy(
                    writable.display().to_string(),
                    format!(
                        "the writable path would re-expose hidden path {}",
                        hidden_path.display()
                    ),
                    "remove the overlapping writable mount or choose a narrower build directory",
                ));
            }
        }
        for visible in read_only {
            if writable == visible || visible.starts_with(writable) {
                return Err(CageError::policy(
                    writable.display().to_string(),
                    format!(
                        "the writable path would re-expose read-only path {}",
                        visible.display()
                    ),
                    "choose a writable child directory below the read-only workspace",
                ));
            }
        }
        for private_path in private {
            if paths_overlap(writable, private_path)
                && !is_reexposed_below_private(writable, private_path, read_only)
            {
                return Err(CageError::policy(
                    writable.display().to_string(),
                    format!(
                        "the writable path overlaps private filesystem {}",
                        private_path.display()
                    ),
                    "choose a persistent writable path outside the private temporary filesystem",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_read_only_paths(paths: &[PathBuf], private: &[PathBuf]) -> CageResult<()> {
    for visible in paths {
        for private_path in private {
            if visible == private_path || private_path.starts_with(visible) {
                return Err(CageError::policy(
                    visible.display().to_string(),
                    format!(
                        "a read-only mount must not overlap private filesystem {}",
                        private_path.display()
                    ),
                    "mount only the required workspace subdirectory as read-only",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn paths_overlap(first: &Path, second: &Path) -> bool {
    first == second || first.starts_with(second) || second.starts_with(first)
}

#[cfg(target_os = "linux")]
fn is_reexposed_below_private(
    path: &Path,
    private_path: &Path,
    read_only_paths: &[PathBuf],
) -> bool {
    read_only_paths
        .iter()
        .any(|visible| path.starts_with(visible) && visible.starts_with(private_path))
}

#[cfg(target_os = "linux")]
fn find_bwrap() -> CageResult<PathBuf> {
    if let Some(requested) = env::var_os("CARGO_CAGE_BWRAP") {
        let path = PathBuf::from(requested);
        if !path.is_absolute() {
            return Err(CageError::BackendUnavailable(
                "CARGO_CAGE_BWRAP must be an absolute path; set it to the trusted Bubblewrap executable"
                    .to_owned(),
            ));
        }
        return validate_bwrap_path(path);
    }

    for candidate in [Path::new("/usr/bin/bwrap"), Path::new("/bin/bwrap")] {
        if candidate.is_file() {
            return validate_bwrap_path(candidate.to_path_buf());
        }
    }
    Err(CageError::BackendUnavailable(
        "Bubblewrap was not found; install the `bubblewrap` package or set CARGO_CAGE_BWRAP to a trusted absolute executable"
            .to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn validate_bwrap_path(path: PathBuf) -> CageResult<PathBuf> {
    let canonical = fs::canonicalize(&path).map_err(|error| {
        CageError::io(
            format!("could not resolve Bubblewrap executable {}", path.display()),
            error,
        )
    })?;
    if !canonical.is_file() {
        return Err(CageError::BackendUnavailable(format!(
            "Bubblewrap path {} is not a regular file; install Bubblewrap or set CARGO_CAGE_BWRAP to a regular executable",
            canonical.display(),
        )));
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn bwrap_version(path: &Path) -> CageResult<(u32, u32, u32)> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|source| CageError::ProcessSpawn {
            program: path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(CageError::BackendUnavailable(format!(
            "{} --version failed with {:?}; install a working Bubblewrap executable",
            path.display(),
            output.status.code(),
        )));
    }
    parse_version(&output.stdout).ok_or_else(|| {
        CageError::BackendUnavailable(format!(
            "could not parse Bubblewrap version from {}; install Bubblewrap >= 0.8",
            String::from_utf8_lossy(&output.stdout).trim(),
        ))
    })
}

#[cfg(target_os = "linux")]
fn parse_version(output: &[u8]) -> Option<(u32, u32, u32)> {
    let text = String::from_utf8_lossy(output);
    text.split_whitespace().find_map(|token| {
        let token = token.trim_start_matches(['v', 'V']);
        let mut parts = token.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts
            .next()
            .and_then(|part| {
                part.split(|character: char| !character.is_ascii_digit())
                    .next()
            })
            .and_then(|part| part.parse().ok())
            .unwrap_or(0);
        Some((major, minor, patch))
    })
}

#[cfg(target_os = "linux")]
fn version_at_least(actual: (u32, u32, u32), required: (u32, u32, u32)) -> bool {
    actual >= required
}

#[cfg(target_os = "linux")]
fn sandbox_setup_detail(output: &[u8]) -> String {
    let text = String::from_utf8_lossy(output);
    let text = text.trim();
    if text.is_empty() {
        return String::new();
    }

    let apparmor_hint = if text.contains("RTM_NEWADDR") && text.contains("Operation not permitted")
    {
        " Ubuntu 24.04 AppArmor may be blocking the unprivileged user namespace; allow Bubblewrap in the host policy before retrying."
    } else {
        ""
    };
    format!(": {text}.{apparmor_hint}")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn accepts_required_bubblewrap_versions() {
        assert_eq!(parse_version(b"bubblewrap 0.8.0\n"), Some((0, 8, 0)));
        assert_eq!(parse_version(b"bubblewrap 0.11.2\n"), Some((0, 11, 2)));
        assert!(version_at_least((0, 8, 0), (0, 8, 0)));
        assert!(version_at_least((0, 9, 0), (0, 8, 0)));
        assert!(!version_at_least((0, 7, 0), (0, 8, 0)));
    }

    #[test]
    fn builds_fail_closed_bwrap_arguments() {
        let plan = SandboxPlan {
            current_dir: PathBuf::from("/workspace"),
            writable_paths: vec![PathBuf::from("/workspace/target")],
            hidden_paths: vec![MaskPath::Directory(PathBuf::from("/home/user/.ssh"))],
            private_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/run")],
            read_only_paths: vec![PathBuf::from("/workspace")],
            cargo_cache_paths: vec![
                PathBuf::from("/home/user/.cargo/registry"),
                PathBuf::from("/home/user/.cargo/git"),
            ],
            environment: Environment {
                set: vec![(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"))],
                remove: vec![OsString::from("SSH_AUTH_SOCK")],
            },
            network: NetworkAccess::Deny,
        };
        let args = build_bwrap_args(
            &plan,
            Path::new("/usr/bin/cargo"),
            &[OsString::from("build")],
        );

        assert!(contains_pair(&args, "--ro-bind", "/", "/"));
        assert!(contains_pair(
            &args,
            "--ro-bind",
            "/workspace",
            "/workspace"
        ));
        assert!(contains_pair(
            &args,
            "--bind",
            "/workspace/target",
            "/workspace/target"
        ));
        assert!(contains_pair(&args, "--tmpfs", "/home/user/.ssh", ""));
        assert!(contains_pair(
            &args,
            "--ro-bind",
            "/home/user/.cargo/registry",
            "/run/cargo-cage-home/registry"
        ));
        assert!(contains_pair(
            &args,
            "--ro-bind",
            "/home/user/.cargo/git",
            "/run/cargo-cage-home/git"
        ));
        assert!(!args.iter().any(|arg| arg == "config.toml"));
        assert!(!args.iter().any(|arg| arg == "config"));
        assert!(args.iter().any(|arg| arg == "--unshare-net"));
        assert!(args.iter().any(|arg| arg == "--unshare-user"));
        assert!(args.iter().any(|arg| arg == "--unshare-ipc"));
        assert!(args.iter().any(|arg| arg == "--unshare-pid"));
        assert!(args.iter().any(|arg| arg == "--unshare-uts"));
        assert!(args.iter().any(|arg| arg == "--disable-userns"));
        assert!(args.iter().any(|arg| arg == "--assert-userns-disabled"));
        assert!(args.iter().any(|arg| arg == "--cap-drop"));
        assert!(args.iter().any(|arg| arg == "ALL"));
        assert!(args.iter().any(|arg| arg == "--new-session"));
        assert!(args.iter().any(|arg| arg == "--die-with-parent"));
        assert!(args.iter().any(|arg| arg == "--"));
        assert!(!args.iter().any(|arg| arg == "--share-net"));

        let allow_plan = SandboxPlan {
            network: NetworkAccess::Allow,
            ..plan
        };
        let allow_args = build_bwrap_args(&allow_plan, Path::new("/usr/bin/cargo"), &[]);
        assert!(!allow_args.iter().any(|arg| arg == "--unshare-net"));
    }

    #[test]
    fn policy_removals_win_over_environment_sets() {
        let mut request = SandboxRequest::new("/bin/sh", "/");
        request.environment = Environment {
            set: vec![
                (
                    OsString::from("AWS_SECRET_ACCESS_KEY"),
                    OsString::from("must-not-escape"),
                ),
                (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
            ],
            remove: Vec::new(),
        };
        request.policy.remove_environment = vec![OsString::from("AWS_SECRET_ACCESS_KEY")];

        let environment = merged_environment(&request);
        assert_eq!(environment.set.len(), 1);
        assert_eq!(environment.set[0].0, OsString::from("CARGO_NET_OFFLINE"));
        assert_eq!(
            environment.remove,
            vec![OsString::from("AWS_SECRET_ACCESS_KEY")]
        );

        let plan = SandboxPlan {
            current_dir: PathBuf::from("/"),
            writable_paths: Vec::new(),
            hidden_paths: Vec::new(),
            private_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/run")],
            read_only_paths: Vec::new(),
            cargo_cache_paths: Vec::new(),
            environment,
            network: NetworkAccess::Deny,
        };
        let args = build_bwrap_args(&plan, Path::new("/bin/sh"), &[]);
        assert!(!contains_pair(
            &args,
            "--setenv",
            "AWS_SECRET_ACCESS_KEY",
            "must-not-escape"
        ));
        assert!(contains_pair(
            &args,
            "--setenv",
            "CARGO_NET_OFFLINE",
            "true"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cargo_cache_root() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let cargo_home = root.path().join("cargo-home");
        let external = root.path().join("external");
        fs::create_dir(&cargo_home).expect("create Cargo home");
        fs::create_dir(&external).expect("create external cache");
        symlink(&external, cargo_home.join("registry")).expect("create cache symlink");

        let error =
            validate_cargo_cache_paths(&cargo_home, &[], &[], &[], &[]).expect_err("symlink cache");
        let text = error.to_string();
        assert!(text.contains("Cargo cache"), "{text}");
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_inside_cargo_cache() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let cargo_home = root.path().join("cargo-home");
        let registry = cargo_home.join("registry");
        let external = root.path().join("external");
        fs::create_dir(&cargo_home).expect("create Cargo home");
        fs::create_dir(&registry).expect("create registry cache");
        fs::create_dir(&external).expect("create external cache");
        symlink(&external, registry.join("escape")).expect("create nested cache symlink");

        let error = validate_cargo_cache_paths(&cargo_home, &[], &[], &[], &[])
            .expect_err("nested symlink cache");
        let text = error.to_string();
        assert!(text.contains("mounted Cargo caches"), "{text}");
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[test]
    fn rejects_cache_sources_overlapping_writable_or_hidden_paths() {
        let writable_error = validate_cache_source_policy(
            Path::new("/workspace/target/cargo-home/registry"),
            &[PathBuf::from("/workspace/target")],
            &[],
            &[],
            &[],
        )
        .expect_err("cache under writable target");
        assert!(writable_error.to_string().contains("writable path"));

        let hidden_error = validate_cache_source_policy(
            Path::new("/home/user/.ssh/cargo/registry"),
            &[],
            &[MaskPath::Directory(PathBuf::from("/home/user/.ssh"))],
            &[],
            &[],
        )
        .expect_err("cache under hidden path");
        assert!(hidden_error.to_string().contains("hidden path"));

        validate_cache_source_policy(
            Path::new("/tmp/workspace/cargo-home/registry"),
            &[],
            &[],
            &[PathBuf::from("/tmp")],
            &[PathBuf::from("/tmp/workspace")],
        )
        .expect("cache below explicitly re-exposed workspace");
    }

    #[test]
    fn rejects_writable_parent_of_hidden_path() {
        let error = validate_writable_paths(
            &[PathBuf::from("/home/user")],
            &[MaskPath::Directory(PathBuf::from("/home/user/.ssh"))],
            &[],
            &[],
        )
        .expect_err("writable parent would reveal hidden path");
        assert!(error.to_string().contains("re-expose"));
    }

    #[test]
    fn explains_ubuntu_namespace_permission_failure() {
        let detail =
            sandbox_setup_detail(b"bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted\n");
        assert!(detail.contains("AppArmor"));
        assert!(detail.contains("allow Bubblewrap"));
    }

    #[test]
    fn rejects_paths_overlapping_private_filesystems() {
        let error = validate_writable_paths(
            &[PathBuf::from("/tmp/build")],
            &[],
            &[PathBuf::from("/tmp")],
            &[],
        )
        .expect_err("writable path would re-expose private tmp");
        let text = error.to_string();
        assert!(text.contains("private filesystem"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[test]
    fn rejects_writable_parent_of_read_only_path() {
        let error = validate_writable_paths(
            &[PathBuf::from("/workspace")],
            &[],
            &[],
            &[PathBuf::from("/workspace/src")],
        )
        .expect_err("writable parent would re-expose source tree");
        let text = error.to_string();
        assert!(text.contains("read-only path"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[test]
    fn allows_workspace_reexposure_below_private_tmp() {
        validate_read_only_paths(&[PathBuf::from("/tmp/workspace")], &[PathBuf::from("/tmp")])
            .expect("workspace child can be re-exposed");
        validate_writable_paths(
            &[PathBuf::from("/tmp/workspace/target")],
            &[],
            &[PathBuf::from("/tmp")],
            &[PathBuf::from("/tmp/workspace")],
        )
        .expect("target below re-exposed workspace can be writable");
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::{SystemTime, UNIX_EPOCH};

            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!("cargo-cage-linux-test-{timestamp}-{id}"));
            fs::create_dir(&path).expect("create test directory");
            Self(fs::canonicalize(path).expect("canonical test directory"))
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

    fn contains_pair(args: &[OsString], option: &str, first: &str, second: &str) -> bool {
        args.windows(3).any(|window| {
            window[0] == option && window[1] == first && (second.is_empty() || window[2] == second)
        })
    }
}
