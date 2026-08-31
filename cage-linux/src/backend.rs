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
                    "{} is too old; Bubblewrap >= {}.{} is required",
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
        request: &SandboxRequest,
        plan: &SandboxPlan,
        program: &Path,
        args: &[OsString],
        output_mode: OutputMode,
    ) -> CageResult<SandboxOutcome> {
        let mut command = Command::new(&self.bwrap);
        command.args(build_bwrap_args(plan, program, args));
        command.current_dir(&plan.current_dir);
        command.envs(
            request
                .environment
                .set
                .iter()
                .map(|(key, value)| (key, value)),
        );
        for key in request
            .environment
            .remove
            .iter()
            .chain(request.policy.remove_environment.iter())
        {
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
                request,
                &plan,
                Path::new("/bin/sh"),
                &preflight_args,
                OutputMode::Capture,
            )?;
            if !preflight.status.successfully_exited()
                || preflight.stdout != NAMESPACE_PREFLIGHT_OUTPUT
            {
                let detail = format_output(&preflight.stderr);
                return Err(CageError::SandboxSetup(format!(
                    "Bubblewrap could not activate the requested policy or complete its namespace preflight{}",
                    detail
                )));
            }
            self.run_inner(
                request,
                &plan,
                &request.program,
                &request.args,
                request.output,
            )
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
    cargo_home: Option<PathBuf>,
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
        validate_writable_paths(&writable_paths, &hidden_paths)?;
        let cargo_home = host_cargo_home()?;
        let environment = merged_environment(request);

        Ok(Self {
            current_dir,
            writable_paths,
            hidden_paths,
            private_paths,
            read_only_paths,
            cargo_home,
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
    if let Some(cargo_home) = &plan.cargo_home {
        for name in ["registry", "git"] {
            let source = cargo_home.join(name);
            let destination = Path::new(CARGO_HOME_IN_SANDBOX).join(name);
            push_args(
                &mut command,
                [
                    OsString::from("--ro-bind-try"),
                    source.into_os_string(),
                    destination.into_os_string(),
                ],
            );
        }
        for name in ["config.toml", "config"] {
            let source = cargo_home.join(name);
            // A symlink could make a config mount expose a credentials file.
            if is_real_regular_file(&source) {
                let destination = Path::new(CARGO_HOME_IN_SANDBOX).join(name);
                push_args(
                    &mut command,
                    [
                        OsString::from("--ro-bind"),
                        source.into_os_string(),
                        destination.into_os_string(),
                    ],
                );
            }
        }
    }

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
    push_args(
        &mut command,
        [
            OsString::from("--setenv"),
            OsString::from("CARGO_HOME"),
            OsString::from(CARGO_HOME_IN_SANDBOX),
        ],
    );

    command.push(OsString::from("--"));
    command.push(program.to_path_buf().into_os_string());
    command.extend(args.iter().cloned());
    command
}

#[cfg(target_os = "linux")]
fn is_real_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
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
    Environment {
        set: request.environment.set.clone(),
        remove,
    }
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
        return Err(CageError::Policy(
            "CARGO_HOME must be absolute when it is set".to_owned(),
        ));
    }
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {
            Ok(Some(fs::canonicalize(&path).map_err(|error| {
                CageError::io(
                    format!("could not canonicalize CARGO_HOME {}", path.display()),
                    error,
                )
            })?))
        }
        Ok(_) => Err(CageError::Policy(format!(
            "CARGO_HOME {} is not a directory",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CageError::io(
            format!("could not inspect CARGO_HOME {}", path.display()),
            error,
        )),
    }
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
        return Err(CageError::Policy(format!(
            "{label} {} must be a real directory",
            path.display()
        )));
    }
    fs::canonicalize(path).map_err(|error| {
        CageError::io(
            format!("could not canonicalize {label} {}", path.display()),
            error,
        )
    })
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
            return Err(CageError::Policy(format!(
                "{label} {} must not contain symlink components",
                path.display()
            )));
        }
        if components.peek().is_some() && !metadata.is_dir() {
            return Err(CageError::Policy(format!(
                "{label} parent {} is not a directory",
                current.display()
            )));
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
        return Err(CageError::Policy(format!(
            "hidden path {} resolves to the filesystem root",
            path.display()
        )));
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
fn validate_writable_paths(paths: &[PathBuf], hidden: &[MaskPath]) -> CageResult<()> {
    for writable in paths {
        if writable == Path::new("/") {
            return Err(CageError::Policy(
                "the filesystem root cannot be writable".to_owned(),
            ));
        }
        for mask in hidden {
            let hidden_path = match mask {
                MaskPath::Directory(path) | MaskPath::File(path) => path,
            };
            if writable == hidden_path || writable.starts_with(hidden_path) {
                return Err(CageError::Policy(format!(
                    "writable path {} is hidden by policy",
                    writable.display()
                )));
            }
            if hidden_path.starts_with(writable) {
                return Err(CageError::Policy(format!(
                    "writable path {} would re-expose hidden path {}",
                    writable.display(),
                    hidden_path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_read_only_paths(paths: &[PathBuf], private: &[PathBuf]) -> CageResult<()> {
    for visible in paths {
        for private_path in private {
            if visible == private_path {
                return Err(CageError::Policy(format!(
                    "read-only path {} would disable its private filesystem",
                    visible.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn find_bwrap() -> CageResult<PathBuf> {
    if let Some(requested) = env::var_os("CARGO_CAGE_BWRAP") {
        let path = PathBuf::from(requested);
        if !path.is_absolute() {
            return Err(CageError::BackendUnavailable(
                "CARGO_CAGE_BWRAP must be an absolute path".to_owned(),
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
        "Bubblewrap was not found; install the `bubblewrap` package or set CARGO_CAGE_BWRAP"
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
            "Bubblewrap path {} is not a regular file",
            canonical.display()
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
            "{} --version failed with {:?}",
            path.display(),
            output.status.code()
        )));
    }
    parse_version(&output.stdout).ok_or_else(|| {
        CageError::BackendUnavailable(format!(
            "could not parse Bubblewrap version from {}",
            String::from_utf8_lossy(&output.stdout).trim()
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
fn format_output(output: &[u8]) -> String {
    let text = String::from_utf8_lossy(output);
    let text = text.trim();
    if text.is_empty() {
        String::new()
    } else {
        format!(": {text}")
    }
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
            cargo_home: None,
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
        assert!(args.iter().any(|arg| arg == "--unshare-net"));
        assert!(args.iter().any(|arg| arg == "--disable-userns"));
        assert!(args.iter().any(|arg| arg == "--assert-userns-disabled"));
        assert!(args.iter().any(|arg| arg == "--cap-drop"));
        assert!(args.iter().any(|arg| arg == "ALL"));
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
    fn rejects_writable_parent_of_hidden_path() {
        let error = validate_writable_paths(
            &[PathBuf::from("/home/user")],
            &[MaskPath::Directory(PathBuf::from("/home/user/.ssh"))],
        )
        .expect_err("writable parent would reveal hidden path");
        assert!(error.to_string().contains("re-expose"));
    }

    fn contains_pair(args: &[OsString], option: &str, first: &str, second: &str) -> bool {
        args.windows(3).any(|window| {
            window[0] == option && window[1] == first && (second.is_empty() || window[2] == second)
        })
    }
}
