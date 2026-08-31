use cage_core::{CageError, CageResult, SandboxBackend, SandboxOutcome, SandboxRequest};
#[cfg(target_os = "linux")]
use cage_core::{Environment, NetworkAccess, OutputMode, ProcessStatus};
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::path::{Component, Path};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
const MIN_BWRAP_MAJOR: u32 = 0;
#[cfg(target_os = "linux")]
const MIN_BWRAP_MINOR: u32 = 12;
#[cfg(target_os = "linux")]
const MIN_BWRAP_PATCH: u32 = 0;
#[cfg(target_os = "linux")]
const CARGO_HOME_IN_SANDBOX: &str = "/run/cargo-cage-home";
#[cfg(target_os = "linux")]
const FD_SCRUBBER_SHELL: &str = "/bin/bash";
#[cfg(target_os = "linux")]
const NAMESPACE_PREFLIGHT_OUTPUT: &[u8] = b"cargo-cage-namespace-preflight-ok\n";
#[cfg(target_os = "linux")]
const NAMESPACE_PREFLIGHT: &str = r#"set -eu
fail() {
  printf 'cargo-cage preflight check failed: %s\n' "$1" >&2
  exit 1
}
[ -x /usr/bin/readlink ] || fail "readlink is unavailable"
[ -x /usr/bin/grep ] || fail "grep is unavailable"
[ -x /usr/bin/ps ] || fail "ps is unavailable"
[ -x /usr/bin/tr ] || fail "tr is unavailable"
mnt=$(/usr/bin/readlink /proc/self/ns/mnt) || fail "mount namespace cannot be inspected"
user=$(/usr/bin/readlink /proc/self/ns/user) || fail "user namespace cannot be inspected"
pid=$(/usr/bin/readlink /proc/self/ns/pid) || fail "PID namespace cannot be inspected"
ipc=$(/usr/bin/readlink /proc/self/ns/ipc) || fail "IPC namespace cannot be inspected"
uts=$(/usr/bin/readlink /proc/self/ns/uts) || fail "UTS namespace cannot be inspected"
net=$(/usr/bin/readlink /proc/self/ns/net) || fail "network namespace cannot be inspected"
[ -n "$mnt" ] && [ "$mnt" != "$1" ] || fail "mount namespace was not isolated"
[ -n "$user" ] && [ "$user" != "$2" ] || fail "user namespace was not isolated"
[ -n "$pid" ] && [ "$pid" != "$3" ] || fail "PID namespace was not isolated"
[ -n "$ipc" ] && [ "$ipc" != "$4" ] || fail "IPC namespace was not isolated"
[ -n "$uts" ] && [ "$uts" != "$5" ] || fail "UTS namespace was not isolated"
if [ -n "${6:-}" ]; then
  [ -n "$net" ] && [ "$net" != "$6" ] || fail "network namespace was not isolated"
fi
for capability in CapEff CapPrm CapInh CapBnd CapAmb; do
  /usr/bin/grep -Eq "^${capability}:[[:space:]]+0+$" /proc/self/status \
    || fail "$capability is not empty"
done
/usr/bin/grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status \
  || fail "NoNewPrivs is not enabled"
session=$(/usr/bin/ps -o sid= -p $$ | /usr/bin/tr -d '[:space:]') \
  || fail "session ID cannot be inspected"
parent_session="$7"
[ -n "$session" ] && [ -n "$parent_session" ] \
  || fail "session IDs are unavailable"
[ "$session" != "$parent_session" ] \
  || fail "sandbox kept the parent session"
session_leader=$(/usr/bin/ps -o sid= -p 1 | /usr/bin/tr -d '[:space:]') \
  || fail "sandbox session leader cannot be inspected"
[ "$session" = "$session_leader" ] \
  || fail "sandbox command is not in Bubblewrap's new session"
printf '%s\n' cargo-cage-namespace-preflight-ok
"#;
#[cfg(target_os = "linux")]
const FD_SCRUBBER: &str = r#"set -eu
[ -d /proc/self/fd ] || {
  printf 'cargo-cage file-descriptor scrubber failed: /proc/self/fd is unavailable\n' >&2
  exit 125
}
for fd_path in /proc/self/fd/*; do
  fd=${fd_path##*/}
  case "$fd" in
    ''|*[!0-9]*) continue ;;
  esac
  if [ "$fd" -ge 3 ]; then
    eval "exec ${fd}>&-"
  fi
done
exec "$@"
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
            if !version_at_least(version, (MIN_BWRAP_MAJOR, MIN_BWRAP_MINOR, MIN_BWRAP_PATCH)) {
                return Err(CageError::BackendUnavailable(format!(
                    "{} is too old; Bubblewrap >= {}.{}.{} is required; install a newer Bubblewrap or set CARGO_CAGE_BWRAP to a trusted absolute executable",
                    bwrap.display(),
                    MIN_BWRAP_MAJOR,
                    MIN_BWRAP_MINOR,
                    MIN_BWRAP_PATCH
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
        if !plan.environment.inherit {
            command.env_clear();
        }
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
    runtime_mounts: Vec<BindMount>,
    writable_paths: Vec<PathBuf>,
    hidden_paths: Vec<MaskPath>,
    private_paths: Vec<PathBuf>,
    read_only_paths: Vec<PathBuf>,
    cargo_cache_paths: Vec<PathBuf>,
    environment: Environment,
    network: NetworkAccess,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct BindMount {
    source: PathBuf,
    destination: PathBuf,
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
        let runtime_mounts = runtime_mounts()?;
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
            .collect::<Vec<_>>();

        validate_program_path(
            &request.program,
            &runtime_mounts,
            &writable_paths,
            &read_only_paths,
        )?;

        let cargo_home = host_cargo_home()?;
        if let Some(cargo_home) = cargo_home.as_ref() {
            if cargo_home == Path::new("/") {
                return Err(CageError::policy(
                    cargo_home.display().to_string(),
                    "CARGO_HOME must not be the filesystem root",
                    "set CARGO_HOME to a real Cargo home directory",
                ));
            }
            let already_private = private_paths
                .iter()
                .any(|private| cargo_home == private || cargo_home.starts_with(private));
            let would_be_reexposed_by_parent = read_only_paths
                .iter()
                .any(|visible| cargo_home == visible || cargo_home.starts_with(visible));
            let would_hide_runtime = runtime_mounts.iter().any(|mount| {
                cargo_home.as_path() == mount.destination
                    || mount.destination.starts_with(cargo_home)
            });
            if would_hide_runtime {
                return Err(CageError::policy(
                    cargo_home.display().to_string(),
                    "CARGO_HOME must not cover a required Linux runtime mount",
                    "set CARGO_HOME below a dedicated directory outside /usr, /bin, /lib, and /etc",
                ));
            }
            if !already_private && !would_be_reexposed_by_parent {
                private_paths.push(cargo_home.clone());
            }
        }

        validate_read_only_paths(&read_only_paths, &private_paths, &hidden_paths)?;
        validate_writable_paths(
            &writable_paths,
            &hidden_paths,
            &private_paths,
            &read_only_paths,
        )?;
        for path in &writable_paths {
            validate_writable_tree(path)?;
        }
        for path in unique_mount_roots(&read_only_paths) {
            validate_read_only_tree(path, &writable_paths)?;
        }
        let cargo_cache_paths = cargo_home
            .as_deref()
            .map(|cargo_home| {
                validate_cargo_cache_paths(cargo_home, &writable_paths, &hidden_paths)
            })
            .transpose()?
            .unwrap_or_default();
        let environment = merged_environment(request);

        Ok(Self {
            current_dir,
            runtime_mounts,
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
fn runtime_mounts() -> CageResult<Vec<BindMount>> {
    let required = ["/usr", "/bin", "/lib", "/etc"];
    let optional = ["/sbin", "/lib64", "/lib32"];
    let mut mounts = Vec::new();

    for path in required {
        if let Some(mount) = runtime_mount(Path::new(path), true)? {
            mounts.push(mount);
        }
    }
    for path in optional {
        if let Some(mount) = runtime_mount(Path::new(path), false)? {
            mounts.push(mount);
        }
    }
    Ok(mounts)
}

#[cfg(target_os = "linux")]
fn runtime_mount(path: &Path, required: bool) -> CageResult<Option<BindMount>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => {
            return Err(CageError::io(
                format!("could not inspect required runtime path {}", path.display()),
                error,
            ));
        }
    };
    if !metadata.is_dir() {
        return Err(CageError::policy(
            path.display().to_string(),
            "runtime mount sources must be directories",
            "install the required Linux runtime directories before running cargo-cage",
        ));
    }

    let source = fs::canonicalize(path).map_err(|error| {
        CageError::io(
            format!("could not canonicalize runtime path {}", path.display()),
            error,
        )
    })?;
    if source == Path::new("/") {
        return Err(CageError::policy(
            path.display().to_string(),
            "a runtime mount must not resolve to the filesystem root",
            "install a normal Linux runtime layout and retry",
        ));
    }
    Ok(Some(BindMount {
        source,
        destination: path.to_path_buf(),
    }))
}

#[cfg(target_os = "linux")]
fn validate_program_path(
    program: &Path,
    runtime_mounts: &[BindMount],
    writable_paths: &[PathBuf],
    read_only_paths: &[PathBuf],
) -> CageResult<()> {
    if !program.is_absolute() {
        return Err(CageError::policy(
            program.display().to_string(),
            "the sandbox program path must be absolute",
            "pass an absolute executable path to the sandbox backend",
        ));
    }
    if program
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(CageError::policy(
            program.display().to_string(),
            "the sandbox program path must not contain parent-directory traversal",
            "pass the canonical executable path without `..` components",
        ));
    }
    if !fs::metadata(program).is_ok_and(|metadata| metadata.is_file()) {
        return Err(CageError::policy(
            program.display().to_string(),
            "the sandbox program must be an existing regular file",
            "select an installed Cargo, shell, or toolchain executable",
        ));
    }

    let visible = runtime_mounts
        .iter()
        .any(|mount| program == mount.destination || program.starts_with(&mount.destination))
        || writable_paths
            .iter()
            .any(|path| program == path || program.starts_with(path))
        || read_only_paths
            .iter()
            .any(|path| program == path || program.starts_with(path));
    if !visible {
        return Err(CageError::policy(
            program.display().to_string(),
            "the sandbox program is not covered by an allowed filesystem mount",
            "add the executable to the selected toolchain/runtime or use a supported Cargo path",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn push_private_parent_directories(
    args: &mut Vec<OsString>,
    private_paths: &[PathBuf],
    runtime_mounts: &[BindMount],
) {
    let mut directories = Vec::new();
    for path in private_paths {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == Path::new("/") {
                break;
            }
            if runtime_mounts.iter().any(|mount| {
                directory == mount.destination || directory.starts_with(&mount.destination)
            }) {
                break;
            }
            if !directories.iter().any(|item| item == directory) {
                directories.push(directory.to_path_buf());
            }
            parent = directory.parent();
        }
    }
    directories.sort_by_key(|path| path.components().count());
    for directory in directories {
        push_args(args, [OsString::from("--dir"), directory.into_os_string()]);
    }
}

#[cfg(target_os = "linux")]
fn push_mount_parent_directories(
    args: &mut Vec<OsString>,
    paths: &[PathBuf],
    private_paths: &[PathBuf],
    runtime_mounts: &[BindMount],
) {
    let mut directories = Vec::new();
    for path in paths {
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == Path::new("/") {
                break;
            }
            if private_paths
                .iter()
                .any(|private| directory == private || directory.starts_with(private))
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
    for directory in directories {
        push_args(args, [OsString::from("--dir"), directory.into_os_string()]);
    }
}

#[cfg(target_os = "linux")]
fn build_bwrap_args(plan: &SandboxPlan, program: &Path, args: &[OsString]) -> Vec<OsString> {
    let mut command = Vec::new();
    for mount in &plan.runtime_mounts {
        push_args(
            &mut command,
            [
                OsString::from("--ro-bind"),
                mount.source.clone().into_os_string(),
                mount.destination.clone().into_os_string(),
            ],
        );
    }
    push_args(&mut command, ["--proc", "/proc"]);
    push_args(&mut command, ["--dev", "/dev"]);

    push_private_parent_directories(&mut command, &plan.private_paths, &plan.runtime_mounts);

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
    push_mount_parent_directories(
        &mut command,
        &plan.read_only_paths,
        &plan.private_paths,
        &plan.runtime_mounts,
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
                OsString::from(CARGO_HOME_IN_SANDBOX),
            ],
        );
    }

    command.push(OsString::from("--"));
    // dash (Ubuntu's /bin/sh) only accepts short file-descriptor numbers in
    // redirections. Bash handles the high descriptors Cargo's jobserver may
    // provide, while the script itself remains fixed and argument-safe.
    command.push(PathBuf::from(FD_SCRUBBER_SHELL).into_os_string());
    command.push(OsString::from("-c"));
    command.push(OsString::from(FD_SCRUBBER));
    command.push(OsString::from("cargo-cage-fd-scrubber"));
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
    for (key, _) in &request.environment.set {
        if is_protected_environment_name(key) && !remove.contains(key) {
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
    Environment {
        inherit: request.environment.inherit,
        set,
        remove,
    }
}

#[cfg(target_os = "linux")]
fn is_protected_environment_name(name: &OsString) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let name = name.to_ascii_uppercase();
    name.starts_with("AWS_")
        || name == "TOKEN"
        || name.ends_with("_TOKEN")
        || name.ends_with("_TOKENS")
        || name == "PASSWORD"
        || name.ends_with("_PASSWORD")
        || name == "PASS"
        || name.ends_with("_PASS")
        || name == "SECRET"
        || name.ends_with("_SECRET")
        || name.ends_with("_SECRET_KEY")
        || name == "CREDENTIAL"
        || name.ends_with("_CREDENTIAL")
        || name == "PRIVATE_KEY"
        || name.ends_with("_PRIVATE_KEY")
        || name == "API_KEY"
        || name.ends_with("_API_KEY")
        || name == "ACCESS_KEY"
        || name.ends_with("_ACCESS_KEY")
        || name.starts_with("SSH_")
        || name.starts_with("GPG_")
        || name.ends_with("_AGENT")
        || name.ends_with("_AGENT_INFO")
        || name.ends_with("_AGENT_PID")
        || name.ends_with("_AUTH_SOCK")
}

#[cfg(target_os = "linux")]
fn parent_namespace_markers() -> CageResult<Vec<OsString>> {
    let mut markers = ["mnt", "user", "pid", "ipc", "uts", "net"]
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
        .collect::<CageResult<Vec<_>>>()?;
    markers.push(parent_session_marker()?);
    Ok(markers)
}

#[cfg(target_os = "linux")]
fn parent_session_marker() -> CageResult<OsString> {
    let pid = std::process::id().to_string();
    let output = Command::new("/usr/bin/ps")
        .env_clear()
        .args(["-o", "sid=", "-p", &pid])
        .output()
        .map_err(|source| CageError::ProcessSpawn {
            program: PathBuf::from("/usr/bin/ps"),
            source,
        })?;
    if !output.status.success() {
        return Err(CageError::SandboxSetup(
            "could not determine the parent session ID; install procps and retry".to_owned(),
        ));
    }
    let marker = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if marker.is_empty() || !marker.chars().all(|character| character.is_ascii_digit()) {
        return Err(CageError::SandboxSetup(
            "the parent session ID was invalid; install a working procps package and retry"
                .to_owned(),
        ));
    }
    Ok(marker.into())
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
    if path == Path::new("/") {
        return Err(CageError::policy(
            path.display().to_string(),
            "CARGO_HOME must not be the filesystem root",
            "set CARGO_HOME to a real Cargo home directory",
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
        validate_cache_source_policy(&cache, writable_paths, hidden_paths)?;
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
    // Cache sources are mounted read-only at the private CARGO_HOME
    // destination. They may therefore live below a private host path (for
    // example a test-specific CARGO_HOME below /tmp), as long as they do not
    // overlap a writable or hidden path and the cache tree passed validation.
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cache_tree(root: &Path) -> CageResult<()> {
    validate_tree(root, TreeKind::Cache, &[])
}

#[cfg(target_os = "linux")]
fn validate_writable_tree(root: &Path) -> CageResult<()> {
    validate_tree(root, TreeKind::Writable, &[])
}

#[cfg(target_os = "linux")]
fn validate_read_only_tree(root: &Path, excluded_paths: &[PathBuf]) -> CageResult<()> {
    validate_tree(root, TreeKind::ReadOnly, excluded_paths)
}

#[cfg(target_os = "linux")]
fn unique_mount_roots(paths: &[PathBuf]) -> Vec<&PathBuf> {
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

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum TreeKind {
    Cache,
    ReadOnly,
    Writable,
}

#[cfg(target_os = "linux")]
fn validate_tree(root: &Path, kind: TreeKind, excluded_paths: &[PathBuf]) -> CageResult<()> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        CageError::io(
            format!("could not inspect {} {}", tree_label(kind), root.display()),
            error,
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
            CageError::io(
                format!(
                    "could not inspect {} {}",
                    tree_label(kind),
                    directory.display()
                ),
                error,
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                CageError::io(
                    format!(
                        "could not inspect {} {}",
                        tree_label(kind),
                        directory.display()
                    ),
                    error,
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
                CageError::io(
                    format!(
                        "could not inspect {} entry {}",
                        tree_label(kind),
                        path.display()
                    ),
                    error,
                )
            })?;
            if metadata.file_type().is_symlink() {
                if matches!(kind, TreeKind::ReadOnly) {
                    let resolved = fs::canonicalize(&path).map_err(|error| {
                        CageError::io(
                            format!("could not resolve read-only symlink {}", path.display()),
                            error,
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

#[cfg(target_os = "linux")]
fn tree_label(kind: TreeKind) -> &'static str {
    match kind {
        TreeKind::Cache => "Cargo cache",
        TreeKind::ReadOnly => "read-only",
        TreeKind::Writable => "writable",
    }
}

#[cfg(target_os = "linux")]
fn validate_hardlink_aliases(files: &[(PathBuf, fs::Metadata)], label: &str) -> CageResult<()> {
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

#[cfg(target_os = "linux")]
fn validate_no_nested_mounts(root: &Path, label: &str) -> CageResult<()> {
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

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(encoded: &str) -> Option<PathBuf> {
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
    if !path.is_absolute() {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("{label} must be an absolute path"),
            "pass an absolute path before starting the sandbox",
        ));
    }
    let mut current = PathBuf::new();
    let mut components = path.components().peekable();
    if path.to_string_lossy().split('/').any(|part| part == "..") {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("{label} must not contain parent-directory traversal"),
            "pass the canonical path without `..` components",
        ));
    }
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
    if metadata.file_type().is_symlink() {
        return Err(CageError::policy(
            path.display().to_string(),
            "hidden paths must not be symlinks",
            "replace the symlink with a real file or directory before running cargo-cage",
        ));
    }
    let resolved = canonical_path_without_symlink(path, "hidden path")?;
    if resolved == Path::new("/") {
        return Err(CageError::policy(
            path.display().to_string(),
            "a hidden path must not resolve to the filesystem root",
            "remove the invalid hidden-path entry and retry",
        ));
    }
    if metadata.is_dir() {
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
fn validate_read_only_paths(
    paths: &[PathBuf],
    private: &[PathBuf],
    hidden: &[MaskPath],
) -> CageResult<()> {
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
        for hidden_path in hidden {
            let hidden_path = match hidden_path {
                MaskPath::Directory(path) | MaskPath::File(path) => path,
            };
            if paths_overlap(visible, hidden_path) {
                return Err(CageError::policy(
                    visible.display().to_string(),
                    format!(
                        "a read-only mount would re-expose hidden path {}",
                        hidden_path.display()
                    ),
                    "choose a source path outside protected home and credential paths",
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
        "Bubblewrap >= 0.12.0 was not found; install a patched `bubblewrap` package or set CARGO_CAGE_BWRAP to a trusted absolute executable"
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
    let mode = fs::metadata(&canonical)
        .map_err(|error| {
            CageError::io(
                format!(
                    "could not inspect Bubblewrap permissions {}",
                    canonical.display()
                ),
                error,
            )
        })?
        .permissions()
        .mode();
    if mode & 0o111 == 0 {
        return Err(CageError::BackendUnavailable(format!(
            "Bubblewrap {} is not executable; install a working Bubblewrap >= 0.12.0",
            canonical.display()
        )));
    }
    if mode & 0o4000 != 0 {
        return Err(CageError::BackendUnavailable(format!(
            "Bubblewrap {} is setuid; install a non-setuid Bubblewrap >= 0.12.0",
            canonical.display()
        )));
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn bwrap_version(path: &Path) -> CageResult<(u32, u32, u32)> {
    let output = Command::new(path)
        .env_clear()
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
            "could not parse Bubblewrap version from {}; install Bubblewrap >= 0.12.0",
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
        assert_eq!(parse_version(b"bubblewrap 0.12.0\n"), Some((0, 12, 0)));
        assert_eq!(parse_version(b"bubblewrap 0.11.2\n"), Some((0, 11, 2)));
        assert!(version_at_least(
            (0, 12, 0),
            (MIN_BWRAP_MAJOR, MIN_BWRAP_MINOR, MIN_BWRAP_PATCH)
        ));
        assert!(version_at_least(
            (0, 13, 0),
            (MIN_BWRAP_MAJOR, MIN_BWRAP_MINOR, MIN_BWRAP_PATCH)
        ));
        assert!(!version_at_least(
            (0, 11, 2),
            (MIN_BWRAP_MAJOR, MIN_BWRAP_MINOR, MIN_BWRAP_PATCH)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_setuid_bubblewrap() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestDirectory::new();
        let bwrap = root.path().join("bwrap");
        fs::write(&bwrap, b"not a real executable").expect("write test Bubblewrap");
        let mut permissions = fs::metadata(&bwrap)
            .expect("read test Bubblewrap metadata")
            .permissions();
        permissions.set_mode(0o4755);
        fs::set_permissions(&bwrap, permissions).expect("setuid test Bubblewrap");
        if fs::metadata(&bwrap)
            .expect("read setuid test Bubblewrap metadata")
            .permissions()
            .mode()
            & 0o4000
            == 0
        {
            return;
        }

        let error = validate_bwrap_path(bwrap).expect_err("setuid Bubblewrap");
        assert!(error.to_string().contains("setuid"));
        assert!(error.to_string().contains("0.12.0"));
    }

    #[test]
    fn runtime_mounts_are_explicit_and_never_include_host_root() {
        if !Path::new("/lib").exists() {
            return;
        }
        let mounts = runtime_mounts().expect("reference runtime paths");
        assert!(
            mounts
                .iter()
                .any(|mount| mount.destination == Path::new("/usr"))
        );
        assert!(
            mounts
                .iter()
                .any(|mount| mount.destination == Path::new("/etc"))
        );
        assert!(
            !mounts
                .iter()
                .any(|mount| mount.destination == Path::new("/"))
        );
        assert!(!mounts.iter().any(|mount| mount.source == Path::new("/")));
    }

    #[test]
    fn builds_fail_closed_bwrap_arguments() {
        let plan = SandboxPlan {
            current_dir: PathBuf::from("/workspace"),
            runtime_mounts: vec![
                BindMount {
                    source: PathBuf::from("/usr"),
                    destination: PathBuf::from("/usr"),
                },
                BindMount {
                    source: PathBuf::from("/usr/bin"),
                    destination: PathBuf::from("/bin"),
                },
            ],
            writable_paths: vec![PathBuf::from("/workspace/target")],
            hidden_paths: vec![MaskPath::Directory(PathBuf::from("/home/user/.ssh"))],
            private_paths: vec![
                PathBuf::from("/home/user"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
                PathBuf::from("/run"),
            ],
            read_only_paths: vec![PathBuf::from("/workspace")],
            cargo_cache_paths: vec![
                PathBuf::from("/home/user/.cargo/registry"),
                PathBuf::from("/home/user/.cargo/git"),
            ],
            environment: Environment {
                inherit: true,
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

        assert!(contains_pair(&args, "--ro-bind", "/usr", "/usr"));
        assert!(contains_pair(&args, "--ro-bind", "/usr/bin", "/bin"));
        assert!(!contains_pair(&args, "--ro-bind", "/", "/"));
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
        assert!(contains_pair(&args, "--tmpfs", "/home/user", ""));
        assert!(contains_pair(&args, "--tmpfs", "/var/tmp", ""));
        assert!(contains_pair(&args, "--dir", "/home", ""));
        assert!(contains_pair(&args, "--dir", "/var", ""));
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
        let command_separator = args
            .iter()
            .position(|arg| arg == "--")
            .expect("bubblewrap command separator");
        assert_eq!(args[command_separator + 1], FD_SCRUBBER_SHELL);
        assert_eq!(args[command_separator + 2], "-c");
        assert_eq!(args[command_separator + 3], FD_SCRUBBER);
        assert!(!args.iter().any(|arg| arg == "--share-net"));
        assert!(!args.iter().any(|arg| arg == "--clearenv"));
        assert!(!args.iter().any(|arg| arg == "--seccomp"));
        assert!(!args.iter().any(|arg| arg == "--add-seccomp-fd"));
        assert!(NAMESPACE_PREFLIGHT.contains("NoNewPrivs"));
        assert!(NAMESPACE_PREFLIGHT.contains("CapEff"));
        assert!(NAMESPACE_PREFLIGHT.contains("CapBnd"));
        assert!(NAMESPACE_PREFLIGHT.contains("parent_session=\"$7\""));
        assert!(NAMESPACE_PREFLIGHT.contains("session_leader="));
        assert!(FD_SCRUBBER.contains("/proc/self/fd"));
        assert!(FD_SCRUBBER.contains("eval \"exec ${fd}>&-\""));

        let allow_plan = SandboxPlan {
            network: NetworkAccess::Allow,
            ..plan
        };
        let allow_args = build_bwrap_args(&allow_plan, Path::new("/usr/bin/cargo"), &[]);
        assert!(!allow_args.iter().any(|arg| arg == "--unshare-net"));
    }

    #[test]
    fn clean_environment_is_explicitly_applied_to_bubblewrap() {
        let plan = SandboxPlan {
            current_dir: PathBuf::from("/workspace"),
            runtime_mounts: Vec::new(),
            writable_paths: Vec::new(),
            hidden_paths: Vec::new(),
            private_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/run")],
            read_only_paths: Vec::new(),
            cargo_cache_paths: Vec::new(),
            environment: Environment::clean().set("PATH", "/usr/bin"),
            network: NetworkAccess::Deny,
        };
        let args = build_bwrap_args(&plan, Path::new("/bin/sh"), &[]);
        assert!(args.iter().any(|arg| arg == "--clearenv"));
        assert!(contains_pair(&args, "--setenv", "PATH", "/usr/bin"));
    }

    #[test]
    fn policy_removals_win_over_environment_sets() {
        let mut request = SandboxRequest::new("/bin/sh", "/");
        request.environment = Environment {
            inherit: false,
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
            runtime_mounts: Vec::new(),
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

    #[test]
    fn protected_environment_sets_are_removed_even_without_policy_entries() {
        let mut request = SandboxRequest::new("/bin/sh", "/");
        request.environment = Environment::clean()
            .set("AWS_ARBITRARY_SECRET", "must-not-escape")
            .set("SERVICE_TOKEN", "must-not-escape")
            .set("NORMAL_VALUE", "allowed");

        let environment = merged_environment(&request);
        assert!(
            !environment
                .set
                .iter()
                .any(|(key, _)| key == "AWS_ARBITRARY_SECRET" || key == "SERVICE_TOKEN")
        );
        assert!(
            environment
                .set
                .iter()
                .any(|(key, value)| key == "NORMAL_VALUE" && value == "allowed")
        );
        assert!(
            environment
                .remove
                .iter()
                .any(|key| key == "AWS_ARBITRARY_SECRET")
        );
        assert!(environment.remove.iter().any(|key| key == "SERVICE_TOKEN"));
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

        let error = validate_cargo_cache_paths(&cargo_home, &[], &[]).expect_err("symlink cache");
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

        let error =
            validate_cargo_cache_paths(&cargo_home, &[], &[]).expect_err("nested symlink cache");
        let text = error.to_string();
        assert!(text.contains("Cargo cache"), "{text}");
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_hardlink_alias_outside_validated_tree() {
        let root = TestDirectory::new();
        let inside = root.path().join("inside");
        let outside = root.path().join("outside");
        fs::write(&outside, b"secret").expect("write external file");
        fs::hard_link(&outside, &inside).expect("create external hardlink");

        let files = vec![(
            inside.clone(),
            fs::metadata(&inside).expect("inside metadata"),
        )];
        let error = validate_hardlink_aliases(&files, "read-only").expect_err("external alias");
        let text = error.to_string();
        assert!(text.contains("hardlink"), "{text}");
        assert!(text.contains(&inside.display().to_string()), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn accepts_hardlink_aliases_inside_validated_tree() {
        let root = TestDirectory::new();
        let first = root.path().join("first");
        let second = root.path().join("second");
        fs::write(&first, b"internal").expect("write internal file");
        fs::hard_link(&first, &second).expect("create internal hardlink");

        let files = vec![
            (first.clone(), fs::metadata(&first).expect("first metadata")),
            (
                second.clone(),
                fs::metadata(&second).expect("second metadata"),
            ),
        ];
        validate_hardlink_aliases(&files, "writable").expect("internal aliases are safe");
    }

    #[test]
    fn decodes_mountinfo_escaped_paths() {
        assert_eq!(
            decode_mountinfo_path("/tmp/path\\040with\\011escapes"),
            Some(PathBuf::from("/tmp/path with\tescapes"))
        );
        assert_eq!(decode_mountinfo_path("/tmp/invalid\\08"), None);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_hidden_path_instead_of_masking_its_target() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let target = root.path().join("real-secret");
        let link = root.path().join("hidden-secret");
        fs::write(&target, b"secret").expect("write hidden target");
        symlink(&target, &link).expect("create hidden symlink");

        let error = make_mask(&link).expect_err("symlinked hidden path");
        let text = error.to_string();
        assert!(text.contains("hidden paths"), "{text}");
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[test]
    fn rejects_cache_sources_overlapping_writable_or_hidden_paths() {
        let writable_error = validate_cache_source_policy(
            Path::new("/workspace/target/cargo-home/registry"),
            &[PathBuf::from("/workspace/target")],
            &[],
        )
        .expect_err("cache under writable target");
        assert!(writable_error.to_string().contains("writable path"));

        let hidden_error = validate_cache_source_policy(
            Path::new("/home/user/.ssh/cargo/registry"),
            &[],
            &[MaskPath::Directory(PathBuf::from("/home/user/.ssh"))],
        )
        .expect_err("cache under hidden path");
        assert!(hidden_error.to_string().contains("hidden path"));

        validate_cache_source_policy(Path::new("/tmp/workspace/cargo-home/registry"), &[], &[])
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
    fn rejects_relative_mount_paths() {
        let error = canonical_path_without_symlink(Path::new("relative/path"), "writable path")
            .expect_err("relative writable path");
        let text = error.to_string();
        assert!(text.contains("absolute path"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[test]
    fn rejects_parent_directory_traversal_in_mount_paths() {
        let error = canonical_path_without_symlink(Path::new("/workspace/../outside"), "target")
            .expect_err("parent traversal");
        let text = error.to_string();
        assert!(text.contains("parent-directory traversal"), "{text}");
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
    fn rejects_read_only_mount_that_re_exposes_hidden_path() {
        let error = validate_read_only_paths(
            &[PathBuf::from("/home/user")],
            &[PathBuf::from("/home")],
            &[MaskPath::Directory(PathBuf::from("/home/user/.ssh"))],
        )
        .expect_err("read-only home mount would reveal hidden SSH directory");
        let text = error.to_string();
        assert!(text.contains("re-expose"), "{text}");
        assert!(text.contains(".ssh"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[test]
    fn allows_workspace_reexposure_below_private_tmp() {
        validate_read_only_paths(
            &[PathBuf::from("/tmp/workspace")],
            &[PathBuf::from("/tmp")],
            &[],
        )
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
