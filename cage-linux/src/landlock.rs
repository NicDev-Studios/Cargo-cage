use cage_core::{CageError, CageResult};
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd,
    RestrictionStatus, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
    make_bitflags,
};
use std::ffi::{OsStr, OsString};
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const INTERNAL_LAUNCHER_ARG: &str = "__cargo_cage_landlock_exec";
pub const LAUNCHER_DESTINATION: &str = "/run/cargo-cage-landlock-launcher";
pub const LAUNCHER_SETUP_EXIT_CODE: i32 = 125;

const LANDLOCK_MIN_ABI: ABI = ABI::V5;

const READ_ARGS: &str = "--landlock-read";
const EXECUTE_ARGS: &str = "--landlock-execute";
const WRITE_ARGS: &str = "--landlock-write";
const LOCKFILE_ARGS: &str = "--landlock-lockfile";
const PRIVATE_ARGS: &str = "--landlock-private";
const PROC_ARGS: &str = "--landlock-proc";
const DEVICE_ARGS: &str = "--landlock-device";
const NETWORK_DENY_ARGS: &str = "--landlock-network-deny";

#[derive(Debug)]
struct LandlockFeatures {
    filesystem_abi: ABI,
    scope_supported: bool,
}

trait LandlockProbe {
    fn supports_filesystem_abi(&self, abi: ABI) -> bool;
    fn supports_scope_abi_v6(&self) -> bool;
}

struct KernelLandlockProbe;

impl LandlockProbe for KernelLandlockProbe {
    fn supports_filesystem_abi(&self, abi: ABI) -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .is_ok()
    }

    fn supports_scope_abi_v6(&self) -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .scope(Scope::from_all(ABI::V6))
            .is_ok()
    }
}

#[derive(Debug)]
struct LauncherPlan {
    read_paths: Vec<PathBuf>,
    execute_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    lockfile_paths: Vec<PathBuf>,
    private_paths: Vec<PathBuf>,
    proc_paths: Vec<PathBuf>,
    device_paths: Vec<PathBuf>,
    network_deny: bool,
    program: PathBuf,
    args: Vec<OsString>,
}

impl LauncherPlan {
    fn parse(args: &[OsString]) -> CageResult<Self> {
        let mut plan = Self {
            read_paths: Vec::new(),
            execute_paths: Vec::new(),
            write_paths: Vec::new(),
            lockfile_paths: Vec::new(),
            private_paths: Vec::new(),
            proc_paths: Vec::new(),
            device_paths: Vec::new(),
            network_deny: false,
            program: PathBuf::new(),
            args: Vec::new(),
        };
        let mut index = 0;
        while index < args.len() {
            if args[index] == OsStr::new("--") {
                let program = args.get(index + 1).ok_or_else(|| {
                    CageError::InvalidInvocation(
                        "internal Landlock launcher is missing its program".to_owned(),
                    )
                })?;
                plan.program = validate_launcher_path(program, "internal launcher program")?;
                plan.args.extend(args.iter().skip(index + 2).cloned());
                return Ok(plan);
            }

            let option = args[index].to_string_lossy();
            match option.as_ref() {
                READ_ARGS => plan
                    .read_paths
                    .push(next_path(args, &mut index, READ_ARGS)?),
                EXECUTE_ARGS => plan
                    .execute_paths
                    .push(next_path(args, &mut index, EXECUTE_ARGS)?),
                WRITE_ARGS => plan
                    .write_paths
                    .push(next_path(args, &mut index, WRITE_ARGS)?),
                LOCKFILE_ARGS => {
                    plan.lockfile_paths
                        .push(next_path(args, &mut index, LOCKFILE_ARGS)?)
                }
                PRIVATE_ARGS => plan
                    .private_paths
                    .push(next_path(args, &mut index, PRIVATE_ARGS)?),
                PROC_ARGS => plan
                    .proc_paths
                    .push(next_path(args, &mut index, PROC_ARGS)?),
                DEVICE_ARGS => plan
                    .device_paths
                    .push(next_path(args, &mut index, DEVICE_ARGS)?),
                NETWORK_DENY_ARGS => {
                    plan.network_deny = true;
                    index += 1;
                }
                _ => {
                    return Err(CageError::InvalidInvocation(format!(
                        "unknown internal Landlock launcher option {option}"
                    )));
                }
            }
        }

        Err(CageError::InvalidInvocation(
            "internal Landlock launcher is missing the -- program separator".to_owned(),
        ))
    }
}

fn next_path(args: &[OsString], index: &mut usize, option: &str) -> CageResult<PathBuf> {
    let value = args.get(*index + 1).ok_or_else(|| {
        CageError::InvalidInvocation(format!(
            "internal Landlock launcher option {option} needs a path"
        ))
    })?;
    *index += 2;
    validate_launcher_path(value, option)
}

fn validate_launcher_path(value: &OsStr, label: &str) -> CageResult<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("{label} must be an absolute sandbox path"),
            "use the canonical absolute destination generated by cargo-cage",
        ));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(CageError::policy(
            path.display().to_string(),
            format!("{label} must not contain parent-directory traversal"),
            "use a normalized sandbox path without parent-directory components",
        ));
    }
    Ok(path)
}

/// Run the internal launcher after Bubblewrap has completed its setup.
///
/// This entry point is intentionally not part of the user-facing command
/// parser. It always applies a deny-by-default Landlock ruleset before it
/// starts the requested child and has no option to disable or widen it.
pub fn run_internal_launcher(args: &[OsString]) -> CageResult<i32> {
    let plan = LauncherPlan::parse(args)?;
    let status = apply_landlock(&plan)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(landlock_setup_error(
            "Landlock did not report a fully enforced ruleset with no_new_privs",
            "run on a Linux kernel with Landlock ABI 5 or newer and retry",
        ));
    }

    let child = Command::new(&plan.program)
        .args(&plan.args)
        .status()
        .map_err(|error| {
            CageError::io(
                format!(
                    "could not start sandboxed program {}",
                    plan.program.display()
                ),
                error,
            )
        })?;
    Ok(child
        .code()
        .unwrap_or_else(|| 128 + child.signal().unwrap_or(1)))
}

fn apply_landlock(plan: &LauncherPlan) -> CageResult<RestrictionStatus> {
    let features = required_landlock_features(&KernelLandlockProbe)?;
    let fs_abi = features.filesystem_abi;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(fs_abi))
        .map_err(|error| {
            landlock_setup_error(
                format!("could not configure required filesystem rights: {error}"),
                "run on a kernel that supports Landlock filesystem ABI 5",
            )
        })?;
    if plan.network_deny {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(ABI::V4))
            .map_err(|error| {
                landlock_setup_error(
                    format!("could not configure required TCP network denial: {error}"),
                    "run on a kernel that supports Landlock TCP rights or fix the Linux kernel",
                )
            })?;
    }
    if features.scope_supported {
        ruleset = ruleset.scope(Scope::from_all(ABI::V6)).map_err(|error| {
            landlock_setup_error(
                format!("could not configure Unix-socket and signal scope denial: {error}"),
                "run on a kernel with working Landlock scope support",
            )
        })?;
    }
    let mut created = ruleset.create().map_err(|error| {
        landlock_setup_error(
            format!("could not create the Landlock ruleset: {error}"),
            "enable Landlock in the Linux kernel and retry",
        )
    })?;

    for path in &plan.read_paths {
        created = add_path_rule(created, path, read_access(), "read-only")?;
    }
    for path in &plan.execute_paths {
        created = add_path_rule(created, path, execute_access(), "executable")?;
    }
    for path in &plan.write_paths {
        created = add_path_rule(created, path, write_access(), "writable")?;
    }
    for path in &plan.lockfile_paths {
        created = add_path_rule(created, path, lockfile_access(), "lockfile")?;
    }
    for path in &plan.private_paths {
        created = add_path_rule(created, path, private_access(), "private")?;
    }
    for path in &plan.proc_paths {
        created = add_path_rule(created, path, proc_access(), "procfs")?;
    }
    for path in &plan.device_paths {
        created = add_path_rule(created, path, device_access(), "device")?;
    }

    created.restrict_self().map_err(|error| {
        landlock_setup_error(
            format!("could not enforce the Landlock ruleset: {error}"),
            "use a Linux kernel with enabled unprivileged Landlock and no_new_privs support",
        )
    })
}

fn read_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir})
}

fn execute_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir})
}

fn write_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{
        Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeDir | MakeReg
        | MakeSym | Refer | Truncate
    })
}

fn private_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{
        Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeDir | MakeReg
        | MakeSock | MakeFifo | MakeSym | Refer | Truncate
    })
}

fn lockfile_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | WriteFile | Truncate})
}

fn proc_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir})
}

fn device_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir | WriteFile})
}

fn add_path_rule(
    created: landlock::RulesetCreated,
    path: &Path,
    access: landlock::BitFlags<AccessFs>,
    kind: &str,
) -> CageResult<landlock::RulesetCreated> {
    let fd = PathFd::new(path).map_err(|error| {
        landlock_setup_error(
            format!(
                "could not open {kind} Landlock path {}: {error}",
                path.display()
            ),
            "ensure every sandbox destination exists after Bubblewrap setup",
        )
    })?;
    created
        .add_rule(PathBeneath::new(fd, access))
        .map_err(|error| {
            landlock_setup_error(
                format!(
                    "could not add {kind} Landlock rule for {}: {error}",
                    path.display()
                ),
                "remove the conflicting mount and retry with canonical sandbox paths",
            )
        })
}

fn required_landlock_features<P: LandlockProbe>(probe: &P) -> CageResult<LandlockFeatures> {
    if !probe.supports_filesystem_abi(LANDLOCK_MIN_ABI) {
        return Err(landlock_setup_error(
            "the running kernel does not provide the required Landlock filesystem ABI 5",
            "enable Landlock or upgrade to a Linux kernel with ABI 5 or newer",
        ));
    }
    Ok(LandlockFeatures {
        filesystem_abi: if probe.supports_filesystem_abi(ABI::V9) {
            ABI::V9
        } else {
            LANDLOCK_MIN_ABI
        },
        scope_supported: probe.supports_scope_abi_v6(),
    })
}

fn landlock_setup_error(detail: impl Into<String>, remedy: impl Into<String>) -> CageError {
    CageError::SandboxSetup(format!(
        "Landlock setup failed for path sandbox-policy: {}; rule: every required Landlock restriction must be enforced before the child starts; remedy: {}",
        detail.into(),
        remedy.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_requires_absolute_paths_without_traversal() {
        let relative = validate_launcher_path(OsStr::new("target"), "test");
        assert!(relative.is_err());

        let traversal = validate_launcher_path(OsStr::new("/run/../tmp"), "test");
        assert!(traversal.is_err());
    }

    #[test]
    fn launcher_parser_keeps_program_arguments_after_separator() {
        let plan = LauncherPlan::parse(&[
            OsString::from(READ_ARGS),
            OsString::from("/usr"),
            OsString::from("--"),
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("exit 0"),
        ])
        .expect("parse launcher plan");
        assert_eq!(plan.program, PathBuf::from("/bin/sh"));
        assert_eq!(plan.args, [OsString::from("-c"), OsString::from("exit 0")]);
    }

    #[test]
    fn launcher_rejects_unknown_options() {
        let error = LauncherPlan::parse(&[OsString::from("--disable-landlock")])
            .expect_err("unknown option");
        assert!(error.to_string().contains("unknown internal Landlock"));
    }

    #[test]
    fn setup_exit_code_is_reserved_for_launcher_failures() {
        assert_eq!(LAUNCHER_SETUP_EXIT_CODE, 125);
    }

    struct FakeLandlockProbe {
        filesystem_abi: ABI,
        scope_supported: bool,
    }

    impl LandlockProbe for FakeLandlockProbe {
        fn supports_filesystem_abi(&self, abi: ABI) -> bool {
            self.filesystem_abi >= abi
        }

        fn supports_scope_abi_v6(&self) -> bool {
            self.scope_supported
        }
    }

    #[test]
    fn missing_required_landlock_fails_closed_without_a_runtime_switch() {
        let error = required_landlock_features(&FakeLandlockProbe {
            filesystem_abi: ABI::Unsupported,
            scope_supported: false,
        })
        .expect_err("missing Landlock");
        let text = error.to_string();
        assert!(text.contains("ABI 5"), "{text}");
        assert!(text.contains("remedy:"), "{text}");
    }

    #[test]
    fn feature_probe_selects_the_strongest_known_filesystem_abi() {
        let features = required_landlock_features(&FakeLandlockProbe {
            filesystem_abi: ABI::V9,
            scope_supported: true,
        })
        .expect("Landlock features");
        assert_eq!(features.filesystem_abi, ABI::V9);
        assert!(features.scope_supported);
    }

    #[test]
    fn writable_policy_does_not_grant_device_or_special_file_creation() {
        let access = write_access();
        assert!(!access.contains(AccessFs::MakeChar));
        assert!(!access.contains(AccessFs::MakeBlock));
        assert!(!access.contains(AccessFs::MakeSock));
        assert!(!access.contains(AccessFs::MakeFifo));
        assert!(!access.contains(AccessFs::IoctlDev));
        assert!(access.contains(AccessFs::Refer));
        assert!(access.contains(AccessFs::Truncate));
    }

    #[test]
    fn private_policy_allows_process_temporary_sockets_but_not_devices() {
        let access = private_access();
        assert!(access.contains(AccessFs::MakeSock));
        assert!(access.contains(AccessFs::MakeFifo));
        assert!(!access.contains(AccessFs::MakeChar));
        assert!(!access.contains(AccessFs::MakeBlock));
        assert!(!access.contains(AccessFs::IoctlDev));
    }

    #[test]
    fn lockfile_policy_cannot_modify_directories() {
        let access = lockfile_access();
        assert!(access.contains(AccessFs::ReadFile));
        assert!(access.contains(AccessFs::WriteFile));
        assert!(access.contains(AccessFs::Truncate));
        assert!(!access.contains(AccessFs::ReadDir));
        assert!(!access.contains(AccessFs::MakeReg));
        assert!(!access.contains(AccessFs::RemoveFile));
    }
}
