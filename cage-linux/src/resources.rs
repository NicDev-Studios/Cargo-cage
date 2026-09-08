use cage_core::{CageError, CageResult, ResourceLimitKind, ResourceLimits};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MIN_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
const CPU_PERIOD_MICROS: u64 = 100_000;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const SIGXFSZ: i32 = 25;

static NEXT_CGROUP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EffectiveResourceLimits {
    pub(super) max_processes: u64,
    pub(super) max_memory_bytes: u64,
    pub(super) max_cpu_cores: u32,
    pub(super) max_wall_time: Duration,
    pub(super) max_file_size_bytes: u64,
    pub(super) max_open_files: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EventCounters {
    memory_max: u64,
    memory_oom_kill: u64,
    pids_max: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResourceReport {
    pub(super) limits: EffectiveResourceLimits,
    before: EventCounters,
    after: EventCounters,
}

impl ResourceReport {
    pub(super) fn resource_error(
        &self,
        status: &std::process::ExitStatus,
        wall_time_expired: bool,
    ) -> Option<CageError> {
        if wall_time_expired {
            return Some(resource_limit_error(
                ResourceLimitKind::WallTime,
                format_duration(self.limits.max_wall_time),
                status,
                "the sandbox watchdog terminated the process tree after the wall-clock budget expired",
                "split the build, reduce its workload, or run it in a trusted environment",
            ));
        }

        if self.after.memory_oom_kill > self.before.memory_oom_kill
            || self.after.memory_max > self.before.memory_max
        {
            return Some(resource_limit_error(
                ResourceLimitKind::Memory,
                format_bytes(self.limits.max_memory_bytes),
                status,
                "the cgroup memory controller reported a memory limit event",
                "reduce parallelism or build size, or run the workload in a trusted environment",
            ));
        }

        if self.after.pids_max > self.before.pids_max {
            return Some(resource_limit_error(
                ResourceLimitKind::Processes,
                self.limits.max_processes.to_string(),
                status,
                "the cgroup process controller reported that pids.max was reached",
                "reduce child-process parallelism or run the workload in a trusted environment",
            ));
        }

        if status.signal() == Some(SIGXFSZ) || status.code() == Some(128 + SIGXFSZ) {
            return Some(resource_limit_error(
                ResourceLimitKind::FileSize,
                format_bytes(self.limits.max_file_size_bytes),
                status,
                "the process was terminated after exceeding RLIMIT_FSIZE",
                "reduce generated file sizes or run the workload in a trusted environment",
            ));
        }

        None
    }
}

pub(super) struct ResourceGroup {
    restore: PathBuf,
    path: PathBuf,
    limits: EffectiveResourceLimits,
    before: EventCounters,
    entered: bool,
    finished: bool,
}

impl ResourceGroup {
    pub(super) fn prepare(requested: ResourceLimits) -> CageResult<Self> {
        let context = CgroupContext::discover(requested)?;
        let path = create_child_cgroup(&context.parent)?;
        if let Err(error) = configure_cgroup(&path, context.limits) {
            let _ = fs::remove_dir(&path);
            return Err(error);
        }

        let before = match read_events(&path) {
            Ok(events) => events,
            Err(error) => {
                let _ = fs::remove_dir(&path);
                return Err(cgroup_setup_error(
                    path.display().to_string(),
                    "resource event counters must be readable before the child starts",
                    "use a delegated cgroup v2 subtree with readable memory.events and pids.events",
                    error.to_string(),
                ));
            }
        };

        Ok(Self {
            restore: context.restore,
            path,
            limits: context.limits,
            before,
            entered: false,
            finished: false,
        })
    }

    pub(super) fn limits(&self) -> EffectiveResourceLimits {
        self.limits
    }

    pub(super) fn apply_inherited_limits(&mut self) -> CageResult<()> {
        self.limits.max_file_size_bytes = set_lower_limit(
            Resource::Fsize,
            self.limits.max_file_size_bytes,
            "RLIMIT_FSIZE",
        )?;
        self.limits.max_open_files = set_lower_limit(
            Resource::Nofile,
            self.limits.max_open_files,
            "RLIMIT_NOFILE",
        )?;
        let _ = set_lower_limit(Resource::Core, 0, "RLIMIT_CORE")?;
        Ok(())
    }

    pub(super) fn enter_current_process(&mut self) -> CageResult<()> {
        write_pid(&self.path.join("cgroup.procs"), "enter the resource cgroup")?;
        self.entered = true;
        Ok(())
    }

    pub(super) fn restore_current_process(&mut self) -> CageResult<()> {
        write_pid(
            &self.restore.join("cgroup.procs"),
            "restore the cargo-cage supervisor",
        )?;
        self.entered = false;
        Ok(())
    }

    pub(super) fn kill_all(&self) -> CageResult<()> {
        fs::write(self.path.join("cgroup.kill"), b"1\n").map_err(|error| {
            cgroup_setup_error(
                self.path.display().to_string(),
                "the entire sandbox process tree must be killable through cgroup.kill",
                "use a delegated Linux cgroup v2 subtree with cgroup.kill support",
                error.to_string(),
            )
        })?;

        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            if cgroup_is_empty(&self.path)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(cgroup_setup_error(
                    self.path.display().to_string(),
                    "all sandbox descendants must exit during resource cleanup",
                    "terminate the remaining process tree and retry on a working cgroup v2 host",
                    "cgroup remained populated after cgroup.kill",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn finish(mut self) -> CageResult<ResourceReport> {
        if self.entered {
            self.restore_current_process()?;
        }
        if !cgroup_is_empty(&self.path)? {
            self.kill_all()?;
        }
        let after = read_events(&self.path).map_err(|error| {
            cgroup_setup_error(
                self.path.display().to_string(),
                "resource event counters must remain readable after the child exits",
                "use a delegated cgroup v2 subtree with readable event files",
                error.to_string(),
            )
        })?;
        fs::remove_dir(&self.path).map_err(|error| {
            cgroup_setup_error(
                self.path.display().to_string(),
                "the empty resource cgroup must be removable after the child exits",
                "remove stale child processes from the delegated cgroup and retry",
                error.to_string(),
            )
        })?;
        self.finished = true;
        Ok(ResourceReport {
            limits: self.limits,
            before: self.before,
            after,
        })
    }
}

impl Drop for ResourceGroup {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut supervisor_restored = true;
        if self.entered {
            supervisor_restored =
                write_pid(&self.restore.join("cgroup.procs"), "restore the supervisor").is_ok();
            if supervisor_restored {
                self.entered = false;
            }
        }
        if supervisor_restored {
            let _ = self.kill_all();
        }
        let _ = fs::remove_dir(&self.path);
    }
}

#[derive(Debug)]
struct CgroupContext {
    parent: PathBuf,
    restore: PathBuf,
    limits: EffectiveResourceLimits,
}

impl CgroupContext {
    fn discover(requested: ResourceLimits) -> CageResult<Self> {
        if !requested.validate() {
            return Err(cgroup_setup_error(
                "ResourceLimits",
                "every resource limit must be positive and within the fixed cargo-cage profile",
                "use positive limits no larger than the documented cargo-cage defaults",
                "the requested resource profile is invalid or attempts to raise a hard limit",
            ));
        }

        let mount = find_cgroup2_mount()?;
        let relative = current_cgroup_path()?;
        let parent = if relative == Path::new("/") {
            mount.clone()
        } else {
            mount.join(relative.strip_prefix("/").unwrap_or(&relative))
        };
        let restore = canonical_directory_without_symlinks(&parent, "current cgroup")?;
        require_writable(
            &restore.join("cgroup.procs"),
            "restoring the cargo-cage supervisor",
        )?;
        let parent = find_delegated_parent(&mount, &restore)?;

        let host_memory = host_memory_bytes()?;
        let host_budget = host_memory
            .checked_mul(3)
            .and_then(|value| value.checked_div(4))
            .ok_or_else(|| {
                cgroup_setup_error(
                    "/proc/meminfo",
                    "the host memory budget must be representable safely",
                    "run on a Linux host with a normal MemTotal value",
                    "memory budget arithmetic overflowed",
                )
            })?;
        let parent_budget = read_optional_limit(&parent.join("memory.max"))?;
        let max_memory_bytes = requested
            .max_memory_bytes
            .min(host_budget)
            .min(parent_budget.unwrap_or(u64::MAX));
        if max_memory_bytes < MIN_MEMORY_BYTES {
            return Err(cgroup_setup_error(
                parent.display().to_string(),
                "the effective memory budget must be at least 1 GiB",
                "run on a host with more memory or configure a larger delegated parent budget",
                format!(
                    "effective memory budget is {}",
                    format_bytes(max_memory_bytes)
                ),
            ));
        }

        Ok(Self {
            parent,
            restore,
            limits: EffectiveResourceLimits {
                max_processes: requested.max_processes,
                max_memory_bytes,
                max_cpu_cores: requested.max_cpu_cores,
                max_wall_time: requested.max_wall_time,
                max_file_size_bytes: requested.max_file_size_bytes,
                max_open_files: requested.max_open_files,
            },
        })
    }
}

fn find_delegated_parent(mount: &Path, restore: &Path) -> CageResult<PathBuf> {
    let mut candidate = restore.to_path_buf();
    loop {
        if has_required_controllers(&candidate)? && can_create_child(&candidate)? {
            return Ok(candidate);
        }
        if candidate == mount {
            break;
        }
        if !candidate.pop() {
            break;
        }
    }

    Err(cgroup_setup_error(
        restore.display().to_string(),
        "an ancestor cgroup must delegate cpu, memory, and pids to a private child",
        "run inside a user-delegated cgroup subtree with those controllers enabled on its parent",
        format!(
            "no usable delegated ancestor was found between {} and {}",
            restore.display(),
            mount.display()
        ),
    ))
}

fn has_required_controllers(path: &Path) -> CageResult<bool> {
    let available = read_text(&path.join("cgroup.controllers"))?;
    let enabled = read_text(&path.join("cgroup.subtree_control"))?;
    Ok(["cpu", "memory", "pids"]
        .into_iter()
        .all(|controller| has_word(&available, controller) && has_word(&enabled, controller)))
}

fn can_create_child(path: &Path) -> CageResult<bool> {
    match OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.procs"))
    {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(false),
        Err(error) => Err(cgroup_setup_error(
            path.display().to_string(),
            "the delegated ancestor cgroup process file must be writable",
            "delegate cgroup.procs and child creation to the current user",
            error.to_string(),
        )),
    }
}

fn find_cgroup2_mount() -> CageResult<PathBuf> {
    let conventional = Path::new("/sys/fs/cgroup");
    if is_cgroup2_mount(conventional) {
        return Ok(conventional.to_path_buf());
    }

    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(|error| {
        cgroup_setup_error(
            "/proc/self/mountinfo",
            "the cgroup v2 mount must be discoverable",
            "enable a unified cgroup v2 hierarchy and retry",
            error.to_string(),
        )
    })?;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        if right.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let fields = left.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            continue;
        }
        let mount = PathBuf::from(decode_mountinfo_path(fields[4]));
        if is_cgroup2_mount(&mount) {
            return Ok(mount);
        }
    }
    Err(cgroup_setup_error(
        "/sys/fs/cgroup",
        "a unified cgroup v2 hierarchy is required",
        "boot Linux with cgroup v2 mounted and retry",
        "no cgroup2 mount was found",
    ))
}

fn is_cgroup2_mount(path: &Path) -> bool {
    path.is_dir() && path.join("cgroup.controllers").exists()
}

fn current_cgroup_path() -> CageResult<PathBuf> {
    let content = fs::read_to_string("/proc/self/cgroup").map_err(|error| {
        cgroup_setup_error(
            "/proc/self/cgroup",
            "the current cgroup must be identifiable before spawning Bubblewrap",
            "run with readable procfs and a unified cgroup v2 hierarchy",
            error.to_string(),
        )
    })?;
    let path = content.lines().find_map(|line| {
        let (hierarchy, path) = line.split_once("::")?;
        (hierarchy == "0").then_some(path)
    });
    let Some(path) = path else {
        return Err(cgroup_setup_error(
            "/proc/self/cgroup",
            "the current process must belong to a unified cgroup v2 hierarchy",
            "run under cgroup v2 and enable a user-delegated subtree",
            "the cgroup v2 entry 0:: was missing",
        ));
    };
    let path = PathBuf::from(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(cgroup_setup_error(
            path.display().to_string(),
            "the current cgroup path must be absolute and traversal-free",
            "run under a normal cgroup v2 hierarchy",
            "the kernel returned an unsafe cgroup path",
        ));
    }
    Ok(path)
}

fn create_child_cgroup(parent: &Path) -> CageResult<PathBuf> {
    for _ in 0..32 {
        let id = NEXT_CGROUP_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("cargo-cage-{}-{id}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => {
                let metadata = fs::symlink_metadata(&path).map_err(|error| {
                    cgroup_setup_error(
                        path.display().to_string(),
                        "the resource cgroup must be a real directory",
                        "remove the conflicting cgroup entry and retry",
                        error.to_string(),
                    )
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(cgroup_setup_error(
                        path.display().to_string(),
                        "the resource cgroup must not be a symlink or special file",
                        "remove the conflicting cgroup entry and retry",
                        "created cgroup had an unexpected file type",
                    ));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(cgroup_setup_error(
                    parent.display().to_string(),
                    "a private child cgroup must be creatable in the delegated subtree",
                    "delegate cpu, memory, and pids controllers to the current user",
                    error.to_string(),
                ));
            }
        }
    }
    Err(cgroup_setup_error(
        parent.display().to_string(),
        "the child cgroup name must be collision-free",
        "remove stale cargo-cage cgroups and retry",
        "could not allocate a unique cgroup name",
    ))
}

fn configure_cgroup(path: &Path, limits: EffectiveResourceLimits) -> CageResult<()> {
    for required in ["cgroup.kill", "memory.events", "pids.events"] {
        if !path.join(required).exists() {
            return Err(cgroup_setup_error(
                path.display().to_string(),
                format!("{required} must be available for fail-closed resource enforcement"),
                "use a current Linux kernel with cgroup v2 process and memory controls",
                format!("missing {}", path.join(required).display()),
            ));
        }
    }
    write_control(path, "pids.max", limits.max_processes.to_string())?;
    write_control(path, "memory.max", limits.max_memory_bytes.to_string())?;
    write_control(path, "memory.swap.max", "0".to_owned())?;
    write_control(path, "memory.oom.group", "1".to_owned())?;
    let cpu_quota = cpu_quota_micros(limits.max_cpu_cores).ok_or_else(|| {
        cgroup_setup_error(
            path.display().to_string(),
            "the CPU quota must be representable safely",
            "use a positive CPU budget within the supported range",
            "CPU quota arithmetic overflowed",
        )
    })?;
    write_control(path, "cpu.max", format!("{cpu_quota} {CPU_PERIOD_MICROS}"))?;
    Ok(())
}

fn write_control(path: &Path, name: &str, value: String) -> CageResult<()> {
    fs::write(path.join(name), format!("{value}\n")).map_err(|error| {
        cgroup_setup_error(
            path.display().to_string(),
            format!("{name} must accept the requested resource limit"),
            "run inside a user-delegated cgroup v2 subtree with cpu, memory, and pids enabled",
            error.to_string(),
        )
    })
}

fn require_writable(path: &Path, subject: &str) -> CageResult<()> {
    OpenOptions::new()
        .write(true)
        .open(path)
        .map(|_| ())
        .map_err(|error| {
            cgroup_setup_error(
                path.display().to_string(),
                format!("{subject} must be writable without changing the host hierarchy"),
                "run under a user-delegated cgroup v2 subtree",
                error.to_string(),
            )
        })
}

fn write_pid(path: &Path, action: &str) -> CageResult<()> {
    fs::write(path, format!("{}\n", std::process::id())).map_err(|error| {
        cgroup_setup_error(
            path.display().to_string(),
            format!("the supervisor must be able to {action} safely"),
            "run under a user-delegated cgroup v2 subtree with writable cgroup.procs",
            error.to_string(),
        )
    })
}

fn cgroup_is_empty(path: &Path) -> CageResult<bool> {
    Ok(read_text(&path.join("cgroup.procs"))?
        .lines()
        .all(|line| line.trim().is_empty()))
}

fn read_events(path: &Path) -> io::Result<EventCounters> {
    let memory = fs::read_to_string(path.join("memory.events"))?;
    let pids = fs::read_to_string(path.join("pids.events"))?;
    Ok(EventCounters {
        memory_max: parse_counter(&memory, "max", &path.join("memory.events"))?,
        memory_oom_kill: parse_counter(&memory, "oom_kill", &path.join("memory.events"))?,
        pids_max: parse_counter(&pids, "max", &path.join("pids.events"))?,
    })
}

fn parse_counter(content: &str, key: &str, path: &Path) -> io::Result<u64> {
    content
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some(key)).then(|| fields.next()?.parse().ok())
        })
        .flatten()
        .ok_or_else(|| io::Error::other(format!("{key} was missing from {}", path.display())))
}

fn read_optional_limit(path: &Path) -> CageResult<Option<u64>> {
    let content = read_text(path)?;
    parse_optional_limit(&content, path)
}

fn parse_optional_limit(content: &str, path: &Path) -> CageResult<Option<u64>> {
    if content.trim() == "max" {
        Ok(None)
    } else {
        content.trim().parse::<u64>().map(Some).map_err(|error| {
            cgroup_setup_error(
                path.display().to_string(),
                "the parent cgroup memory limit must be numeric or max",
                "repair the delegated cgroup v2 memory.max value",
                error.to_string(),
            )
        })
    }
}

fn cpu_quota_micros(cores: u32) -> Option<u64> {
    u64::from(cores).checked_mul(CPU_PERIOD_MICROS)
}

fn host_memory_bytes() -> CageResult<u64> {
    let content = fs::read_to_string("/proc/meminfo").map_err(|error| {
        cgroup_setup_error(
            "/proc/meminfo",
            "host memory must be measurable before selecting the sandbox budget",
            "run on a Linux host with readable procfs",
            error.to_string(),
        )
    })?;
    let kilobytes = content.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some("MemTotal:")).then(|| fields.next()?.parse().ok())
    });
    kilobytes
        .flatten()
        .and_then(|value: u64| value.checked_mul(1024))
        .ok_or_else(|| {
            cgroup_setup_error(
                "/proc/meminfo",
                "MemTotal must be a positive, representable value",
                "run on a normal Linux host with readable MemTotal",
                "MemTotal was missing or invalid",
            )
        })
}

fn read_text(path: &Path) -> CageResult<String> {
    fs::read_to_string(path).map_err(|error| {
        cgroup_setup_error(
            path.display().to_string(),
            "the cgroup control file must be readable",
            "enable a working delegated cgroup v2 hierarchy",
            error.to_string(),
        )
    })
}

fn has_word(content: &str, word: &str) -> bool {
    content
        .split_whitespace()
        .any(|value| value == word || value == format!("+{word}"))
}

fn canonical_directory_without_symlinks(path: &Path, label: &str) -> CageResult<PathBuf> {
    cage_core::canonical_existing_path_without_symlinks(path, label)
}

fn decode_mountinfo_path(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn set_lower_limit(resource: Resource, requested: u64, label: &str) -> CageResult<u64> {
    let current = getrlimit(resource);
    let hard = current.maximum.unwrap_or(requested);
    let effective = requested.min(hard);
    if requested > 0 && effective == 0 {
        return Err(cgroup_setup_error(
            "current cargo-cage process",
            format!("{label} must allow a positive inherited limit"),
            "raise the current user's hard resource limit and retry",
            "the host hard limit is zero",
        ));
    }
    setrlimit(
        resource,
        Rlimit {
            current: Some(effective),
            maximum: Some(effective),
        },
    )
    .map_err(|error| {
        cgroup_setup_error(
            "current cargo-cage process",
            format!("{label} must be lowered before Bubblewrap starts"),
            "run with resource limits that the current user is allowed to set",
            error.to_string(),
        )
    })?;
    Ok(effective)
}

fn format_bytes(value: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if value % GIB == 0 {
        format!("{} GiB", value / GIB)
    } else {
        format!("{value} bytes")
    }
}

fn format_duration(value: Duration) -> String {
    if value.as_secs() == 0 {
        format!("{} ms", value.as_millis())
    } else if value.as_secs() % 60 == 0 {
        format!("{} minutes", value.as_secs() / 60)
    } else {
        format!("{} seconds", value.as_secs())
    }
}

fn resource_limit_error(
    kind: ResourceLimitKind,
    limit: String,
    status: &std::process::ExitStatus,
    detail: &str,
    remedy: &str,
) -> CageError {
    CageError::ResourceLimitExceeded {
        kind,
        limit,
        status: Some(cage_core::ProcessStatus {
            code: status.code(),
        }),
        remedy: remedy.to_owned(),
        detail: detail.to_owned(),
    }
}

fn cgroup_setup_error(
    subject: impl Into<String>,
    rule: impl Into<String>,
    remedy: impl Into<String>,
    detail: impl Into<String>,
) -> CageError {
    CageError::sandbox_setup(subject, rule, remedy, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mountinfo_paths() {
        assert_eq!(
            decode_mountinfo_path("/sys/fs/cgroup\\040root"),
            "/sys/fs/cgroup root"
        );
    }

    #[test]
    fn recognizes_controller_words() {
        assert!(has_word("cpu memory pids", "memory"));
        assert!(has_word("+cpu +memory", "cpu"));
        assert!(!has_word("cpu io", "memory"));
    }

    #[test]
    fn parses_resource_event_counters() {
        let memory = "low 0\nhigh 0\nmax 3\n oom 0\noom_kill 2\n";
        let pids = "max 7\n";
        assert_eq!(
            parse_counter(memory, "max", Path::new("memory.events")).unwrap(),
            3
        );
        assert_eq!(
            parse_counter(memory, "oom_kill", Path::new("memory.events")).unwrap(),
            2
        );
        assert_eq!(
            parse_counter(pids, "max", Path::new("pids.events")).unwrap(),
            7
        );
        assert!(parse_counter(pids, "oom_kill", Path::new("pids.events")).is_err());
    }

    #[test]
    fn parses_parent_memory_limits() {
        assert_eq!(
            parse_optional_limit("max\n", Path::new("memory.max")).unwrap(),
            None
        );
        assert_eq!(
            parse_optional_limit("4294967296\n", Path::new("memory.max")).unwrap(),
            Some(4_294_967_296)
        );
        assert!(parse_optional_limit("invalid\n", Path::new("memory.max")).is_err());
    }

    #[test]
    fn calculates_cpu_quota_from_cores() {
        assert_eq!(cpu_quota_micros(4), Some(400_000));
        assert_eq!(cpu_quota_micros(0), Some(0));
    }

    #[test]
    fn reports_memory_and_process_events_as_resource_errors() {
        let limits = EffectiveResourceLimits {
            max_processes: 16,
            max_memory_bytes: 1024 * 1024 * 1024,
            max_cpu_cores: 1,
            max_wall_time: Duration::from_secs(5),
            max_file_size_bytes: 1024 * 1024,
            max_open_files: 256,
        };
        let status = std::process::ExitStatus::from_raw(1 << 8);
        let memory = ResourceReport {
            limits,
            before: EventCounters::default(),
            after: EventCounters {
                memory_max: 1,
                ..EventCounters::default()
            },
        };
        assert!(matches!(
            memory.resource_error(&status, false),
            Some(CageError::ResourceLimitExceeded {
                kind: ResourceLimitKind::Memory,
                ..
            })
        ));

        let processes = ResourceReport {
            limits,
            before: EventCounters::default(),
            after: EventCounters {
                pids_max: 1,
                ..EventCounters::default()
            },
        };
        assert!(matches!(
            processes.resource_error(&status, false),
            Some(CageError::ResourceLimitExceeded {
                kind: ResourceLimitKind::Processes,
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cgroup_parent() {
        let root = std::env::temp_dir().join(format!(
            "cargo-cage-cgroup-path-test-{}-{}",
            std::process::id(),
            NEXT_CGROUP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let real = root.join("real");
        let link = root.join("link");
        fs::create_dir_all(&real).expect("test cgroup directory");
        std::os::unix::fs::symlink(&real, &link).expect("test cgroup symlink");
        let error = canonical_directory_without_symlinks(&link, "test cgroup").unwrap_err();
        assert!(error.to_string().contains("symlink"));
        fs::remove_file(link).expect("test cgroup symlink cleanup");
        fs::remove_dir_all(root).expect("test cgroup path cleanup");
    }

    #[test]
    fn formats_default_limits_for_diagnostics() {
        let limits = ResourceLimits::default();
        assert_eq!(format_bytes(limits.max_memory_bytes), "8 GiB");
        assert_eq!(format_duration(limits.max_wall_time), "30 minutes");
        assert_eq!(format_duration(Duration::from_millis(250)), "250 ms");
    }
}
