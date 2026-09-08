use crate::resources::ResourceGroup;
use cage_core::{CageError, CageResult};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use std::env;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, ExitStatus, Output};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

pub(super) fn wait_for_child(
    child: &mut Child,
    group: &ResourceGroup,
    wall_time: Duration,
) -> CageResult<(ExitStatus, bool)> {
    let deadline = Instant::now() + wall_time;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, false)),
            Ok(None) if Instant::now() >= deadline => {
                group.kill_all()?;
                let status = child.wait().map_err(|error| {
                    CageError::io("could not wait for the timed-out Bubblewrap process", error)
                })?;
                return Ok((status, true));
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = group.kill_all();
                let _ = child.wait();
                return Err(CageError::io(
                    "could not monitor the Bubblewrap process",
                    error,
                ));
            }
        }
    }
}

pub(super) fn capture_child_output(
    mut child: Child,
    group: &ResourceGroup,
    wall_time: Duration,
) -> CageResult<(Output, bool)> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("captured Bubblewrap stdout pipe was not created"));
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("captured Bubblewrap stderr pipe was not created"));
    let (Ok(stdout), Ok(stderr)) = (stdout, stderr) else {
        let _ = group.kill_all();
        let _ = child.kill();
        let _ = child.wait();
        return Err(CageError::io(
            "captured Bubblewrap output pipes could not be prepared",
            std::io::Error::other("one or more output pipes were missing"),
        ));
    };

    let stdout_over_limit = Arc::new(AtomicBool::new(false));
    let stderr_over_limit = Arc::new(AtomicBool::new(false));
    let stdout_flag = Arc::clone(&stdout_over_limit);
    let stderr_flag = Arc::clone(&stderr_over_limit);
    let stdout_reader = thread::spawn(move || read_capped(stdout, stdout_flag));
    let stderr_reader = thread::spawn(move || read_capped(stderr, stderr_flag));

    let deadline = Instant::now() + wall_time;
    let mut killed_for_output = false;
    let mut wall_time_expired = false;
    let status = loop {
        if (stdout_over_limit.load(Ordering::Relaxed) || stderr_over_limit.load(Ordering::Relaxed))
            && !killed_for_output
        {
            group.kill_all()?;
            let _ = child.kill();
            killed_for_output = true;
        }
        if Instant::now() >= deadline && !killed_for_output {
            group.kill_all()?;
            let _ = child.kill();
            killed_for_output = true;
            wall_time_expired = true;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(error) => {
                let _ = group.kill_all();
                let _ = child.kill();
                let _ = child.wait();
                return Err(CageError::io(
                    "could not monitor captured Bubblewrap output",
                    error,
                ));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| {
            CageError::io(
                "captured Bubblewrap stdout reader panicked",
                std::io::Error::other("stdout reader thread panicked"),
            )
        })?
        .map_err(|error| CageError::io("could not read captured Bubblewrap stdout", error))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| {
            CageError::io(
                "captured Bubblewrap stderr reader panicked",
                std::io::Error::other("stderr reader thread panicked"),
            )
        })?
        .map_err(|error| CageError::io("could not read captured Bubblewrap stderr", error))?;
    if stdout_over_limit.load(Ordering::Relaxed) || stderr_over_limit.load(Ordering::Relaxed) {
        return Err(CageError::sandbox_setup(
            "Bubblewrap discovery output",
            "captured discovery output must stay below the safety limit",
            "fix the discovery command or retry with a normal Bubblewrap setup",
            format!(
                "captured Bubblewrap output exceeded the {} byte safety limit",
                super::MAX_CAPTURED_OUTPUT
            ),
        ));
    }
    Ok((
        Output {
            status,
            stdout,
            stderr,
        },
        wall_time_expired,
    ))
}

#[cfg(test)]
pub(super) fn capture_command_output(
    mut command: std::process::Command,
) -> std::io::Result<std::process::Output> {
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("captured stdout pipe was not created"));
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("captured stderr pipe was not created"));
    let (Ok(stdout), Ok(stderr)) = (stdout, stderr) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other(
            "captured output pipes were not created",
        ));
    };
    let stdout_over_limit = Arc::new(AtomicBool::new(false));
    let stderr_over_limit = Arc::new(AtomicBool::new(false));
    let stdout_reader = {
        let flag = Arc::clone(&stdout_over_limit);
        thread::spawn(move || read_capped(stdout, flag))
    };
    let stderr_reader = {
        let flag = Arc::clone(&stderr_over_limit);
        thread::spawn(move || read_capped(stderr, flag))
    };
    let status = loop {
        if (stdout_over_limit.load(Ordering::Relaxed) || stderr_over_limit.load(Ordering::Relaxed))
            && child.try_wait()?.is_none()
        {
            let _ = child.kill();
        }
        match child.try_wait()? {
            Some(status) => break status,
            None => thread::sleep(Duration::from_millis(5)),
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| std::io::Error::other("stdout reader thread panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| std::io::Error::other("stderr reader thread panicked"))??;
    if stdout_over_limit.load(Ordering::Relaxed) || stderr_over_limit.load(Ordering::Relaxed) {
        return Err(std::io::Error::other(format!(
            "captured Bubblewrap output exceeded the {} byte safety limit",
            super::MAX_CAPTURED_OUTPUT
        )));
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn read_capped<R: Read>(mut reader: R, over_limit: Arc<AtomicBool>) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => {
                over_limit.store(true, Ordering::Relaxed);
                return Err(error);
            }
        };
        if read == 0 {
            return Ok(output);
        }
        let remaining = super::MAX_CAPTURED_OUTPUT.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..read.min(remaining)]);
        if read > remaining {
            over_limit.store(true, Ordering::Relaxed);
        }
    }
}

pub(super) struct LauncherContext {
    file: fs::File,
    path: PathBuf,
}

impl LauncherContext {
    pub(super) fn new() -> CageResult<Self> {
        use std::io::{Seek, SeekFrom, Write};

        let path = env::temp_dir().join(format!(
            "cargo-cage-launcher-context-{}-{}",
            std::process::id(),
            super::NEXT_LAUNCHER_CONTEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed,)
        ));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| {
                CageError::sandbox_setup(
                    path.display().to_string(),
                    "the launcher context must be created as a private regular file",
                    "make the system temporary directory writable and retry",
                    format!("could not create the launcher context: {error}"),
                )
            })?;
        file.write_all(crate::landlock::LAUNCHER_CONTEXT_CONTENT)
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .map_err(|error| {
                CageError::sandbox_setup(
                    path.display().to_string(),
                    "the launcher context must contain the expected marker",
                    "retry with a working temporary filesystem",
                    format!("could not prepare the launcher context: {error}"),
                )
            })?;
        let mut flags = fcntl_getfd(&file).map_err(|error| {
            CageError::sandbox_setup(
                path.display().to_string(),
                "the launcher context descriptor must be transferable to Bubblewrap",
                "use a working Linux fcntl implementation",
                format!("could not inspect the launcher context descriptor: {error}"),
            )
        })?;
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(&file, flags).map_err(|error| {
            CageError::sandbox_setup(
                path.display().to_string(),
                "the launcher context descriptor must be transferable to Bubblewrap",
                "use a working Linux fcntl implementation",
                format!("could not prepare the launcher context descriptor: {error}"),
            )
        })?;
        fs::remove_file(&path).map_err(|error| {
            CageError::sandbox_setup(
                path.display().to_string(),
                "the launcher context source must not remain addressable by a host path",
                "retry with a working temporary filesystem",
                format!("could not unlink the temporary launcher context: {error}"),
            )
        })?;
        Ok(Self { file, path })
    }

    pub(super) fn raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }

    #[cfg(test)]
    pub(super) fn file(&self) -> &fs::File {
        &self.file
    }

    #[cfg(test)]
    pub(super) fn host_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LauncherContext {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
