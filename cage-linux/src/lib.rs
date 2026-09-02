#![forbid(unsafe_code)]

mod backend;
#[cfg(target_os = "linux")]
mod landlock;

pub use backend::LinuxSandbox;

#[cfg(target_os = "linux")]
pub use landlock::INTERNAL_LAUNCHER_ARG;

#[cfg(not(target_os = "linux"))]
pub const INTERNAL_LAUNCHER_ARG: &str = "__cargo_cage_landlock_exec";

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use landlock::{LAUNCHER_SETUP_EXIT_CODE, run_internal_launcher};

#[cfg(not(target_os = "linux"))]
#[doc(hidden)]
pub fn run_internal_launcher(_args: &[std::ffi::OsString]) -> cage_core::CageResult<i32> {
    Err(cage_core::CageError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub const LAUNCHER_SETUP_EXIT_CODE: i32 = 125;
