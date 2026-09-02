#![forbid(unsafe_code)]

use cage_linux::{INTERNAL_LAUNCHER_ARG, LAUNCHER_SETUP_EXIT_CODE, run_internal_launcher};
use std::env;
use std::ffi::OsStr;
use std::process;

fn main() {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_none_or(|arg| arg != OsStr::new(INTERNAL_LAUNCHER_ARG))
    {
        eprintln!("cargo-cage-landlock-launcher: internal invocation only");
        process::exit(2);
    }

    match run_internal_launcher(&args[1..]) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("cargo-cage-landlock-launcher: {error}");
            process::exit(LAUNCHER_SETUP_EXIT_CODE);
        }
    }
}
