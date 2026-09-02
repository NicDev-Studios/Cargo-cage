#![forbid(unsafe_code)]

use cage_cargo::{CargoInvocation, help_text, parse_invocation, run};
use cage_linux::LinuxSandbox;
use std::env;
use std::ffi::OsStr;
use std::process;

fn main() {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|arg| arg == OsStr::new(cage_linux::INTERNAL_LAUNCHER_ARG))
    {
        match cage_linux::run_internal_launcher(&args[1..]) {
            Ok(code) => process::exit(code),
            Err(error) => {
                eprintln!("cargo-cage: {error}");
                process::exit(cage_linux::LAUNCHER_SETUP_EXIT_CODE);
            }
        }
    }
    let invocation = match parse_invocation(args.iter().cloned()) {
        Ok(CargoInvocation::Help) => {
            print!("{}", help_text());
            return;
        }
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("cargo-cage: {error}");
            process::exit(1);
        }
    };
    let doctor = matches!(invocation, CargoInvocation::Doctor { .. });

    let backend = match LinuxSandbox::new() {
        Ok(backend) => backend,
        Err(error) => {
            if doctor {
                eprintln!("cargo-cage doctor: FAIL Bubblewrap/backend: {error}");
            } else {
                eprintln!("cargo-cage: {error}");
            }
            process::exit(1);
        }
    };

    match run(args, &backend) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("cargo-cage: {error}");
            process::exit(1);
        }
    }
}
