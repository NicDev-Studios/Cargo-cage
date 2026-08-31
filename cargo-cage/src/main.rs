#![forbid(unsafe_code)]

use cage_cargo::{help_text, is_help_request, run};
use cage_linux::LinuxSandbox;
use std::env;
use std::process;

fn main() {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if is_help_request(&args) {
        print!("{}", help_text());
        return;
    }

    let backend = match LinuxSandbox::new() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("cargo-cage: {error}");
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
