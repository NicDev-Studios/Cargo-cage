use cage_core::{CageError, CageResult};
use std::ffi::{OsStr, OsString};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CargoInvocation {
    Help,
    Cargo {
        command: CargoCommand,
        args: Vec<OsString>,
    },
    Doctor {
        verbose: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoCommand {
    Build,
    Check,
    Test,
    Doc,
}

impl CargoCommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Check => "check",
            Self::Test => "test",
            Self::Doc => "doc",
        }
    }
}

pub fn parse_invocation<I>(args: I) -> CageResult<CargoInvocation>
where
    I: IntoIterator<Item = OsString>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == OsStr::new("cage")) {
        return Err(CageError::InvalidInvocation(
            "the `cargo cage` dispatcher form is not supported because Cargo aliases can bypass this sandbox; invoke `cargo-cage` directly"
                .to_owned(),
        ));
    }

    let Some(command) = args.first() else {
        return Err(CageError::InvalidInvocation(
            "expected `cargo-cage <build|check|test|doc|doctor> [OPTIONS]`".to_owned(),
        ));
    };
    if command == OsStr::new("--help") || command == OsStr::new("-h") {
        return Ok(CargoInvocation::Help);
    }

    if command == OsStr::new("doctor") {
        let doctor_args = &args[1..];
        return match doctor_args {
            [] => Ok(CargoInvocation::Doctor { verbose: false }),
            [arg] if arg == OsStr::new("--verbose") || arg == OsStr::new("-v") => {
                Ok(CargoInvocation::Doctor { verbose: true })
            }
            [arg] if arg == OsStr::new("--help") || arg == OsStr::new("-h") => {
                Ok(CargoInvocation::Help)
            }
            _ => Err(CageError::InvalidInvocation(
                "`doctor` accepts only the optional `--verbose` flag".to_owned(),
            )),
        };
    }

    let command = match command.to_str() {
        Some("build") => CargoCommand::Build,
        Some("check") => CargoCommand::Check,
        Some("test") => CargoCommand::Test,
        Some("doc") => CargoCommand::Doc,
        _ => {
            return Err(CageError::InvalidInvocation(format!(
                "unsupported command `{}`; supported commands are `build`, `check`, `test`, `doc`, and `doctor`",
                command.to_string_lossy()
            )));
        }
    };

    Ok(CargoInvocation::Cargo {
        command,
        args: args.into_iter().skip(1).collect(),
    })
}

pub fn is_help_request(args: &[OsString]) -> bool {
    matches!(
        parse_invocation(args.iter().cloned()),
        Ok(CargoInvocation::Help)
    )
}

pub fn help_text() -> &'static str {
    "cargo-cage v0.3.0\n\nUSAGE:\n    cargo-cage <build|check|test|doc> [CARGO_OPTIONS...]\n    cargo-cage doctor [--verbose]\n\nCargo runs in an experimental Linux sandbox. Network access is denied,\nHOME is private, the child environment uses a fixed allowlist, and persistent\nwrites are limited to target and Cargo.lock. Dependencies must be available\nlocally; use `cargo fetch` separately before running an offline command.\n\nThe direct `cargo-cage` executable is required for the security boundary.\nThe `cargo cage` dispatcher form is intentionally unsupported because Cargo\nconfiguration aliases can bypass external subcommands.\n\n`doctor` checks Bubblewrap, namespaces, workspace paths, toolchain paths, and\nCargo caches without modifying the project.\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cargo_dispatcher_invocation() {
        let error = parse_invocation([
            OsString::from("cage"),
            OsString::from("build"),
            OsString::from("--release"),
        ])
        .expect_err("Cargo dispatcher form must be rejected");
        assert!(error.to_string().contains("dispatcher form"));
        assert!(error.to_string().contains("cargo-cage"));
    }

    #[test]
    fn parses_direct_invocation() {
        let invocation = parse_invocation([OsString::from("build")]).expect("valid invocation");
        assert_eq!(
            invocation,
            CargoInvocation::Cargo {
                command: CargoCommand::Build,
                args: Vec::new()
            }
        );
    }

    #[test]
    fn parses_all_supported_commands() {
        for (name, command) in [
            ("build", CargoCommand::Build),
            ("check", CargoCommand::Check),
            ("test", CargoCommand::Test),
            ("doc", CargoCommand::Doc),
        ] {
            let invocation = parse_invocation([OsString::from(name)]).expect("valid command");
            assert_eq!(
                invocation,
                CargoInvocation::Cargo {
                    command,
                    args: Vec::new()
                }
            );
        }
    }

    #[test]
    fn parses_doctor_options() {
        assert_eq!(
            parse_invocation([OsString::from("doctor")]).expect("doctor"),
            CargoInvocation::Doctor { verbose: false }
        );
        assert_eq!(
            parse_invocation([OsString::from("doctor"), OsString::from("--verbose")])
                .expect("verbose doctor"),
            CargoInvocation::Doctor { verbose: true }
        );
    }

    #[test]
    fn rejects_unsupported_command() {
        let error = parse_invocation([OsString::from("run")]).expect_err("run is unsupported");
        assert!(error.to_string().contains("supported commands"));
    }

    #[test]
    fn rejects_doctor_options_other_than_verbose() {
        let error = parse_invocation([
            OsString::from("doctor"),
            OsString::from("--manifest-path"),
            OsString::from("Cargo.toml"),
        ])
        .expect_err("doctor manifest path is unsupported");
        assert!(error.to_string().contains("only the optional `--verbose`"));
    }

    #[test]
    fn recognizes_direct_help_only() {
        assert!(is_help_request(&[OsString::from("--help")]));
        assert!(!is_help_request(&[
            OsString::from("cage"),
            OsString::from("--help")
        ]));
        assert!(!is_help_request(&[
            OsString::from("cage"),
            OsString::from("doctor"),
            OsString::from("--help")
        ]));
        assert!(!is_help_request(&[OsString::from("build")]));
    }
}
