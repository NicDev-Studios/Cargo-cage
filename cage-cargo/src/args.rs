use cage_core::{CageError, CageResult};
use std::ffi::{OsStr, OsString};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CargoInvocation {
    Help,
    Cargo {
        command: CargoCommand,
        args: Vec<OsString>,
        reuse_target: bool,
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
    let mut args = args.into_iter().collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == OsStr::new("cage")) {
        return Err(CageError::InvalidInvocation(
            "the `cargo cage` dispatcher form is not supported because Cargo aliases can bypass this sandbox; invoke `cargo-cage` directly"
                .to_owned(),
        ));
    }

    let reuse_target = if args
        .first()
        .is_some_and(|arg| arg == OsStr::new("--reuse-target"))
    {
        args.remove(0);
        true
    } else {
        false
    };

    let Some(command) = args.first() else {
        return Err(CageError::InvalidInvocation(
            if reuse_target {
                "`--reuse-target` needs a Cargo command"
            } else {
                "expected `cargo-cage [--reuse-target] <build|check|test|doc|doctor> [OPTIONS]`"
            }
            .to_owned(),
        ));
    };
    if command == OsStr::new("--help") || command == OsStr::new("-h") {
        return Ok(CargoInvocation::Help);
    }

    if command == OsStr::new("doctor") {
        if reuse_target {
            return Err(CageError::InvalidInvocation(
                "`--reuse-target` is only valid with build, check, test, or doc".to_owned(),
            ));
        }
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
        reuse_target,
    })
}

pub fn is_help_request(args: &[OsString]) -> bool {
    matches!(
        parse_invocation(args.iter().cloned()),
        Ok(CargoInvocation::Help)
    )
}

pub fn help_text() -> &'static str {
    "cargo-cage v0.1.0-alpha.1\n\nUSAGE:\n    cargo-cage [--reuse-target] <build|check|test|doc> [CARGO_OPTIONS...]\n    cargo-cage doctor [--verbose]\n\nCargo runs in an experimental Linux sandbox. Network access is denied,\nHOME is private, the child environment uses a fixed allowlist, and persistent\nwrites are limited to an isolated target run and Cargo.lock. Dependencies must\nbe available locally; use `cargo fetch` separately before running offline.\n\nThe direct `cargo-cage` executable is required for the security boundary.\nThe `cargo cage` dispatcher form is intentionally unsupported because Cargo\nconfiguration aliases can bypass external subcommands.\n\nEach command gets a fresh target run by default. Use `--reuse-target` only\nfor a trusted workspace when you explicitly need Cargo's existing target tree.\n\n`doctor` checks Bubblewrap, namespaces, workspace paths, toolchain paths, and\nCargo caches without modifying the project.\n"
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
                args: Vec::new(),
                reuse_target: false,
            }
        );
    }

    #[test]
    fn parses_reuse_target_before_the_cargo_command() {
        let invocation = parse_invocation([
            OsString::from("--reuse-target"),
            OsString::from("build"),
            OsString::from("--workspace"),
        ])
        .expect("reuse target invocation");
        assert_eq!(
            invocation,
            CargoInvocation::Cargo {
                command: CargoCommand::Build,
                args: vec![OsString::from("--workspace")],
                reuse_target: true,
            }
        );
    }

    #[test]
    fn keeps_reuse_target_after_the_command_for_cargo_to_reject() {
        let invocation =
            parse_invocation([OsString::from("build"), OsString::from("--reuse-target")])
                .expect("Cargo arguments remain Cargo arguments");
        assert_eq!(
            invocation,
            CargoInvocation::Cargo {
                command: CargoCommand::Build,
                args: vec![OsString::from("--reuse-target")],
                reuse_target: false,
            }
        );
    }

    #[test]
    fn rejects_reuse_target_without_a_cargo_command() {
        let error = parse_invocation([OsString::from("--reuse-target")])
            .expect_err("missing Cargo command");
        assert!(error.to_string().contains("needs a Cargo command"));
    }

    #[test]
    fn rejects_reuse_target_for_doctor() {
        let error = parse_invocation([OsString::from("--reuse-target"), OsString::from("doctor")])
            .expect_err("reuse target doctor");
        assert!(error.to_string().contains("only valid with"));
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
                    args: Vec::new(),
                    reuse_target: false,
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
