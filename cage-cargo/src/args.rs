use cage_core::{CageError, CageResult};
use std::ffi::{OsStr, OsString};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CargoInvocation {
    Help,
    Build { args: Vec<OsString> },
}

pub fn parse_invocation<I>(args: I) -> CageResult<CargoInvocation>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter().collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == OsStr::new("cage")) {
        args.remove(0);
    }

    let Some(command) = args.first() else {
        return Err(CageError::InvalidInvocation(
            "expected `cargo cage build [OPTIONS]`".to_owned(),
        ));
    };
    if command == OsStr::new("--help") || command == OsStr::new("-h") {
        return Ok(CargoInvocation::Help);
    }
    if command != OsStr::new("build") {
        return Err(CageError::InvalidInvocation(format!(
            "unsupported command `{}`; v0.1 supports only `build`",
            command.to_string_lossy()
        )));
    }

    Ok(CargoInvocation::Build {
        args: args.into_iter().skip(1).collect(),
    })
}

pub fn is_help_request(args: &[OsString]) -> bool {
    let first = args.first();
    let help = |arg: Option<&OsString>| {
        arg.is_some_and(|arg| arg == OsStr::new("--help") || arg == OsStr::new("-h"))
    };
    if first.is_some_and(|arg| arg == OsStr::new("cage")) {
        help(args.get(1))
    } else {
        help(first)
    }
}

pub fn help_text() -> &'static str {
    "cargo-cage v0.1.0\n\nUSAGE:\n    cargo cage build [CARGO_OPTIONS...]\n    cargo-cage build [CARGO_OPTIONS...]\n\nThe build runs in an experimental Linux sandbox. Network access is denied,\nsensitive home paths are hidden, and persistent writes are limited to target\nand Cargo.lock. Dependencies must be available locally; use `cargo fetch`\nseparately before running an offline build.\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_external_cargo_invocation() {
        let invocation = parse_invocation([
            OsString::from("cage"),
            OsString::from("build"),
            OsString::from("--release"),
        ])
        .expect("valid invocation");
        assert_eq!(
            invocation,
            CargoInvocation::Build {
                args: vec![OsString::from("--release")]
            }
        );
    }

    #[test]
    fn parses_direct_invocation() {
        let invocation = parse_invocation([OsString::from("build")]).expect("valid invocation");
        assert_eq!(invocation, CargoInvocation::Build { args: Vec::new() });
    }

    #[test]
    fn rejects_unsupported_command() {
        let error = parse_invocation([OsString::from("test")]).expect_err("test is unsupported");
        assert!(error.to_string().contains("only `build`"));
    }

    #[test]
    fn recognizes_help_in_both_forms() {
        assert!(is_help_request(&[OsString::from("--help")]));
        assert!(is_help_request(&[
            OsString::from("cage"),
            OsString::from("--help")
        ]));
        assert!(!is_help_request(&[OsString::from("build")]));
    }
}
