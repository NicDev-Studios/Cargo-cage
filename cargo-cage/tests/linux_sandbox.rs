#![cfg(target_os = "linux")]

use cage_testkit::{Fixture, materialize};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[test]
fn linux_sandbox_acceptance_matrix() {
    simple_build_works();
    out_dir_is_writable();
    sensitive_home_path_is_hidden();
    workspace_write_is_denied();
    nested_child_inherits_policy();
    network_is_denied();
    symlink_escape_is_denied();
    symlink_target_is_rejected();
    external_cargo_subcommand_works();
    missing_backend_fails_closed();
    defective_backend_fails_closed();
}

fn simple_build_works() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let output = run_cage(&fixture, &[]);
    assert_success(&output);
    assert!(fixture.file("target/debug/cage-simple-build").is_file());
}

fn out_dir_is_writable() {
    let fixture = materialize("out-dir-build").expect("OUT_DIR fixture");
    let output = run_cage(&fixture, &[]);
    assert_success(&output);
    assert!(find_file(&fixture.file("target"), "cage-output.txt"));
}

fn sensitive_home_path_is_hidden() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let fake_home = fixture.file("fake-home");
    fs::create_dir_all(fake_home.join(".ssh")).expect("fake ssh directory");
    fs::write(fake_home.join(".ssh/fixture-secret"), b"must stay hidden").expect("fake ssh secret");

    let output = run_cage_with_env(&fixture, &[("CAGE_TEST_ACTION", "home-read")]);
    assert_policy_failure(&output);
    assert!(fake_home.join(".ssh/fixture-secret").is_file());
}

fn workspace_write_is_denied() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let path = fixture.file("build-script-write.txt");
    let path_value = path.to_str().expect("UTF-8 test path");
    let output = run_cage_with_env(
        &fixture,
        &[
            ("CAGE_TEST_ACTION", "workspace-write"),
            ("CAGE_TEST_WRITE_PATH", path_value),
        ],
    );
    assert_policy_failure(&output);
    assert!(!path.exists());
}

fn nested_child_inherits_policy() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let path = fixture.file("nested-write.txt");
    let path_value = path.to_str().expect("UTF-8 test path");
    let output = run_cage_with_env(
        &fixture,
        &[
            ("CAGE_TEST_ACTION", "nested-write"),
            ("CAGE_TEST_WRITE_PATH", path_value),
        ],
    );
    assert_policy_failure(&output);
    assert!(!path.exists());
}

fn network_is_denied() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener");
    let endpoint = listener.local_addr().expect("listener address").to_string();
    let output = run_cage_with_env(
        &fixture,
        &[
            ("CAGE_TEST_ACTION", "network"),
            ("CAGE_TEST_ENDPOINT", endpoint.as_str()),
        ],
    );
    assert_policy_failure(&output);
}

fn symlink_escape_is_denied() {
    use std::os::unix::fs::symlink;

    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    fs::create_dir(fixture.file("target")).expect("target directory");
    let external = fixture.file("symlink-target.txt");
    symlink(&external, fixture.file("target/escape-link")).expect("escape symlink");
    let link_path = fixture.file("target/escape-link");
    let link_value = link_path.to_str().expect("UTF-8 test path");
    let output = run_cage_with_env(
        &fixture,
        &[
            ("CAGE_TEST_ACTION", "symlink-escape"),
            ("CAGE_TEST_SYMLINK", link_value),
        ],
    );
    assert_policy_failure(&output);
    assert!(!external.exists());
}

fn symlink_target_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let outside = fixture.file("outside-target");
    fs::create_dir(&outside).expect("outside target directory");
    symlink(&outside, fixture.file("target")).expect("target symlink");
    let output = run_cage(&fixture, &[]);
    assert!(!output.status.success());
    let text = output_text(&output);
    assert!(
        text.contains("outside the workspace") || text.contains("symlink"),
        "{text}"
    );
}

fn external_cargo_subcommand_works() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let cargo = cargo_program();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-cage"));
    let binary_directory = binary.parent().expect("cargo-cage binary directory");
    let mut command = Command::new(cargo);
    command
        .current_dir(fixture.path())
        .args([
            "cage",
            "build",
            "--manifest-path",
            fixture
                .file("Cargo.toml")
                .to_str()
                .expect("UTF-8 manifest path"),
        ])
        .env("PATH", prepend_path(binary_directory))
        .env("CARGO_HOME", host_cargo_home())
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR");
    apply_rustup_home(&mut command);
    let output = command.output().expect("run cargo cage");
    assert_success(&output);
    assert!(fixture.file("target/debug/cage-simple-build").is_file());
}

fn missing_backend_fails_closed() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let mut command = base_command(&fixture);
    command.env("CARGO_CAGE_BWRAP", "/definitely/missing/bwrap");
    let output = command.output().expect("run cargo-cage");
    assert!(!output.status.success());
    let text = output_text(&output);
    assert!(
        text.contains("Bubblewrap") || text.contains("sandbox backend"),
        "{text}"
    );
    assert!(!fixture.file("target").exists());
}

fn defective_backend_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = materialize("simple-build").expect("simple fixture");
    let fake_bwrap = fixture.file("fake-bwrap");
    fs::write(
        &fake_bwrap,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'bubblewrap 0.8.0\\n'\n  exit 0\nfi\nexit 0\n",
    )
    .expect("write fake Bubblewrap");
    let mut permissions = fs::metadata(&fake_bwrap)
        .expect("fake Bubblewrap metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_bwrap, permissions).expect("make fake Bubblewrap executable");

    let mut command = base_command(&fixture);
    command.env("CARGO_CAGE_BWRAP", &fake_bwrap);
    let output = command.output().expect("run cargo-cage");
    assert!(!output.status.success());
    let text = output_text(&output);
    assert!(
        text.contains("Bubblewrap") || text.contains("sandbox backend"),
        "{text}"
    );
    assert!(!fixture.file("target").exists());
}

fn run_cage(fixture: &Fixture, extra: &[(&str, &str)]) -> Output {
    run_cage_with_env(fixture, extra)
}

fn run_cage_with_env(fixture: &Fixture, extra: &[(&str, &str)]) -> Output {
    let mut command = base_command(fixture);
    for (key, value) in extra {
        command.env(key, value);
    }
    command.output().expect("run cargo-cage")
}

fn base_command(fixture: &Fixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-cage"));
    command
        .current_dir(fixture.path())
        .args(["build", "--manifest-path"])
        .arg(fixture.file("Cargo.toml"))
        .env("HOME", fixture.file("fake-home"))
        .env("CARGO_HOME", host_cargo_home())
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR");
    apply_rustup_home(&mut command);
    command
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

fn host_cargo_home() -> OsString {
    env::var_os("CARGO_HOME").unwrap_or_else(|| {
        PathBuf::from(env::var_os("HOME").expect("test HOME"))
            .join(".cargo")
            .into_os_string()
    })
}

fn apply_rustup_home(command: &mut Command) {
    if let Some(rustup_home) = env::var_os("RUSTUP_HOME") {
        command.env("RUSTUP_HOME", rustup_home);
    }
}

fn prepend_path(directory: &Path) -> OsString {
    let mut entries = vec![directory.to_path_buf()];
    if let Some(path) = env::var_os("PATH") {
        entries.extend(env::split_paths(&path));
    }
    env::join_paths(entries).expect("valid PATH")
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", output_text(output));
}

fn assert_policy_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        output_text(output)
    );
    let text = output_text(output);
    assert!(text.contains("CAGE_POLICY_DENIED"), "{text}");
    assert!(
        text.contains("cargo-cage: Cargo build failed inside the Linux sandbox"),
        "{text}"
    );
}

fn output_text(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

fn find_file(root: &Path, name: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.file_name().and_then(|value| value.to_str()) == Some(name) {
            true
        } else if path.is_dir() {
            find_file(&path, name)
        } else {
            false
        }
    })
}
