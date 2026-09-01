#![cfg(target_os = "linux")]

use cage_testkit::{Fixture, materialize};
use std::env;
use std::fs;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

#[test]
fn linux_sandbox_acceptance_matrix() {
    simple_build_works();
    proc_macro_build_works();
    supported_cargo_commands_work();
    out_dir_is_writable();
    doctor_is_non_mutating();
    sensitive_home_path_is_hidden();
    host_home_socket_is_hidden();
    sensitive_environment_is_removed();
    cargo_config_is_hidden();
    runtime_paths_are_hidden();
    project_toolchain_path_is_rejected_before_compiler_execution();
    inherited_file_descriptors_do_not_reach_the_build();
    parent_death_kills_nested_builds();
    workspace_write_is_denied();
    nested_child_inherits_policy();
    network_is_denied();
    workspace_special_file_is_rejected();
    workspace_external_symlink_is_rejected();
    workspace_external_hardlink_is_rejected();
    target_external_hardlink_is_rejected();
    incremental_build_hardlinks_are_allowed();
    symlink_escape_is_denied();
    symlink_target_is_rejected();
    cargo_cache_symlink_is_rejected();
    cargo_git_cache_symlink_is_rejected();
    cargo_cache_nested_symlink_is_rejected();
    cargo_cache_special_file_is_rejected();
    cargo_cache_external_hardlink_is_rejected();
    missing_backend_fails_closed();
    old_backend_fails_closed();
    defective_backend_fails_closed();
}

fn simple_build_works() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let output = run_cage(&fixture, &[]);
    assert_success(&output);
    assert!(fixture.file("target/debug/cage-simple-build").is_file());
}

fn proc_macro_build_works() {
    let fixture = materialize("proc-macro-build").expect("proc-macro fixture");
    let output = run_cage(&fixture, &[]);
    assert_success(&output);
    assert!(fixture.file("target/debug/cage-proc-macro-build").is_file());
}

fn supported_cargo_commands_work() {
    for command in ["check", "test", "doc"] {
        let fixture = materialize("simple-build").expect("simple fixture");
        let output = run_cage_command(&fixture, command, &[]);
        assert_success(&output);
    }
}

fn out_dir_is_writable() {
    let fixture = materialize("out-dir-build").expect("OUT_DIR fixture");
    let output = run_cage(&fixture, &[]);
    assert_success(&output);
    assert!(find_file(&fixture.file("target"), "cage-output.txt"));
}

fn doctor_is_non_mutating() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let lockfile = fixture.file("Cargo.lock");
    let lock_before = fs::read(&lockfile).expect("fixture lockfile");
    assert!(!fixture.file("target").exists());

    let output = run_doctor(&fixture, false);
    assert_success(&output);
    let text = output_text(&output);
    assert!(text.contains("cargo-cage doctor"), "{text}");
    assert!(text.contains("sandbox preflight"), "{text}");
    assert!(!fixture.file("target").exists());
    assert_eq!(
        fs::read(&lockfile).expect("lockfile after doctor"),
        lock_before
    );
}

fn sensitive_home_path_is_hidden() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let fake_home = test_home(&fixture);
    fs::create_dir_all(fake_home.join(".ssh")).expect("fake ssh directory");
    fs::write(fake_home.join(".ssh/fixture-secret"), b"must stay hidden").expect("fake ssh secret");
    fs::write(
        fake_home.join("unlisted-fixture-secret"),
        b"must also stay hidden",
    )
    .expect("unlisted fake home secret");

    let output = run_cage_feature(&fixture, "home-read", &[]);
    assert_policy_failure(&output);
    assert!(fake_home.join(".ssh/fixture-secret").is_file());
}

fn host_home_socket_is_hidden() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let fake_home = test_home(&fixture);
    let socket = fake_home.join("fixture-agent.sock");
    let _listener = UnixListener::bind(&socket).expect("fake host agent socket");

    let output = run_cage_feature(&fixture, "home-socket-read", &[]);
    assert_policy_failure(&output);
    assert!(socket.exists());
}

fn sensitive_environment_is_removed() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let output = run_cage_feature(
        &fixture,
        "secret-env",
        &[
            ("AWS_SECRET_ACCESS_KEY", "fixture-secret"),
            ("GITHUB_TOKEN", "fixture-token"),
            ("CAGE_TEST_ARBITRARY_SECRET", "fixture-arbitrary-secret"),
            ("CARGO_REGISTRIES_CRATES_IO_TOKEN", "fixture-crates-token"),
            ("SSH_AUTH_SOCK", "/tmp/fixture-agent.sock"),
        ],
    );
    assert_policy_failure(&output);
    let text = output_text(&output);
    assert!(!text.contains("fixture-secret"), "{text}");
    assert!(!text.contains("fixture-token"), "{text}");
    assert!(!text.contains("fixture-crates-token"), "{text}");
    assert!(!text.contains("fixture-password"), "{text}");
}

fn cargo_config_is_hidden() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let cargo_home = test_cargo_home(&fixture);
    let config = cargo_home.join("config.toml");
    let config_before = b"[registries.private]\ntoken = \"fixture-secret\"\n";
    fs::write(&config, config_before).expect("write Cargo config fixture");

    let output = run_cage_feature_with_cargo_home(&fixture, "cargo-config-read", &cargo_home, &[]);
    assert_policy_failure(&output);
    let text = output_text(&output);
    assert!(text.contains("Cargo configuration"), "{text}");
    assert!(!text.contains("fixture-secret"), "{text}");
    assert_eq!(
        fs::read(config).expect("read Cargo config after build"),
        config_before
    );
}

fn runtime_paths_are_hidden() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let output = run_cage_feature(&fixture, "runtime-path-read", &[]);
    assert_policy_failure(&output);
}

fn project_toolchain_path_is_rejected_before_compiler_execution() {
    let mut rustup_probe = Command::new("rustup");
    rustup_probe
        .args(["which", "rustc"])
        .env_remove("RUSTUP_TOOLCHAIN");
    let rustup_output = rustup_probe.output();
    let Ok(rustup_output) = rustup_output else {
        return;
    };
    if !rustup_output.status.success() {
        return;
    }
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")));
    let Some(rustup_home) = rustup_home else {
        return;
    };
    if !fs::symlink_metadata(&rustup_home)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        return;
    }

    use std::os::unix::fs::PermissionsExt;

    let fixture = materialize("simple-build").expect("simple fixture");
    let toolchain = fixture
        .temporary_dir("project-toolchain")
        .expect("project toolchain directory");
    let bin = toolchain.join("bin");
    fs::create_dir(&bin).expect("fake toolchain bin directory");
    let marker = toolchain.join("compiler-ran");
    let compiler = bin.join("rustc");
    fs::write(
        &compiler,
        format!(
            "#!/bin/sh\nprintf ran > \"{}\"\nprintf '%s\\n' /usr\n",
            marker.display()
        ),
    )
    .expect("fake project compiler");
    let mut permissions = fs::metadata(&compiler)
        .expect("fake compiler metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&compiler, permissions).expect("make fake compiler executable");
    fs::write(
        fixture.file("rust-toolchain.toml"),
        format!("[toolchain]\npath = \"{}\"\n", toolchain.display()),
    )
    .expect("project toolchain override");

    let mut command = base_command(&fixture);
    command.env("RUSTC", "rustup");
    command.env("RUSTUP_HOME", &rustup_home);
    command.env_remove("RUSTUP_TOOLCHAIN");
    let output = command.output().expect("run cargo-cage");
    assert!(!output.status.success(), "unexpected toolchain success");
    let text = output_text(&output);
    assert!(
        text.to_ascii_lowercase().contains("rustup")
            || text.to_ascii_lowercase().contains("toolchain"),
        "{text}"
    );
    assert!(!marker.exists(), "project compiler ran before sandbox");
}

fn inherited_file_descriptors_do_not_reach_the_build() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let secret = fixture.file("inherited-fd-secret");
    let secret_before = b"must not be readable through fd 3";
    fs::write(&secret, secret_before).expect("write inherited fd fixture");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-cage"));
    let manifest = fixture.file("Cargo.toml");
    let mut command = Command::new("sh");
    command
        .current_dir(fixture.path())
        .args([
            "-c",
            "exec 3<\"$1\"; shift; exec \"$@\"",
            "cargo-cage-fd-test",
        ])
        .arg(&secret)
        .arg(binary)
        .args(["build", "--manifest-path"])
        .arg(manifest)
        .args(["--features", "fd-read"])
        .env("HOME", test_home(&fixture))
        .env("CARGO_HOME", test_cargo_home(&fixture))
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR");
    apply_rustup_home(&mut command);

    let output = command.output().expect("run cargo-cage with inherited fd");
    assert_policy_failure(&output);
    assert_eq!(
        fs::read(&secret).expect("read inherited fd fixture"),
        secret_before
    );
}

fn parent_death_kills_nested_builds() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let started = fixture.file("target/parent-death-started");
    let finished = fixture.file("target/parent-death-finished");
    let mut command = base_command_for(&fixture, "build");
    command.args(["--features", "parent-death"]);
    let mut child = command.spawn().expect("spawn cargo-cage parent-death test");

    for _ in 0..50 {
        if started.is_file() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(started.is_file(), "parent-death fixture did not start");

    child.kill().expect("kill cargo-cage parent");
    let _ = child.wait().expect("wait for killed cargo-cage");
    thread::sleep(Duration::from_secs(3));
    assert!(
        !finished.exists(),
        "nested child survived cargo-cage parent"
    );
}

fn workspace_write_is_denied() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let path = fixture.file("build-script-write.txt");
    let output = run_cage_feature(&fixture, "workspace-write", &[]);
    assert_policy_failure(&output);
    assert!(!path.exists());
}

fn nested_child_inherits_policy() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let path = fixture.file("nested-write.txt");
    let output = run_cage_feature(&fixture, "nested-write", &[]);
    assert_policy_failure(&output);
    assert!(!path.exists());
}

fn network_is_denied() {
    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener");
    let endpoint = listener.local_addr().expect("listener address").to_string();
    fs::write(fixture.file("network-endpoint.txt"), endpoint).expect("write network endpoint");
    let output = run_cage_feature(&fixture, "network", &[]);
    assert_policy_failure(&output);
}

fn workspace_special_file_is_rejected() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let socket_path = fixture.file("workspace.sock");
    let _listener = UnixListener::bind(&socket_path).expect("workspace socket");

    let output = run_cage(&fixture, &[]);
    assert_setup_policy_failure(&output, "regular files");
    assert!(socket_path.exists());
}

fn workspace_external_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = materialize("simple-build").expect("simple fixture");
    let external = fixture
        .temporary_dir("workspace-symlink-target")
        .expect("external workspace target")
        .join("secret");
    fs::write(&external, b"must stay outside").expect("write external workspace target");
    let link = fixture.file("workspace-escape");
    symlink(&external, &link).expect("workspace symlink");

    let output = run_cage(&fixture, &[]);
    assert_setup_policy_failure(&output, "symlink");
    assert!(external.is_file());
}

fn workspace_external_hardlink_is_rejected() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let external = fixture
        .temporary_dir("workspace-hardlink-target")
        .expect("external workspace target")
        .join("secret");
    fs::write(&external, b"must stay outside").expect("write external workspace target");
    let hardlink = fixture.file("workspace-hardlink");
    fs::hard_link(&external, &hardlink).expect("workspace hardlink");

    let output = run_cage(&fixture, &[]);
    assert_setup_policy_failure(&output, "hardlink");
    assert_eq!(
        fs::read(&external).expect("read external workspace target"),
        b"must stay outside"
    );
}

fn target_external_hardlink_is_rejected() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let target = fixture.file("target");
    fs::create_dir(&target).expect("target directory");
    let external = fixture
        .temporary_dir("target-hardlink-target")
        .expect("external target")
        .join("secret");
    fs::write(&external, b"must stay outside").expect("write external target");
    fs::hard_link(&external, target.join("hardlink")).expect("target hardlink");

    let output = run_cage(&fixture, &[]);
    assert_setup_policy_failure(&output, "hardlink");
    assert_eq!(
        fs::read(&external).expect("read external target"),
        b"must stay outside"
    );
}

fn incremental_build_hardlinks_are_allowed() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let first = run_cage(&fixture, &[]);
    assert_success(&first);
    let second = run_cage(&fixture, &[]);
    assert_success(&second);
}

fn symlink_escape_is_denied() {
    use std::os::unix::fs::symlink;

    let fixture = materialize("malicious-build-script").expect("malicious fixture");
    fs::create_dir(fixture.file("target")).expect("target directory");
    let external = fixture.file("symlink-target.txt");
    symlink(&external, fixture.file("target/escape-link")).expect("escape symlink");
    let output = run_cage_feature(&fixture, "symlink-escape", &[]);
    assert_setup_policy_failure(&output, "symlink");
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

fn cargo_cache_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = materialize("simple-build").expect("simple fixture");
    let cargo_home = test_cargo_home(&fixture);
    let external = fixture.file("external-cache");
    fs::create_dir(&external).expect("create external cache");
    fs::write(external.join("cache-secret"), b"must stay outside").expect("write cache secret");
    symlink(&external, cargo_home.join("registry")).expect("create cache symlink");

    let output = run_cage_with_cargo_home(&fixture, &cargo_home, &[]);
    assert_cache_setup_failure(&output);
    assert!(external.join("cache-secret").is_file());
    assert!(!fixture.file("target").exists());
}

fn cargo_cache_nested_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = materialize("simple-build").expect("simple fixture");
    let cargo_home = test_cargo_home(&fixture);
    let registry = cargo_home.join("registry");
    fs::create_dir(&registry).expect("create registry cache");
    let external = fixture.file("nested-external-cache");
    fs::create_dir(&external).expect("create nested external cache");
    fs::write(external.join("cache-secret"), b"must stay outside")
        .expect("write nested cache secret");
    symlink(&external, registry.join("escape")).expect("create nested cache symlink");

    let output = run_cage_with_cargo_home(&fixture, &cargo_home, &[]);
    assert_cache_setup_failure(&output);
    assert!(external.join("cache-secret").is_file());
    assert!(!fixture.file("target").exists());
}

fn cargo_git_cache_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = materialize("simple-build").expect("simple fixture");
    let cargo_home = test_cargo_home(&fixture);
    let external = fixture.file("external-git-cache");
    fs::create_dir(&external).expect("create external git cache");
    fs::write(external.join("cache-secret"), b"must stay outside").expect("write git cache secret");
    symlink(&external, cargo_home.join("git")).expect("create git cache symlink");

    let output = run_cage_with_cargo_home(&fixture, &cargo_home, &[]);
    assert_cache_setup_failure(&output);
    assert!(external.join("cache-secret").is_file());
    assert!(!fixture.file("target").exists());
}

fn cargo_cache_special_file_is_rejected() {
    use std::os::unix::net::UnixListener;

    let fixture = materialize("simple-build").expect("simple fixture");
    let cargo_home = test_cargo_home(&fixture);
    let git = cargo_home.join("git");
    fs::create_dir(&git).expect("create git cache");
    let socket_path = git.join("cache.sock");
    let _listener = UnixListener::bind(&socket_path).expect("create cache socket");

    let output = run_cage_with_cargo_home(&fixture, &cargo_home, &[]);
    assert_cache_setup_failure(&output);
    assert!(socket_path.exists());
    assert!(!fixture.file("target").exists());
}

fn cargo_cache_external_hardlink_is_rejected() {
    let fixture = materialize("simple-build").expect("simple fixture");
    let cargo_home = test_cargo_home(&fixture);
    let registry = cargo_home.join("registry");
    fs::create_dir(&registry).expect("create registry cache");
    let external = fixture
        .temporary_dir("cache-hardlink-target")
        .expect("external cache target")
        .join("secret");
    fs::write(&external, b"must stay outside").expect("write external cache target");
    fs::hard_link(&external, registry.join("hardlink")).expect("cache hardlink");

    let output = run_cage_with_cargo_home(&fixture, &cargo_home, &[]);
    assert_cache_setup_failure(&output);
    assert_eq!(
        fs::read(&external).expect("read external cache target"),
        b"must stay outside"
    );
    assert!(!fixture.file("target").exists());
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
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'bubblewrap 0.12.0\\n'\n  exit 0\nfi\nexit 0\n",
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

fn old_backend_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = materialize("simple-build").expect("simple fixture");
    let old_bwrap = fixture.file("old-bwrap");
    fs::write(
        &old_bwrap,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf 'bubblewrap 0.11.2\\n'\n  exit 0\nfi\nexit 0\n",
    )
    .expect("write old Bubblewrap");
    let mut permissions = fs::metadata(&old_bwrap)
        .expect("old Bubblewrap metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&old_bwrap, permissions).expect("make old Bubblewrap executable");

    let mut command = base_command(&fixture);
    command.env("CARGO_CAGE_BWRAP", &old_bwrap);
    let output = command.output().expect("run cargo-cage");
    assert!(!output.status.success());
    let text = output_text(&output);
    assert!(
        text.contains("too old") && text.contains("0.12.0"),
        "{text}"
    );
    assert!(!fixture.file("target").exists());
}

fn run_cage(fixture: &Fixture, extra: &[(&str, &str)]) -> Output {
    let mut command = base_command_for(fixture, "build");
    apply_extra_environment(&mut command, extra);
    command.output().expect("run cargo-cage")
}

fn run_cage_feature(fixture: &Fixture, feature: &str, extra: &[(&str, &str)]) -> Output {
    let mut command = base_command_for(fixture, "build");
    command.args(["--features", feature]);
    apply_extra_environment(&mut command, extra);
    command.output().expect("run cargo-cage")
}

fn run_cage_command(fixture: &Fixture, cargo_command: &str, extra: &[(&str, &str)]) -> Output {
    let mut command = base_command_for(fixture, cargo_command);
    apply_extra_environment(&mut command, extra);
    command.output().expect("run cargo-cage")
}

fn run_doctor(fixture: &Fixture, verbose: bool) -> Output {
    let cargo_home = test_cargo_home(fixture);
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-cage"));
    command
        .current_dir(fixture.path())
        .arg("doctor")
        .env("HOME", test_home(fixture))
        .env("CARGO_HOME", cargo_home)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR");
    if verbose {
        command.arg("--verbose");
    }
    apply_rustup_home(&mut command);
    command.output().expect("run cargo-cage doctor")
}

fn run_cage_with_cargo_home(
    fixture: &Fixture,
    cargo_home: &Path,
    extra: &[(&str, &str)],
) -> Output {
    let mut command = base_command(fixture);
    command.env("CARGO_HOME", cargo_home);
    for (key, value) in extra {
        command.env(key, value);
    }
    command.output().expect("run cargo-cage")
}

fn run_cage_feature_with_cargo_home(
    fixture: &Fixture,
    feature: &str,
    cargo_home: &Path,
    extra: &[(&str, &str)],
) -> Output {
    let mut command = base_command(fixture);
    command
        .args(["--features", feature])
        .env("CARGO_HOME", cargo_home);
    apply_extra_environment(&mut command, extra);
    command.output().expect("run cargo-cage")
}

fn base_command_for(fixture: &Fixture, cargo_command: &str) -> Command {
    let cargo_home = test_cargo_home(fixture);
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-cage"));
    command
        .current_dir(fixture.path())
        .args([cargo_command, "--manifest-path"])
        .arg(fixture.file("Cargo.toml"))
        .env("HOME", test_home(fixture))
        .env("CARGO_HOME", cargo_home)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR");
    apply_rustup_home(&mut command);
    command
}

fn base_command(fixture: &Fixture) -> Command {
    base_command_for(fixture, "build")
}

fn test_cargo_home(fixture: &Fixture) -> PathBuf {
    fixture
        .temporary_dir("cargo-home")
        .expect("create fixture Cargo home")
}

fn test_home(fixture: &Fixture) -> PathBuf {
    fixture
        .temporary_dir("fake-home")
        .expect("create fixture home")
}

fn apply_rustup_home(command: &mut Command) {
    if let Some(rustup_home) = env::var_os("RUSTUP_HOME") {
        command.env("RUSTUP_HOME", rustup_home);
    }
}

fn apply_extra_environment(command: &mut Command, extra: &[(&str, &str)]) {
    for (key, value) in extra {
        command.env(key, value);
    }
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

fn assert_setup_policy_failure(output: &Output, rule_fragment: &str) {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        output_text(output)
    );
    let text = output_text(output);
    assert!(text.contains(rule_fragment), "{text}");
    assert!(text.contains("sandbox policy error"), "{text}");
    assert!(text.contains("remedy:"), "{text}");
}

fn assert_cache_setup_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        output_text(output)
    );
    let text = output_text(output);
    assert!(text.contains("Cargo cache"), "{text}");
    assert!(
        text.contains("symlink") || text.contains("regular files") || text.contains("hardlink"),
        "{text}"
    );
    assert!(text.contains("remedy:"), "{text}");
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
