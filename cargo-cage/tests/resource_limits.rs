#![cfg(target_os = "linux")]

use cage_core::{
    CageError, Environment, NetworkAccess, OutputMode, ResourceLimitKind, ResourceLimits,
    SandboxBackend, SandboxOutcome, SandboxPolicy, SandboxRequest,
};
use cage_linux::LinuxSandbox;
use std::path::PathBuf;
use std::time::Duration;

fn run_shell(script: &str, limits: ResourceLimits) -> cage_core::CageResult<SandboxOutcome> {
    let backend = LinuxSandbox::with_launcher(env!("CARGO_BIN_EXE_cargo-cage-landlock-launcher"))?;
    let mut request = SandboxRequest::new("/bin/sh", "/tmp");
    request.args = vec!["-c".into(), script.into()];
    request.environment = Environment::clean();
    request.output = OutputMode::Capture;
    request.policy = SandboxPolicy {
        network: NetworkAccess::Deny,
        resources: limits,
        private_paths: vec![PathBuf::from("/tmp")],
        ..SandboxPolicy::default()
    };
    backend.run(&request)
}

#[test]
fn wall_clock_budget_is_enforced_and_reported() {
    let limits = ResourceLimits {
        max_wall_time: Duration::from_millis(250),
        ..ResourceLimits::default()
    };
    let error = run_shell("sleep 5", limits).expect_err("sleep must exceed the wall budget");
    assert!(matches!(
        error,
        CageError::ResourceLimitExceeded {
            kind: ResourceLimitKind::WallTime,
            ..
        }
    ));
    assert!(error.to_string().contains("wall-clock time"));
    assert!(error.to_string().contains("remedy:"));
}

#[test]
fn process_budget_is_enforced_and_reported() {
    let limits = ResourceLimits {
        max_processes: 16,
        max_wall_time: Duration::from_secs(5),
        ..ResourceLimits::default()
    };
    let error = run_shell(
        "i=0; while [ \"$i\" -lt 256 ]; do /bin/true & i=$((i + 1)); done; wait",
        limits,
    )
    .expect_err("the process storm must hit pids.max");
    assert!(matches!(
        error,
        CageError::ResourceLimitExceeded {
            kind: ResourceLimitKind::Processes,
            ..
        }
    ));
    assert!(error.to_string().contains("process count"));
    assert!(error.to_string().contains("remedy:"));
}

#[test]
fn file_size_budget_is_enforced_and_reported() {
    let limits = ResourceLimits {
        max_file_size_bytes: 1024 * 1024,
        max_wall_time: Duration::from_secs(5),
        ..ResourceLimits::default()
    };
    let error = run_shell(
        "exec /bin/dd if=/dev/zero of=/tmp/cargo-cage-file-limit bs=2M count=1 status=none",
        limits,
    )
    .expect_err("the file-size budget must reject an oversized write");
    assert!(matches!(
        error,
        CageError::ResourceLimitExceeded {
            kind: ResourceLimitKind::FileSize,
            ..
        }
    ));
    assert!(error.to_string().contains("file size"));
    assert!(error.to_string().contains("remedy:"));
}

#[test]
fn open_file_budget_is_inherited_by_children() {
    let limits = ResourceLimits {
        max_wall_time: Duration::from_secs(5),
        ..ResourceLimits::default()
    };
    let outcome = run_shell(
        r#"exec /bin/bash -c 'for ((fd=3; fd<20000; fd++)); do eval "exec ${fd}</dev/null" 2>/dev/null || exit 42; done'"#,
        limits,
    )
    .expect("the child should fail natively when the descriptor budget is exhausted");
    assert!(!outcome.status.successfully_exited());
}
