# Threat model

## Scope

This document describes the intended boundary of the experimental Linux v0.3
workflow.
It is not proof that the boundary holds against an unknown kernel, Bubblewrap
bug, or toolchain vulnerability.

## Adversary

The following are treated as untrusted:

- workspace build scripts (`build.rs`);
- procedural macros and compiler helpers;
- dependencies being compiled;
- every child process started by the build.

The user is responsible for choosing the Cargo command, toolchain, workspace,
and host security policy.

## Assets

The relevant assets are:

- host network access and local TCP services;
- SSH, AWS, Cargo, and similar credentials in selected home paths;
- files outside the allowed build outputs;
- host processes and host IPC, to the extent covered by the namespaces.

## Trusted components

The Linux kernel, host security policy, Bubblewrap, Cargo, Rustc, and the
user's selected toolchain are trusted components for this release. The host
policy must permit Bubblewrap to create the namespaces required by the backend.

## Enforced boundary

Before each Cargo operation, the backend runs a Bubblewrap preflight and checks
that the requested mount, user, PID, IPC, UTS, and network namespaces are
actually different from the parent where applicable. The host filesystem is
mounted read-only. The canonical workspace `target` directory and
`Cargo.lock` are then explicitly mounted read-write.

`/tmp` and `/run` are private tmpfs filesystems. `TMPDIR` points to the private
`/tmp`. If the workspace itself lives below a private path, it is re-mounted
read-only so Cargo can still read its sources.

Cargo runs with `CARGO_NET_OFFLINE=true` and a private `CARGO_HOME`. Existing
`registry` and `git` caches are mounted read-only only after checking the cache
root, rejecting symlinks and special files, and checking that the source does
not overlap a writable, hidden, or private path. Cargo `config` and
`config.toml` are not mounted. Credentials files are not mounted.

Known credential and agent variables are removed. The list is intentionally not
complete and must not be treated as general-purpose secret scrubbing.

Paths are checked and canonicalized before they are mounted. Writable target
paths, the lockfile, and paths used for sandbox mounts must not rely on unsafe
symlink resolution. A missing, old, or broken sandbox prerequisite aborts the
operation before the real Cargo process starts. There is no unsandboxed
fallback and no automatic network fetch. `build`, `check`, `test`, and `doc`
are supported; `run`, `publish`, `fmt`, and arbitrary Cargo commands are not.

`cargo cage doctor` repeats the relevant host and project validation without
creating project files. Missing target directories, lockfiles, or caches are
reported as warnings when they are safe to create or can be prepared with a
separate `cargo fetch`.

## What this protects

- A build script cannot use the sandbox network namespace to reach a host TCP
  service.
- Masked home paths do not expose their host contents through the normal path.
- Known credential and agent variables are not passed to the child.
- Writes to the read-only workspace, including writes through a symlink from
  `target`, fail with a normal operating-system error.
- Child processes, test binaries, and compiler helpers inherit the mount and
  namespace boundary.
- A malformed or unsafe Cargo cache stops the build before Cargo starts.
- A missing, old, or non-working Bubblewrap backend stops the build before the
  real Cargo process runs.

## What this does not protect

- Kernel, Bubblewrap, Cargo, Rustc, or toolchain vulnerabilities.
- Resource exhaustion, fork bombs, long-running builds, or other denial of
  service attacks.
- Every host file. Non-masked files remain readable, and the home-path list is
  not complete.
- Secrets in environment variables that are not removed, compiler flags,
  readable project files, or hard-link aliases.
- Data that an untrusted build writes inside `target`.
- Safe execution of generated artifacts.
- A seccomp policy or syscall-level audit record.
- A fully race-free filesystem sandbox against another local process changing
  the path hierarchy while setup is in progress.
- A GUI, macOS/Windows backend, dependency reputation, or AI-based detection
  system.

## Residual risk

The path checks use safe Rust and the standard library. They reduce accidental
and straightforward symlink/path escapes, but they cannot make a set of
path-based checks atomic against a concurrent local attacker. The project must
not claim complete confidentiality or complete sandbox escape prevention.
