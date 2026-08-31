# Threat model

## Scope

This document describes the intended boundary of the experimental Linux
workflow. The v0.4 hardening work is being developed against the current 0.3
package and is not released until Ubuntu CI has passed.
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

The Linux kernel, host security policy, Bubblewrap 0.12.0 or newer, Cargo,
Rustc, and the user's selected toolchain are trusted components for this
release. The host policy must permit Bubblewrap to create the namespaces
required by the backend.
Older Bubblewrap releases are outside the supported trust boundary because of
the upstream [GHSA-pxhw-h44j-8pfx setup vulnerability](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx).

## Enforced boundary

Before each Cargo operation, the backend runs a Bubblewrap preflight and checks
that the requested mount, user, PID, IPC, UTS, and network namespaces are
actually different from the parent where applicable. A small read-only Linux
runtime plus the explicitly selected project/toolchain paths is mounted; the
host root is not mounted wholesale. The canonical workspace `target`
directory and `Cargo.lock` are then explicitly mounted read-write.

`HOME`, `/tmp`, `/var/tmp`, and `/run` are private filesystems. `TMPDIR` points
to the private `/tmp`. If the workspace or a required Rust toolchain lives below a
private path, it is re-mounted read-only so Cargo can still use it.

Cargo runs with `CARGO_NET_OFFLINE=true`, a private `CARGO_HOME`, and a clean
environment populated only from a fixed Cargo/Rust allowlist. Existing
`registry` and `git` caches are mounted read-only only after checking the cache
root, rejecting symlinks and special files, and checking that the source does
not overlap a writable or hidden path. Cache sources may live below a private
host path because they are mounted at the private Cargo home destination.
Cargo `config` and `config.toml` are deliberately not mounted. Credentials
files are not mounted. A project-local Cargo config inside the read-only
workspace remains visible and is treated as untrusted project input.

Known credential and agent variables are removed, and the normal Cargo path
does not inherit arbitrary host variables at all. The allowlist still includes
user-controlled build configuration such as compiler flags and is not
general-purpose secret scrubbing.

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
- Non-selected host paths such as `/sys`, `/boot`, and the host `/var` tree are
  not part of the runtime filesystem view.
- Extra inherited file descriptors are closed by Bubblewrap before the child
  starts, and existing writable-tree symlinks and special files are rejected.
- A malformed or unsafe Cargo cache stops the build before Cargo starts.
- A missing, old, or non-working Bubblewrap backend stops the build before the
  real Cargo process runs.

## What this does not protect

- Kernel, Bubblewrap, Cargo, Rustc, or toolchain vulnerabilities.
- Resource exhaustion, fork bombs, long-running builds, or other denial of
  service attacks.
- The selected Linux runtime directories, workspace files, and toolchain files
  are intentionally readable.
- Secrets in environment variables that are not removed, compiler flags,
  readable project files, or hard-link aliases inside the target tree.
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
