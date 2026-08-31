# Threat model

## Scope

This document describes the intended boundary of the experimental Linux MVP.
It is not proof that the boundary holds against an unknown kernel or
Bubblewrap bug.

## Adversary and assets

The workspace, its `build.rs`, procedural macros, compiler helpers, and every
child process they start are treated as untrusted.

The main assets are:

- host network access and local TCP services;
- SSH, AWS, Cargo, and similar credentials in selected home paths;
- files outside the allowed build outputs;
- host processes and host IPC, to the extent covered by the namespaces.

The Linux kernel, host security policy, Bubblewrap, Cargo, Rustc, and the
user's selected toolchain are trusted components for this MVP. The host policy
must permit Bubblewrap to create the namespaces required by the sandbox.

## Enforced policy

Before each Cargo operation, Bubblewrap creates fresh mount, user, PID, IPC,
UTS, and network namespaces. The host filesystem is mounted read-only. The
workspace `target` directory and `Cargo.lock` are then explicitly mounted
read-write.

For builds, `/tmp` and `/run` are private tmpfs filesystems. `TMPDIR` points to
the private `/tmp`. If the workspace itself lives below a private path, it is
re-mounted read-only so Cargo can still read its sources.

Cargo also runs with `CARGO_NET_OFFLINE=true`. Existing registry and Git caches
are exposed read-only through a temporary `CARGO_HOME`; credentials are not
copied into it.

Known credential and agent variables are removed. That list is intentionally
not complete and must not be treated as general-purpose secret scrubbing.

Paths are checked and canonicalized before they are mounted. Writable target
paths, the lockfile, and paths used for sandbox mounts must not rely on unsafe
symlink resolution. A missing or broken sandbox prerequisite aborts the
operation before Cargo starts. There is no unsandboxed fallback.

## What this protects

- A build script cannot use the sandbox network namespace to reach a host TCP
  service.
- Masked home paths do not expose their host contents to the build.
- Writes to the read-only workspace, including writes through a symlink from
  `target`, fail with a normal operating-system error.
- Child processes inherit the mount and namespace boundary.
- A missing, old, or non-working Bubblewrap backend stops the build before the
  real Cargo process runs.

## What this does not protect

- Kernel, Bubblewrap, Cargo, Rustc, or toolchain vulnerabilities.
- Resource exhaustion, fork bombs, long-running builds, or other denial of
  service attacks.
- Every host file. Non-masked files remain readable, and the home-path list is
  not complete.
- Secrets in environment variables that are not removed, compiler flags, or
  readable project files.
- Data that an untrusted build writes inside `target`.
- Safe execution of generated artifacts.
- A GUI, macOS/Windows backend, dependency reputation, or AI-based detection
  system.
- A reliable audit record for every denied syscall. If a build script ignores
  an operation's error and continues successfully, v0.1 cannot report that
  attempt afterwards.

## Assumptions and residual risk

The MVP requires Bubblewrap 0.8 or newer, a Linux kernel with working
unprivileged user namespaces, and a compatible toolchain. The path checks do
not turn the implementation into a fully race-free filesystem sandbox against
another local process changing the path hierarchy at the same time.
