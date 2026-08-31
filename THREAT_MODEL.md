# Threat model

## Why this exists

Cargo builds are not just compiler invocations. They can run `build.rs`,
procedural macros, linkers, compiler wrappers, and arbitrary child processes.
Those processes are useful, but a dependency can also use them to read files,
open sockets, or modify the checkout. `cargo-cage` tries to make that failure
mode less painful on Linux.

It is an experimental, local-build boundary. It is not a proof of complete
isolation, and the current hardening work remains version `0.3.0` until Ubuntu
CI has passed.

## Adversary

We treat these as untrusted code:

- workspace `build.rs` scripts;
- procedural macros and compiler helpers;
- dependencies being compiled;
- linkers and child processes started by the build.

The user still chooses the workspace, Cargo command, toolchain, host policy,
and the files they are willing to build.

## Assets

The main things we are trying not to hand to a build script are:

- host network access and local TCP services;
- SSH, AWS, Cargo, and similar credentials;
- agent sockets and host IPC endpoints;
- files outside the allowed project outputs;
- the ability to persist changes outside `target` and `Cargo.lock`.

## Trusted components

The Linux kernel, the host security policy, Bubblewrap `0.12.0+`, Cargo, Rustc,
and the user's selected toolchain are trusted for this release. If one of
those has a vulnerability or is configured to behave maliciously, this tool
cannot repair it.

Bubblewrap versions below `0.12.0` are outside the trust boundary because of
the upstream
[GHSA-pxhw-h44j-8pfx setup vulnerability](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx).

## Boundary

Before each Cargo operation, the backend runs a real Bubblewrap preflight and
checks the requested mount, user, PID, IPC, UTS, and network namespaces where
applicable. It also checks capabilities, `NoNewPrivs`, the new session, and
the parent-death guard. If setup cannot be proved, the operation stops.

The sandbox exposes a small read-only Linux runtime plus the selected
workspace, toolchain, and Cargo cache paths. The host root is not mounted as a
single tree. The canonical workspace `target` directory and `Cargo.lock` are
the persistent writable locations. `/tmp`, `/var/tmp`, and `/run` are private.

Cargo runs with `CARGO_NET_OFFLINE=true`, a private `CARGO_HOME`, and a clean
environment populated from a fixed allowlist. Existing `registry` and `git`
caches are mounted read-only only after checking their roots and contents.
Cargo user config and credential files stay out of the sandbox. A project-local
Cargo config remains visible because it is project input, not host trust.

Workspace, cache, target, lockfile, hidden, and toolchain paths are checked
before mounting. Traversal, unsafe symlink resolution, special files, nested
mountpoints, and hardlink aliases reaching outside the validated tree fail
closed. Cargo's internal hardlinks are allowed when every alias stays inside
`target`.

Rustup project path overrides are rejected before the selected compiler runs,
and missing toolchains are not installed automatically. Build scripts,
proc-macros, test binaries, linkers, compiler helpers, and their children all
run under the same Bubblewrap boundary. There is no unsandboxed fallback and
no automatic network fetch.

The supported Cargo operations are `build`, `check`, `test`, and `doc`. The
direct executable form, for example `cargo-cage build`, is the security-
canonical invocation.

## What this protects against

- A build script reaching a host TCP service through the normal network path.
- Reads from masked credential and agent locations such as `.ssh`, `.aws`,
  Cargo credentials, and common host sockets.
- Writes to the read-only workspace or to persistent paths outside `target` and
  `Cargo.lock`.
- Straightforward symlink, traversal, special-file, nested-mount, and external
  hardlink escapes in paths that are about to be mounted.
- A missing, old, or broken Bubblewrap backend silently turning into a normal
  host build.
- Extra inherited file descriptors crossing into the build.

## What this does not protect against

- Kernel, Bubblewrap, Cargo, Rustc, toolchain, or host-policy vulnerabilities.
- Resource exhaustion, fork bombs, long-running builds, or other denial of
  service.
- Side channels or complete secrecy of every host file and environment value.
- Secrets deliberately placed in readable project files, compiler flags, or
  selected runtime/toolchain paths.
- Files a build writes inside `target`; those artifacts are not trusted.
- A race-free filesystem guarantee against another local process changing the
  path hierarchy during setup.
- A `cargo cage` alias bypass. Cargo expands aliases before external
  subcommands, so a workspace can prevent `cargo-cage` from being started at
  all. Use the direct executable. See
  [Cargo issue #10049](https://github.com/rust-lang/cargo/issues/10049).
- Seccomp, Landlock, resource limits, a GUI, macOS/Windows support, dependency
  reputation, or AI-based detection.

## Residual risk

The path checks use safe Rust and the standard library and are intentionally
conservative. They reduce accidental and straightforward filesystem escapes,
but they do not make path validation atomic against a concurrent local
attacker. The project must not claim complete confidentiality or complete
sandbox escape prevention.

The dispatcher issue is worth spelling out: if the user runs `cargo cage
build` and Cargo expands a repository or user alias named `cage`, `cargo-cage`
never gets a chance to enforce anything. This is why the README and security
docs require `cargo-cage build` for untrusted workspaces.
