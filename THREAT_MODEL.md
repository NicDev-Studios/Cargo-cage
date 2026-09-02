# Threat model

## Why this exists

Cargo builds are not just compiler invocations. They can run `build.rs`,
procedural macros, linkers, compiler wrappers, and arbitrary child processes.
Those processes are useful, but a dependency can also use them to read files,
open sockets, or modify the checkout. `cargo-cage` tries to make that failure
mode less painful on Linux.

It is an experimental, local-build boundary. This first public alpha is
`0.1.0-alpha.1`; it is not a proof of complete isolation.

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
single tree. Each command gets a fresh writable target run below
target/.cargo-cage/runs/; Cargo.lock is the only other persistent writable
file. /tmp, /var/tmp, and /run are private.

Host path sources are opened through fd-based, symlink-resistant resolution
and passed to Bubblewrap with fd bind options. Once Bubblewrap has finished its
mount setup, an internal Rust launcher applies a deny-by-default Landlock
ruleset before starting Cargo. The required filesystem baseline is Landlock
ABI 5. Newer Unix-socket and scope restrictions are used when available.

Cargo runs with `CARGO_NET_OFFLINE=true`, a private `CARGO_HOME`, and a clean
environment populated from a fixed allowlist. Existing `registry` and `git`
caches are mounted read-only only after checking their roots and contents.
Cargo user config and credential files stay out of the sandbox. A project-local
Cargo config remains visible because it is project input, not host trust.
Standard stdio remains connected; extra inherited file descriptors are scrubbed
before the build process is exec'd by the fixed `/bin/bash` scrubber. A missing
Bash runtime is a setup error, not a fallback condition.

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
- A path source changing between validation and Bubblewrap setup in the common
  fd-bind case.
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
- Files a build writes inside an isolated target run; those artifacts are not
  trusted or copied into the normal target tree.
- The explicit --reuse-target mode, which is only intended for trusted
  workspaces and restores persistent incremental-artifact risk.
- Every filesystem operation that Landlock does not cover, including some
  actions involving already-open file descriptors.
- A race-free filesystem guarantee against another local process changing the
  path hierarchy during setup.
- A `cargo cage` alias bypass. Cargo expands aliases before external
  subcommands, so a workspace can prevent `cargo-cage` from being started at
  all. Use the direct executable. See
  [Cargo issue #10049](https://github.com/rust-lang/cargo/issues/10049).
- Seccomp, resource limits, a GUI, macOS/Windows support, dependency
  reputation, or AI-based detection.

## Residual risk

The path checks use safe Rust and the standard library, while host mount
sources use safe wrappers around fd-based Linux APIs. They reduce accidental
and straightforward filesystem escapes, but they do not make every operation
atomic against a concurrent local attacker. The project must not claim
complete confidentiality or complete sandbox escape prevention.

The independent Rust red-team runner in security/redteam is intentionally
separate from the normal regression tests. It tries black-box writes, reads,
sockets, process and namespace operations, target poisoning, and concurrent
path swaps. A green run is useful evidence, not a proof against a kernel or
sandbox vulnerability.

The dispatcher issue is worth spelling out: if the user runs `cargo cage
build` and Cargo expands a repository or user alias named `cage`, `cargo-cage`
never gets a chance to enforce anything. This is why the README and security
docs require `cargo-cage build` for untrusted workspaces.
