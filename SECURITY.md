# Security

Let's be direct: `cargo-cage` is experimental. It adds a useful Linux
boundary around Cargo, but it is not a complete sandbox and it does not come
with a promise that hostile code can never escape. If you need a hard,
independent trust boundary, use a VM or a dedicated build service as well.

The intended boundary and the assumptions behind it live in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Supported platform

The reference platform is Ubuntu 24.04 x86_64 with Bubblewrap `0.12.0` or
newer, unprivileged user namespaces enabled, and a host AppArmor policy that
allows Bubblewrap to set up those namespaces. Other Linux distributions may
work, but they are experimental. macOS and Windows are not supported.

Bubblewrap versions below `0.12.0` are rejected because they are outside the
supported baseline after the upstream
[GHSA-pxhw-h44j-8pfx setup vulnerability](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx).

## What we actually enforce

The Linux backend mounts a small read-only runtime, the workspace, checked
toolchain paths, and checked Cargo caches. The host root is not mounted as one
giant read-only tree. `target` and the workspace `Cargo.lock` are the only
persistent writable locations. `/tmp`, `/var/tmp`, and `/run` are private.

Network access is denied twice: Bubblewrap gets a separate network namespace,
and Cargo is forced into offline mode. There is no automatic fetch.

The child starts with an empty environment. A fixed allowlist supplies the
Cargo/Rust, compiler, locale, and terminal values needed for normal builds.
Credentials, agent variables, `CARGO_HOME`, `RUSTUP_HOME`, and arbitrary host
variables do not cross the boundary. Policy removals win over later
environment values. Standard stdio is kept for normal Cargo behaviour; extra
inherited file descriptors are closed before the build process starts.

Cargo gets a private `CARGO_HOME`. Only existing `registry` and `git` caches
are considered, and only after their roots and contents pass validation.
User/global Cargo config and credentials are intentionally not mounted. A
project-local `.cargo/config.toml` is still part of the workspace input; it is
not a trust signal.

Before mounting, the backend checks paths, types, overlaps, and canonical
resolution. Nested mountpoints, sockets, device nodes, FIFOs, external
symlinks, and hardlink aliases leaving a validated tree stop the operation.
Hardlinks Cargo keeps entirely inside `target` remain usable.

The selected Rustup compiler is resolved before execution. Project path
overrides outside trusted Rustup toolchains or the system runtime are rejected,
and missing toolchains are not installed automatically. Child processes,
procedural macros, test binaries, linkers, and compiler helpers inherit the
same Bubblewrap boundary.

There is no unsandboxed fallback. If Bubblewrap is absent, too old, not
executable, or cannot complete its preflight, the build stops.

## The invocation trap

Use `cargo-cage build`, not `cargo cage build`, when this boundary matters.
Cargo processes `[alias]` entries before it launches external subcommands. A
workspace can define an alias named `cage`, and then Cargo may never launch
`cargo-cage` at all. No code in this repository can detect a process that was
never started. This is a Cargo dispatcher limitation, not a Bubblewrap escape.
Cargo is tracking the upstream fix in
[issue #10049](https://github.com/rust-lang/cargo/issues/10049).

## Reporting a security issue

Please do not put a working sandbox escape or secret-bearing proof of concept
in a normal public issue.

Use GitHub's private vulnerability reporting flow. Otherwise, email [security@nicdevtv.de](mailto:security@nicdevtv.de).

A useful report includes the Linux distribution, kernel and architecture,
Bubblewrap version, cargo-cage version, a minimal reproduction, and whether
the problem involves `build.rs`, a procedural macro, a compiler helper, or a
child process. Please give us a reasonable chance to investigate before
publishing details.

## Known limits

This release deliberately has no Seccomp, Landlock, resource limits, or
syscall audit log. It does not defend against kernel, Bubblewrap, Cargo, Rustc,
toolchain, or host-policy vulnerabilities. It does not prevent resource DoS,
fork bombs, side channels, every possible secret exposure, or races caused by
another local process changing paths while setup is in progress.

The workspace and selected runtime/toolchain files are readable by design.
Data written to `target` is untrusted, and generated artifacts are not made
safe to execute automatically.
