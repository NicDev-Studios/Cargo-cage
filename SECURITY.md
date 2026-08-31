# Security

`cargo-cage` is experimental software. The current 0.3 package is an
additional guard around local Cargo operations; the v0.4 hardening work is not
released yet. This is not a complete sandbox and is not a promise that a
malicious build cannot escape.

The intended boundary, trust assumptions, and residual risk are documented in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Supported platform

The supported reference platform is Ubuntu 24.04 x86_64 with Bubblewrap 0.12.0 or
newer, unprivileged user namespaces enabled, and a host AppArmor policy that
allows Bubblewrap to perform its setup. Other Linux distributions may work,
but are not the reference environment. macOS and Windows are not supported.
Bubblewrap versions below 0.12.0 are rejected because of the upstream
[GHSA-pxhw-h44j-8pfx setup vulnerability](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx).

## Security properties

The Linux backend uses read-only runtime/project mounts, private temporary and
runtime filesystems (`/tmp`, `/var/tmp`, and `/run`), a new network namespace,
dropped capabilities, and a parent-death guard. Persistent writes are limited
to the canonical build target and workspace lockfile.

The child starts with an empty environment. Only a fixed, reviewed set of
Cargo/Rust, compiler, locale, and terminal variables is copied. `HOME` is
private, and `PATH` is rebuilt from the selected toolchain and existing helper
directories. Credentials, agent variables, `CARGO_HOME`, `RUSTUP_HOME`, and
arbitrary project variables are not inherited.

Cargo runs with a private `CARGO_HOME`; only validated registry and Git caches
are exposed read-only. Cache roots must be real, absolute directories and
their trees may contain only regular files and directories. User Cargo
configuration is deliberately not mounted because it may contain credentials.
That refers to user/global Cargo configuration; a project-local config inside
the read-only workspace remains visible as project input.
`build`, `check`, `test`, and `doc` use the same policy; `test` binaries,
procedural macros, compiler helpers, linkers, and their child processes remain
inside the sandbox.

`cargo cage doctor` performs the same host, workspace, path, cache, and
Bubblewrap preflight checks without creating a target directory or lockfile.

These controls are defense-in-depth. They depend on the Linux kernel,
Bubblewrap, Cargo, Rustc, the host security policy, and the selected toolchain
behaving correctly. There is no Seccomp, Landlock, resource limit, or
race-free path guarantee in this release. `Cargo.lock` hard-links are rejected,
but hard-link aliases inside Cargo's target tree remain a known limitation.
Selected system runtime and project paths can still be read, so this is not
complete secret scrubbing. Artifacts written to `target` are not made safe to
execute automatically.

## Reporting a security issue

Please do not publish a working sandbox escape or other exploit details in a
normal issue.

Use GitHub's private vulnerability reporting flow when it is available for the
repository. Otherwise, send the report to
[security@nicdevtv.de](mailto:security@nicdevtv.de).

Please do not open a public issue with working escape details before there has
been time to investigate and address the report.

Useful reports include the distribution, kernel version, architecture,
Bubblewrap version, cargo-cage version, a minimal reproduction, and whether
the problem comes from a `build.rs`, procedural macro, or child process.
