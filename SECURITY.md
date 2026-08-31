# Security

`cargo-cage` is experimental software. Version 0.2 is an additional guard
around local Cargo builds, not a complete sandbox and not a promise that a
malicious build cannot escape.

The intended boundary, trust assumptions, and residual risk are documented in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Supported platform

The supported reference platform is Ubuntu 24.04 x86_64 with Bubblewrap 0.8 or
newer, unprivileged user namespaces enabled, and a host AppArmor policy that
allows Bubblewrap to perform its setup. Other Linux distributions may work,
but are not the reference environment. macOS and Windows are not supported.

## Security properties

The Linux backend uses a read-only host filesystem, private temporary and
runtime filesystems, a new network namespace, dropped capabilities, and a
parent-death guard. Persistent writes are limited to the canonical build
target and workspace lockfile.

Sensitive environment variables and selected home paths are removed or hidden.
Cargo runs with a private `CARGO_HOME`; only validated registry and Git caches
are exposed read-only. User Cargo configuration is not mounted because it may
contain credentials.

These controls are defense-in-depth. They depend on the Linux kernel,
Bubblewrap, Cargo, Rustc, the host security policy, and the selected toolchain
behaving correctly.

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
