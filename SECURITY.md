# Security

`cargo-cage` is experimental software. Version 0.1 is an additional guard
around Cargo builds, not a complete sandbox and not a guarantee that a
malicious Rust build cannot escape.

The intended security boundary and its assumptions are documented in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Supported platform

The supported reference platform is Ubuntu 24.04 x86_64 with Bubblewrap 0.8 or
newer and unprivileged user namespaces enabled. Other Linux distributions may
work, but are not the reference environment. macOS and Windows are not
supported in v0.1.

## Reporting a security issue

Please do not publish a working sandbox escape or other exploit details in a
normal issue.

Use GitHub's private vulnerability
reporting flow. Otherwise, send the report to [security@nicdevtv.de](mailto:security@nicdevtv.de).

Please do not open a public issue with working escape details before there has
been time to investigate and address the report.

Useful reports include the distribution, kernel version, architecture,
Bubblewrap version, cargo-cage version, a minimal reproduction, and whether the
problem comes from a `build.rs`, procedural macro, or child process.
