# cargo-cage

[![CI](https://github.com/NicDev-Studios/Cargo-cage/actions/workflows/ci.yml/badge.svg)](https://github.com/NicDev-Studios/Cargo-cage/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/NicDev-Studios/Cargo-cage?sort=semver)](https://github.com/NicDev-Studios/Cargo-cage/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/cargo-cage.svg)](https://crates.io/crates/cargo-cage)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Lines of code](https://sloc.xyz/github/NicDev-Studios/Cargo-cage/?category=code)](https://sloc.xyz/github/NicDev-Studios/Cargo-cage)

`cargo-cage` puts a Linux Bubblewrap boundary around Cargo builds.
`build.rs`, procedural macros, compiler helpers, and child processes are all
code that can run during a build. The cage gives them less room to do damage.

This is experimental security tooling, not a magic force field. It is useful
defence in depth for local builds, but it is not a replacement for a VM,
dedicated build service, or a careful review of the code you build.

## What the cage does

- Blocks the network by default and forces Cargo into offline mode.
- Starts with a small read-only Linux runtime instead of mounting the host
  root wholesale.
- Keeps the workspace readable, but allows persistent writes only to the
  canonical `target` directory and `Cargo.lock`.
- Keeps Cargo's normal output and `OUT_DIR` working under `target`.
- Gives `/tmp`, `/var/tmp`, and `/run` private throwaway filesystems.
- Starts Cargo with an empty environment and a reviewed Cargo/Rust/locale
  allowlist. Host secrets, credentials, agent sockets, `HOME`, and arbitrary
  project variables are not inherited.
- Keeps normal stdin/stdout/stderr, but scrubs extra inherited file
  descriptors before Cargo starts.
- Uses a private `CARGO_HOME`. Only checked `registry` and `git` caches are
  mounted read-only. Cargo user configuration and credentials are deliberately
  left outside the cage.
- Checks workspace, target, lockfile, cache, hidden, and toolchain paths before
  mounting them. Symlinks, traversal, special files, nested mountpoints, and
  external hardlink aliases fail closed.
- Keeps hardlinks Cargo creates internally in `target` working, while rejecting
  aliases that point outside the tree being validated.
- Refuses to run when Bubblewrap is missing, too old, or unable to create the
  requested namespaces. There is no quiet fallback to a normal host build.
- Requires Bubblewrap `0.12.0+` because older versions are outside the
  supported security baseline. See the upstream
  [Bubblewrap advisory](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx).

The same policy is used for `build`, `check`, `test`, and `doc`. `doctor`
checks the setup without creating or changing project files.

This is the first public alpha, `0.1.0-alpha.1`. It is deliberately rough
around the edges and should not be mistaken for a production-grade sandbox.

## Requirements and installation

The reference setup is Ubuntu 24.04 x86_64 with unprivileged user namespaces
enabled, a host security policy that permits Bubblewrap, and Bubblewrap
`0.12.0` or newer. Other Linux distributions may work; they are not the
reference platform. macOS and Windows are not supported. The Linux runtime
also needs Bash at `/bin/bash`; cargo-cage uses it only for the small
file-descriptor scrubber and stops if it is missing.

```sh
sudo apt-get install bubblewrap
bwrap --version  # must report 0.12.0 or newer
cargo install --path cargo-cage --locked
```

If your distribution ships an older Bubblewrap, install its security update or
a checksum-verified newer build. `cargo-cage` stops instead of running Cargo
unsandboxed.

Once the alpha is published, install it from crates.io with:

```sh
cargo install cargo-cage --locked --version 0.1.0-alpha.1
```

The public crates are named consistently on crates.io:

- `cargo-cage` — the CLI
- `cargo-cage-core` — platform-neutral policy and backend types
- `cargo-cage-cargo` — Cargo integration
- `cargo-cage-linux` — the Bubblewrap backend

`cage-testkit` contains intentionally hostile fixtures and stays private to
the workspace.

## Offline preparation

The cage does not fetch dependencies for you. Prepare dependencies as a
separate, deliberate step, then run the build offline:

```sh
cargo fetch
cargo-cage build
```

If a crate is not already cached, Cargo keeps its normal offline error and
`cargo-cage` tells you to run `cargo fetch` outside the cage.

## Usage

Use the direct executable when the sandbox matters:

```sh
cargo-cage build
cargo-cage check
cargo-cage test
cargo-cage doc
cargo-cage doctor
cargo-cage doctor --verbose
```

Cargo arguments keep their normal Cargo meaning. `--workspace`, `--package`,
`--features`, `--release`, `--target`, `--manifest-path`, and `--target-dir`
work as normal, subject to the path policy. Relative manifest and target paths
are resolved safely when the sandbox needs a narrower working directory. A
target directory must resolve inside the canonical workspace.

### Why not rely on `cargo cage`?

`cargo cage build` may work when Cargo finds `cargo-cage` and no alias named
`cage` gets in the way. It is not the security-canonical spelling, though.
Cargo expands aliases before it launches external `cargo-*` commands. A
repository can contain this in `.cargo/config.toml`:

```toml
[alias]
cage = ["run", "--"]
```

In that case Cargo never starts `cargo-cage`; it runs the alias instead. There
is no way for a program to detect a bypass after it was never launched. Use
`cargo-cage` directly for an untrusted workspace. Cargo is tracking this
behaviour in [issue #10049](https://github.com/rust-lang/cargo/issues/10049).

`run`, `publish`, `fmt`, arbitrary Cargo subcommands, automatic fetching, and
network opt-in are intentionally out of scope for this release.

## Before and after

The test kit includes a deliberately rude `build.rs`. Without the cage it can
write into the source tree:

```sh
cd cage-testkit/fixtures/malicious-build-script
cargo build --features workspace-write || true
test -e build-script-write.txt
```

With the cage, the source tree is read-only. Cargo keeps its own diagnostic,
and `cargo-cage` adds the policy context:

```sh
rm -f build-script-write.txt
cargo-cage build --features workspace-write || true
test ! -e build-script-write.txt
```

## Failure behaviour

Policy and setup failures stop the operation before the real Cargo process is
started. Errors name the path or variable involved, the rule that stopped the
operation, and what to do next.

When Cargo itself fails, its normal output is left alone. `cargo-cage` adds a
short note about the active policy; it does not pretend to audit every denied
syscall or identify the exact line of a malicious script.

## Limits

This project draws a boundary around a build; it does not make the build
trustworthy. It does not protect against kernel, Bubblewrap, Cargo, Rustc, or
toolchain vulnerabilities. It does not solve resource exhaustion, fork
bombs, side channels, or every secret that might exist in a readable project,
runtime directory, compiler flag, or environment value.

The path checks use safe Rust and the standard library. They are deliberately
fail-closed, but they are not atomic against another local process changing
the filesystem during setup. Files written under `target` are not trusted
automatically, and generated binaries are not made safe to execute.

There is no Seccomp or Landlock policy, no resource limit, no GUI, no dependency
reputation system, no AI detection, and no macOS/Windows backend here. Those
are separate problems, not decorations for this release.

Read [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) before
using this for anything important.
