# cargo-cage

[![CI](https://github.com/NicDev-Studios/Cargo-cage/actions/workflows/ci.yml/badge.svg)](https://github.com/NicDev-Studios/Cargo-cage/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/NicDev-Studios/Cargo-cage?sort=semver)](https://github.com/NicDev-Studios/Cargo-cage/releases/latest)
[![Crates.io](https://img.shields.io/crates/v/cargo-cage.svg)](https://crates.io/crates/cargo-cage)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Lines of code](https://sloc.xyz/github/NicDev-Studios/Cargo-cage/?category=code)](https://github.com/NicDev-Studios/Cargo-cage)

`cargo-cage` is an experimental Linux wrapper for Cargo builds. It runs
Cargo, `build.rs`, procedural macros, compiler helpers, and their child
processes inside a Bubblewrap sandbox.

This is a practical extra boundary around a local build. It is not a complete
security guarantee and it is not a replacement for a hardened build service.

## What v0.3 does

- Denies network access by default and forces Cargo offline mode.
- Mounts the host filesystem read-only.
- Allows persistent writes only to the canonical workspace `target` directory
  and the workspace `Cargo.lock`.
- Keeps normal Cargo output and `OUT_DIR` working under `target`.
- Provides private, throwaway `/tmp` and `/run` filesystems.
- Hides common sensitive paths such as `~/.ssh`, `~/.aws`, `~/.config`, and
  Cargo credentials.
- Removes common credential and agent environment variables. A policy removal
  always wins over an environment value supplied to the child.
- Uses a private `CARGO_HOME`. Only validated `registry` and `git` caches are
  mounted read-only. Cargo `config` and `config.toml` are intentionally not
  mounted because they may contain credentials or credential providers.
- Rejects symlinked or special-file Cargo cache entries, and cache sources that
  overlap writable, hidden, or private paths, before starting Cargo.
- Refuses to run if Bubblewrap is missing, too old, or cannot activate the
  requested namespaces. There is no unsandboxed fallback.
- Supports `build`, `check`, `test`, and `doc` through the same sandbox policy.
- Provides `cargo cage doctor` to check the current project and host without
  creating or changing project files.

## Requirements and installation

The public crates use the `cargo-cage` prefix so their names stay together on
crates.io:

- `cargo-cage` — the CLI
- `cargo-cage-core` — platform-neutral policy and backend types
- `cargo-cage-cargo` — Cargo integration
- `cargo-cage-linux` — Bubblewrap backend for Linux

`cage-testkit` contains deliberately malicious test fixtures and remains a
workspace-private crate.

The reference environment is Ubuntu 24.04 x86_64 with unprivileged user
namespaces enabled and Bubblewrap 0.8 or newer.

The host security policy must also allow Bubblewrap to create the namespaces
it needs. On Ubuntu 24.04, AppArmor can deny this even when the kernel setting
is enabled. The CI workflow prepares its ephemeral runner explicitly;
production hosts should use a narrow host-policy rule rather than weakening
the policy globally.

```sh
sudo apt-get install bubblewrap
cargo install --path cargo-cage --locked
```

Once a crates.io release is available, the CLI can be installed with:

```sh
cargo install cargo-cage --locked --version 0.3.0
```

The repository's crates.io workflow is tag-driven and protected by a GitHub
environment approval. Normal pushes and pull requests do not publish packages.

Cargo is forced into offline mode. Fetch dependencies as a separate,
intentional step before using the cage:

```sh
cargo fetch
cargo cage build
```

`cargo-cage` never fetches automatically and never opens the sandbox network
for that purpose. If a cache is missing, Cargo keeps its native offline error
and `cargo-cage` explains that `cargo fetch` must be run separately.

## Usage

Both forms are supported:

```sh
cargo cage build
cargo cage check
cargo cage test
cargo cage doc
cargo cage doctor
cargo-cage build
cargo-cage doctor --verbose
```

Cargo arguments are passed through unchanged. `--target-dir` is accepted only
when it resolves inside the canonical workspace directory. The same applies
to `CARGO_TARGET_DIR`. `run`, `publish`, `fmt`, and arbitrary Cargo commands
are intentionally not accepted.

`doctor` prints compact `OK`, `WARN`, and `FAIL` lines. A missing target
directory or cache is not a policy failure; the output explains that Cargo may
need to create it or that dependencies should be prepared with `cargo fetch`.
Unsafe paths and a failed Bubblewrap preflight are failures.

## Before and after

The test kit contains a deliberately hostile `build.rs`. Without the cage it
can write into the source tree:

```sh
cd cage-testkit/fixtures/malicious-build-script
CAGE_TEST_ACTION=workspace-write \
CAGE_TEST_WRITE_PATH="$PWD/build-script-write.txt" \
cargo build
```

With the cage, the source tree is read-only. Cargo keeps its native diagnostic
and `cargo-cage` adds the active policy context:

```sh
rm -f build-script-write.txt
CAGE_TEST_ACTION=workspace-write \
CAGE_TEST_WRITE_PATH="$PWD/build-script-write.txt" \
cargo cage build
test ! -e build-script-write.txt
```

## Failure behavior

Policy and setup failures stop the build before an unsafe Cargo process is
started. The error names the affected path or variable, the rule that was
violated, and a concrete remedy.

When Cargo itself fails, its normal output is preserved. The additional
`cargo-cage` message describes the active boundaries, but it does not claim to
audit every denied syscall.

## Limits

The threat model is deliberately narrow. The tool does not protect against
kernel, Bubblewrap, Cargo, Rustc, or toolchain vulnerabilities. It does not
solve resource exhaustion, fork bombs, side channels, or every possible secret
in the environment and filesystem. Most of the host filesystem remains
readable.

The path checks are `std`-only and are not race-free against another local
process changing the filesystem at the same time. Hard-link aliases and
future filesystem or kernel bugs are outside this release's guarantee.

Artifacts written to `target` are not trusted automatically, and the tool does
not make their later execution safe. There is no seccomp profile, GUI,
dependency reputation system, AI detection, automatic fetch, or macOS/Windows
backend in this release.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) before
relying on this for real build isolation.
