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
- Keeps the workspace readable, but gives each command a fresh writable target
  run below target/.cargo-cage/runs/. Cargo.lock is still a separate
  persistent writable file.
- Keeps Cargo's normal output and OUT_DIR working inside that isolated run.
- Uses Bubblewrap fd-based mounts and Linux openat2 path resolution for host
  mount sources. If those checks cannot be completed, the build stops.
- Adds a deny-by-default Landlock layer after Bubblewrap setup. Landlock ABI 5
  is required; newer filesystem and scope restrictions are enabled when
  supported by the kernel.
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

This is still the first public alpha, 0.1.0-alpha.1. The Alpha 2 hardening
work is being developed without changing the version until Ubuntu CI is green.
It is deliberately rough around the edges and should not be mistaken for a
production-grade sandbox.

## Requirements and installation

The reference setup is Ubuntu 24.04 x86_64 with unprivileged user namespaces
enabled, a host security policy that permits Bubblewrap, and Bubblewrap
0.12.0 or newer. The kernel must also provide Landlock ABI 5 and openat2.
Other Linux distributions may work; they are not the reference platform.
macOS and Windows are not supported. The Linux runtime also needs Bash at
/bin/bash; cargo-cage uses it only for the small file-descriptor scrubber and
stops if it is missing.

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

## GitHub Actions

For an Ubuntu 24.04 job, the repository also provides a small composite action:

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fetch --locked
      - uses: NicDev-Studios/Cargo-cage@v1
```

The action installs and checks Bubblewrap, installs the pinned cargo-cage
version, runs `cargo-cage doctor`, and defaults to `cargo-cage build --locked`.
Use `command: test`, `command: check`, or `command: doc` for the other supported
Cargo operations. Additional arguments go in `args`:

```yaml
- uses: NicDev-Studios/Cargo-cage@v1
  with:
    command: test
    args: --locked --workspace
```

`@v1` is the Action's Git tag, not the Cargo package version. The action pins
the installed CLI to `0.1.0-alpha.1` by default; set `cargo-cage-version`
explicitly when using another published version. For a supply-chain-sensitive
workflow, pin the Action itself to a full commit SHA instead of the moving
`v1` tag.

Action development can use `install-from-source: true` to exercise the
checked-out CLI instead of the published package. That input is for this
repository's own smoke test, not a shortcut around the normal release process.

The action does not fetch project dependencies automatically. `cargo fetch`
stays an explicit step outside the cage. It currently supports Linux runners
with an Ubuntu/Debian-style package manager; Ubuntu 24.04 is the reference
setup.

## Dependency checks

The repository keeps its dependency graph deliberately small. Dependabot checks
Cargo and GitHub Actions weekly, and the separate RustSec audit workflow scans
`Cargo.lock` when dependency files change and once a week against the current
advisory database. A clean audit means no matching advisory is known at that
point; it is not a claim that the dependencies or the host toolchain are
perfect.

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
target directory must resolve inside the canonical workspace. A fresh run is
used by default:

~~~sh
cargo-cage build
~~~

Artifacts are retained below target/.cargo-cage/runs/ and are intentionally
treated as untrusted. Reusing the existing target tree is an explicit escape
hatch for trusted workspaces:

~~~sh
cargo-cage --reuse-target build
~~~

That mode restores Cargo's usual target path and its incremental cache, but
also restores the cross-build artifact trust problem. It is not the safe
default.

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

For a separate adversarial pass, the repository contains a Rust-only
black-box runner in security/redteam. It generates its own fixtures and checks
that external sentinel files remain unchanged.

## Failure behaviour

Policy and setup failures stop the operation before the real Cargo process is
started. Errors keep the subject, rule, remedy, and low-level setup detail
separate internally, then print all four in a readable message.

When Cargo itself fails, its normal output is left alone. `cargo-cage` adds a
short note about the active policy; it does not pretend to audit every denied
syscall or identify the exact line of a malicious script.

The backend deliberately does a conservative path scan and a real Bubblewrap
preflight before each Cargo process. Large workspaces or old retained target
runs can therefore take a little longer. That cost is part of failing closed;
the test harness also applies per-case timeouts so one broken fixture cannot
hang the whole CI job forever.

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

The Landlock launcher is an implementation detail. It requires a marker file
created by the Bubblewrap setup and rejects filesystem-root policy paths, so an
installed launcher binary cannot accidentally be used as a general-purpose
policy override. It is not a replacement for the outer Bubblewrap boundary.

There is no Seccomp or resource limit, no GUI, no dependency reputation
system, no AI detection, and no macOS/Windows backend here. Landlock itself
does not restrict every operation (for example, some actions involving
already-open file descriptors), and the path setup is not a complete
concurrent-filesystem race proof. Those are separate limits, not decorations
we pretend to have solved.

Read [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) before
using this for anything important.
