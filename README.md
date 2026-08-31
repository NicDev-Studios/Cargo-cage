# cargo-cage

`cargo-cage` is an experimental Linux tool that runs Cargo builds inside a
Bubblewrap sandbox. That includes `build.rs`, procedural macros, compiler
helpers, and child processes started by them.

This is a small extra boundary around a build. It is not a complete security
guarantee, and it is not a replacement for a container or a hardened build
service.

## What v0.1 does

- Blocks network access by default. There is no network opt-in in the CLI.
- Mounts the host filesystem read-only.
- Allows persistent writes only to the workspace `target` directory and the
  workspace `Cargo.lock`.
- Keeps `OUT_DIR` and normal Cargo build output working under `target`.
- Provides private, throwaway `/tmp` and `/run` filesystems. `TMPDIR` is set
  to `/tmp` inside the sandbox.
- Hides common sensitive paths such as `~/.ssh`, `~/.aws`, `~/.config`, and
  Cargo credentials.
- Removes common credential and agent environment variables.
- Refuses to run if Bubblewrap is missing, too old, or cannot activate the
  requested namespaces. There is no unsandboxed fallback.

## Requirements and installation

The reference environment is Ubuntu 24.04 x86_64 with unprivileged user
namespaces enabled and Bubblewrap 0.8 or newer.

The host security policy must also allow `/usr/bin/bwrap` to create the
unprivileged namespace it needs. On Ubuntu 24.04, AppArmor can deny this even
when the kernel setting is enabled. The CI workflow prepares its ephemeral
runner explicitly; production hosts should use a narrow AppArmor rule rather
than weakening the policy globally.

```sh
sudo apt-get install bubblewrap
cargo install --path cargo-cage
```

Cargo is forced into offline mode. Fetch dependencies as a separate,
intentional step before using the cage:

```sh
cargo fetch
cargo cage build
```

Missing registry or Git data is reported by Cargo. `cargo-cage` never fetches
it automatically and never opens the sandbox network for that purpose.

## Usage

Both forms are supported:

```sh
cargo cage build
cargo-cage build
```

Build arguments are passed through to Cargo. `--target-dir` is accepted only
when it resolves inside the canonical workspace directory. The same applies
to `CARGO_TARGET_DIR`.

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

## Limits

The threat model is deliberately narrow. The tool does not protect against
kernel, Bubblewrap, Cargo, Rustc, or toolchain vulnerabilities. It does not
solve resource exhaustion, fork bombs, side channels, or every possible secret
in the environment and filesystem. Most of the host filesystem remains
readable.

Artifacts written to `target` are not trusted automatically, and the tool does
not make their later execution safe. There is no GUI, dependency reputation
system, AI detection, automatic fetch, or macOS/Windows backend in v0.1.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) before
relying on this for real build isolation.
