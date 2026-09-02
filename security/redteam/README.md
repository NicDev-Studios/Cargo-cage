# cargo-cage red team

This is a black-box attacker harness for cargo-cage. It is deliberately not a
normal workspace test and does not use cage-testkit or cargo-cage internals.
It creates disposable Cargo projects, runs hostile build scripts, and checks
external sentinel files after every attempt.

Run it on the supported Ubuntu runner after building the current CLI:

~~~text
cargo build --package cargo-cage --locked
cargo run --manifest-path security/redteam/Cargo.toml --locked -- \
  --cargo-cage target/debug/cargo-cage \
  --iterations 64
~~~

The harness only uses local listeners and temporary files. It never sends
traffic to an external service and it does not print secret-bearing process
output. A missing attacker tool is an error, not a skipped pass.

The harness can find ordinary policy bugs, but a green run is not a proof
against kernel, Bubblewrap, toolchain, or concurrent-filesystem attacks.
