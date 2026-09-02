use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=network-endpoint.txt");

    if env::var_os("CARGO_FEATURE_HOME_READ").is_some() {
        home_read();
    }
    if env::var_os("CARGO_FEATURE_HOME_SOCKET_READ").is_some() {
        home_socket_read();
    }
    if env::var_os("CARGO_FEATURE_SECRET_ENV").is_some() {
        secret_environment();
    }
    if env::var_os("CARGO_FEATURE_CARGO_CONFIG_READ").is_some() {
        cargo_config_read();
    }
    if env::var_os("CARGO_FEATURE_WORKSPACE_WRITE").is_some() {
        workspace_write();
    }
    if env::var_os("CARGO_FEATURE_NETWORK").is_some() {
        network_access();
    }
    if env::var_os("CARGO_FEATURE_NESTED_WRITE").is_some() {
        nested_write();
    }
    if env::var_os("CARGO_FEATURE_SYMLINK_ESCAPE").is_some() {
        symlink_escape();
    }
    if env::var_os("CARGO_FEATURE_RUNTIME_HARDLINK_ESCAPE").is_some() {
        runtime_hardlink_escape();
    }
    if env::var_os("CARGO_FEATURE_RUNTIME_PATH_READ").is_some() {
        runtime_path_read();
    }
    if env::var_os("CARGO_FEATURE_FD_READ").is_some() {
        inherited_fd_read();
    }
    if env::var_os("CARGO_FEATURE_PARENT_DEATH").is_some() {
        parent_death_probe();
    }
}

fn secret_environment() -> ! {
    let protected = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "CAGE_TEST_ARBITRARY_SECRET",
        "SSH_AUTH_SOCK",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
    ];
    if let Some(name) = protected.iter().find(|name| env::var_os(name).is_some()) {
        panic!("CAGE_POLICY_BYPASSED: protected environment variable {name} was visible");
    }
    panic!("CAGE_POLICY_DENIED: protected environment variables were removed");
}

fn cargo_config_read() -> ! {
    let cargo_home = PathBuf::from(env::var_os("CARGO_HOME").expect("CARGO_HOME is set"));
    let config = cargo_home.join("config.toml");
    match fs::read_to_string(&config) {
        Ok(_) => panic!(
            "CAGE_POLICY_BYPASSED: Cargo configuration was visible at {}",
            config.display()
        ),
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not read Cargo configuration at {}: {error}",
            config.display()
        ),
    }
}

fn home_read() -> ! {
    let home = PathBuf::from(env::var_os("HOME").expect("HOME is set"));
    let secret = home.join(".ssh").join("fixture-secret");
    let unlisted_secret = home.join("unlisted-fixture-secret");
    for secret in [&secret, &unlisted_secret] {
        if let Ok(contents) = fs::read_to_string(secret) {
            panic!(
                "CAGE_POLICY_BYPASSED: read {} ({} bytes)",
                secret.display(),
                contents.len()
            );
        }
    }
    panic!(
        "CAGE_POLICY_DENIED: protected files under {} were not readable",
        home.display()
    );
}

#[cfg(unix)]
fn home_socket_read() -> ! {
    let home = PathBuf::from(env::var_os("HOME").expect("HOME is set"));
    let socket = home.join("fixture-agent.sock");
    match UnixStream::connect(&socket) {
        Ok(_) => panic!("CAGE_POLICY_BYPASSED: connected to {}", socket.display()),
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not connect to {}: {error}",
            socket.display()
        ),
    }
}

#[cfg(not(unix))]
fn home_socket_read() -> ! {
    panic!("CAGE_POLICY_DENIED: Unix socket fixture is unavailable on this platform");
}

fn workspace_write() -> ! {
    let path = manifest_path("build-script-write.txt");
    match fs::write(&path, b"build script wrote outside target") {
        Ok(()) => panic!("CAGE_POLICY_BYPASSED: wrote {}", path.display()),
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not write {}: {error}",
            path.display()
        ),
    }
}

fn network_access() -> ! {
    let endpoint = fs::read_to_string(manifest_path("network-endpoint.txt"))
        .expect("network endpoint fixture is present");
    let endpoint = endpoint.trim();
    match endpoint
        .parse::<SocketAddr>()
        .ok()
        .and_then(|address| TcpStream::connect(address).ok())
    {
        Some(_) => panic!("CAGE_POLICY_BYPASSED: connected to {endpoint}"),
        None => panic!("CAGE_POLICY_DENIED: could not connect to {endpoint}"),
    }
}

fn nested_write() -> ! {
    let path = manifest_path("nested-write.txt");
    let child = Command::new("sh")
        .arg("-c")
        .arg("printf nested > \"$1\"")
        .arg("cargo-cage-test")
        .arg(&path)
        .status()
        .expect("could not start nested child process");
    if child.success() {
        panic!(
            "CAGE_POLICY_BYPASSED: nested child wrote {}",
            path.display()
        );
    }
    panic!(
        "CAGE_POLICY_DENIED: nested child could not write {}",
        path.display()
    );
}

fn symlink_escape() -> ! {
    let path = manifest_path("target/escape-link");
    match fs::write(&path, b"symlink escape") {
        Ok(()) => panic!("CAGE_POLICY_BYPASSED: wrote through {}", path.display()),
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not write through {}: {error}",
            path.display()
        ),
    }
}

fn runtime_hardlink_escape() -> ! {
    let source = manifest_path("Cargo.toml");
    let target_dir = PathBuf::from(env::var_os("CARGO_TARGET_DIR").expect("CARGO_TARGET_DIR is set"));
    let alias = target_dir.join("runtime-hardlink-escape");
    match fs::hard_link(&source, &alias) {
        Ok(()) => match fs::write(&alias, b"runtime hardlink escape") {
            Ok(()) => panic!(
                "CAGE_POLICY_BYPASSED: wrote through runtime hardlink {} to {}",
                alias.display(),
                source.display()
            ),
            Err(error) => panic!(
                "CAGE_POLICY_DENIED: runtime hardlink write to {} failed: {error}",
                alias.display()
            ),
        },
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not create runtime hardlink {}: {error}",
            alias.display()
        ),
    }
}

fn runtime_path_read() -> ! {
    for path in ["/sys", "/boot", "/var/lib", "/oldroot"] {
        if fs::metadata(path).is_ok() {
            panic!("CAGE_POLICY_BYPASSED: host runtime path {path} was visible");
        }
    }
    panic!("CAGE_POLICY_DENIED: host runtime paths were not visible");
}

fn inherited_fd_read() -> ! {
    let descriptor = "/proc/self/fd/9";
    let secret = manifest_path("inherited-fd-secret");
    if fs::canonicalize(descriptor).is_ok_and(|path| path == secret) {
        panic!(
            "CAGE_POLICY_BYPASSED: inherited file descriptor 9 still pointed at the fixture secret"
        );
    }
    panic!(
        "CAGE_POLICY_DENIED: inherited file descriptor 9 did not expose the fixture secret"
    );
}

fn parent_death_probe() {
    let output_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let started = output_dir.join("parent-death-started");
    let finished = output_dir.join("parent-death-finished");
    fs::write(&started, b"started").expect("parent-death start marker is writable");
    let child = Command::new("sh")
        .arg("-c")
        .arg("sleep 2; printf finished > \"$1\"")
        .arg("cargo-cage-parent-death")
        .arg(&finished)
        .status()
        .expect("could not start parent-death child");
    if !child.success() {
        panic!("CAGE_POLICY_DENIED: parent-death child did not complete");
    }
}

fn manifest_path(path: &str) -> PathBuf {
    PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join(path)
}
