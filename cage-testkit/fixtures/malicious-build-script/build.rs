use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CAGE_TEST_ACTION");
    println!("cargo:rerun-if-env-changed=CAGE_TEST_WRITE_PATH");
    println!("cargo:rerun-if-env-changed=CAGE_TEST_ENDPOINT");
    println!("cargo:rerun-if-env-changed=CAGE_TEST_SYMLINK");

    match env::var("CAGE_TEST_ACTION").as_deref() {
        Ok("home-read") => home_read(),
        Ok("secret-env") => secret_environment(),
        Ok("cargo-config-read") => cargo_config_read(),
        Ok("workspace-write") => workspace_write(),
        Ok("network") => network_access(),
        Ok("nested-write") => nested_write(),
        Ok("symlink-escape") => symlink_escape(),
        Ok(action) => panic!("unknown CAGE_TEST_ACTION={action}"),
        Err(_) => {}
    }
}

fn secret_environment() -> ! {
    let protected = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "CAGE_TEST_TOKEN",
        "CAGE_TEST_PASSWORD",
        "SSH_AUTH_SOCK",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
    ];
    if let Some(name) = protected
        .iter()
        .find(|name| env::var_os(name).is_some())
    {
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
    match fs::read_to_string(&secret) {
        Ok(_) => panic!("CAGE_POLICY_BYPASSED: read {}", secret.display()),
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not read {}: {error}",
            secret.display()
        ),
    }
}

fn workspace_write() -> ! {
    let path = test_path("CAGE_TEST_WRITE_PATH", "build-script-write.txt");
    match fs::write(&path, b"build script wrote outside target") {
        Ok(()) => panic!("CAGE_POLICY_BYPASSED: wrote {}", path.display()),
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not write {}: {error}",
            path.display()
        ),
    }
}

fn network_access() -> ! {
    let endpoint = env::var("CAGE_TEST_ENDPOINT").expect("CAGE_TEST_ENDPOINT is set");
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
    let path = test_path("CAGE_TEST_WRITE_PATH", "nested-write.txt");
    let child = Command::new("sh")
        .arg("-c")
        .arg("printf nested > \"$CAGE_TEST_WRITE_PATH\"")
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
    let path = test_path("CAGE_TEST_SYMLINK", "target/escape-link");
    match fs::write(&path, b"symlink escape") {
        Ok(()) => panic!("CAGE_POLICY_BYPASSED: wrote through {}", path.display()),
        Err(error) => panic!(
            "CAGE_POLICY_DENIED: could not write through {}: {error}",
            path.display()
        ),
    }
}

fn test_path(name: &str, fallback: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join(fallback))
}
