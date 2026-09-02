#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("cargo-cage redteam: Linux is required");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args_os()
        .any(|arg| arg == std::ffi::OsStr::new("--help") || arg == std::ffi::OsStr::new("-h"))
    {
        redteam::print_help();
        return;
    }
    if let Err(error) = redteam::run() {
        eprintln!("cargo-cage redteam: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod redteam {
    use std::env;
    use std::fs;
    use std::io;
    use std::net::{TcpListener, UdpSocket};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    const BUILD_HEADER: &str = r#"
use std::env;
use std::fs;
use std::net::{TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bypass(message: &str) -> ! {
    panic!("CAGE_POLICY_BYPASSED: {message}");
}

fn denied(message: &str) -> ! {
    panic!("CAGE_POLICY_DENIED: {message}");
}

fn manifest_path(name: &str) -> PathBuf {
    PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory")).join(name)
}
"#;

    #[derive(Debug)]
    struct Config {
        cargo_cage: PathBuf,
        iterations: u32,
        keep: bool,
    }

    #[derive(Debug)]
    struct Case {
        name: String,
        root: PathBuf,
        workspace: PathBuf,
        home: PathBuf,
        cargo_home: PathBuf,
        external: PathBuf,
        sentinel: PathBuf,
        cargo_cage: PathBuf,
        keep: bool,
        finished: bool,
    }

    impl Case {
        fn new(config: &Config, name: &str) -> io::Result<Self> {
            let root = env::temp_dir().join(format!(
                "cargo-cage-redteam-{}-{}-{}",
                std::process::id(),
                timestamp(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let workspace = root.join("workspace");
            let home = root.join("home");
            let cargo_home = root.join("cargo-home");
            let external = root.join("external");
            fs::create_dir_all(workspace.join("src"))?;
            fs::create_dir_all(&home)?;
            fs::create_dir_all(&cargo_home)?;
            fs::create_dir_all(&external)?;
            let sentinel = external.join("sentinel");
            fs::write(&sentinel, b"redteam-sentinel-before")?;
            fs::write(
                workspace.join("Cargo.toml"),
                "[package]\nname = \"cargo-cage-redteam-case\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n",
            )?;
            fs::write(workspace.join("src/main.rs"), "fn main() {}\n")?;
            Ok(Self {
                name: name.to_owned(),
                root,
                workspace,
                home,
                cargo_home,
                external,
                sentinel,
                cargo_cage: config.cargo_cage.clone(),
                keep: config.keep,
                finished: false,
            })
        }

        fn write_build_script(&self, body: &str) -> io::Result<()> {
            fs::write(
                self.workspace.join("build.rs"),
                format!("{BUILD_HEADER}\nfn main() {{\n{body}\n}}\n"),
            )
        }

        fn base_command(&self) -> Command {
            let mut command = Command::new(&self.cargo_cage);
            command
                .current_dir(&self.workspace)
                .args([
                    "build",
                    "--manifest-path",
                    self.workspace.join("Cargo.toml").to_str().unwrap(),
                ])
                .env("HOME", &self.home)
                .env("CARGO_HOME", &self.cargo_home)
                .env_remove("CARGO_TARGET_DIR")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_CAGE_BWRAP");
            if let Some(rustup_home) = env::var_os("RUSTUP_HOME") {
                command.env("RUSTUP_HOME", rustup_home);
            }
            command
        }

        fn run(&self) -> io::Result<Output> {
            self.base_command().output()
        }

        fn run_reuse(&self) -> io::Result<Output> {
            self.base_reuse_command().output()
        }

        fn base_reuse_command(&self) -> Command {
            let mut command = Command::new(&self.cargo_cage);
            command
                .current_dir(&self.workspace)
                .args([
                    "--reuse-target",
                    "build",
                    "--manifest-path",
                    self.workspace.join("Cargo.toml").to_str().unwrap(),
                ])
                .env("HOME", &self.home)
                .env("CARGO_HOME", &self.cargo_home)
                .env_remove("CARGO_TARGET_DIR")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_CAGE_BWRAP");
            if let Some(rustup_home) = env::var_os("RUSTUP_HOME") {
                command.env("RUSTUP_HOME", rustup_home);
            }
            command
        }

        fn run_with_fd(&self, secret: &Path) -> io::Result<Output> {
            let binary = &self.cargo_cage;
            Command::new("/bin/sh")
                .current_dir(&self.workspace)
                .args([
                    "-c",
                    "exec 9<\"$1\"; shift; exec \"$@\"",
                    "cargo-cage-redteam-fd",
                    secret.to_str().unwrap(),
                    binary.to_str().unwrap(),
                    "build",
                    "--manifest-path",
                    self.workspace.join("Cargo.toml").to_str().unwrap(),
                ])
                .env("HOME", &self.home)
                .env("CARGO_HOME", &self.cargo_home)
                .env_remove("CARGO_TARGET_DIR")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_CAGE_BWRAP")
                .output()
        }

        fn sentinel(&self) -> io::Result<Vec<u8>> {
            fs::read(&self.sentinel)
        }

        fn finish(mut self) {
            self.finished = true;
            if self.keep {
                eprintln!(
                    "cargo-cage redteam: kept case {} at {}",
                    self.name,
                    self.root.display()
                );
            } else {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            if self.keep {
                eprintln!(
                    "cargo-cage redteam: kept failed case {} at {}",
                    self.name,
                    self.root.display()
                );
            } else {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    pub fn run() -> Result<(), String> {
        let config = parse_config()?;
        let cargo_cage = fs::canonicalize(&config.cargo_cage).map_err(|error| {
            format!(
                "cannot resolve cargo-cage executable {}: {error}",
                config.cargo_cage.display()
            )
        })?;
        if !cargo_cage.is_file() {
            return Err(format!(
                "cargo-cage path is not a regular file: {}",
                cargo_cage.display()
            ));
        }
        let config = Config {
            cargo_cage,
            ..config
        };
        require_tools(&[
            "/usr/bin/unshare",
            "/usr/bin/nsenter",
            "/usr/bin/mount",
            "/usr/bin/mknod",
            "/usr/bin/python3",
        ])?;

        normal_build(&config)?;
        attack_environment(&config)?;
        attack_home_files(&config)?;
        attack_cargo_config(&config)?;
        attack_lockfile_symlink(&config)?;
        attack_lockfile_hardlink(&config)?;
        attack_cache_symlink(&config)?;
        attack_cache_nested_symlink(&config)?;
        attack_cache_special_file(&config)?;
        attack_workspace_write(&config)?;
        attack_external_write(&config)?;
        attack_target_write(&config)?;
        attack_network(&config)?;
        attack_unix_socket(&config)?;
        attack_abstract_unix_socket(&config)?;
        attack_file_descriptor(&config)?;
        attack_runtime_paths(&config)?;
        attack_namespace_tools(&config)?;
        attack_child_process(&config)?;
        attack_target_hardlink(&config)?;
        attack_target_symlink(&config)?;
        attack_target_freshness(&config)?;
        attack_path_swap(&config)?;
        eprintln!("cargo-cage redteam: all black-box attacks were denied");
        Ok(())
    }

    pub fn print_help() {
        println!("usage: cargo-cage-redteam --cargo-cage PATH [--iterations N] [--keep]");
    }

    fn parse_config() -> Result<Config, String> {
        let mut args = env::args_os().skip(1);
        let mut cargo_cage = None;
        let mut iterations = 32;
        let mut keep = false;
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--cargo-cage") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--cargo-cage needs a path".to_owned())?;
                    cargo_cage = Some(PathBuf::from(value));
                }
                Some("--iterations") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--iterations needs a number".to_owned())?;
                    iterations = value
                        .to_string_lossy()
                        .parse()
                        .map_err(|_| "--iterations must be a positive number".to_owned())?;
                    if iterations == 0 {
                        return Err("--iterations must be positive".to_owned());
                    }
                }
                Some("--keep") => keep = true,
                Some("--help") | Some("-h") => return Err("help was already handled".to_owned()),
                Some(other) => return Err(format!("unknown option {other}")),
                None => return Err("arguments must be valid UTF-8".to_owned()),
            }
        }
        Ok(Config {
            cargo_cage: cargo_cage.ok_or_else(|| "--cargo-cage is required".to_owned())?,
            iterations,
            keep,
        })
    }

    fn require_tools(tools: &[&str]) -> Result<(), String> {
        for tool in tools {
            let executable = fs::metadata(tool)
                .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
            if !executable {
                return Err(format!(
                    "red-team probe is not runnable: required attacker tool is missing: {tool}"
                ));
            }
        }
        Ok(())
    }

    fn normal_build(config: &Config) -> Result<(), String> {
        let case = Case::new(config, "normal-build").map_err(io_text)?;
        case.write_build_script(
            r#"
let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
fs::write(out_dir.join("redteam-normal-build"), b"ok").expect("write OUT_DIR");
"#,
        )
        .map_err(io_text)?;
        let output = case.run().map_err(io_text)?;
        if !output.status.success() {
            return fail_output(&case, "normal build", &output);
        }
        if !find_file(&case.workspace.join("target"), "redteam-normal-build") {
            return fail_case(&case, "normal build did not produce its OUT_DIR artifact");
        }
        if !find_file(
            &case.workspace.join("target/.cargo-cage/runs"),
            "redteam-normal-build",
        ) {
            return fail_case(&case, "normal build did not use an isolated target run");
        }
        case.finish();
        Ok(())
    }

    fn attack_environment(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "environment",
            r#"
for name in [
    "AWS_SECRET_ACCESS_KEY",
    "SERVICE_TOKEN",
    "CAGE_RANDOM_PASSWORD",
    "CAGE_UNLISTED_SECRET",
    "SSH_AUTH_SOCK",
    "DBUS_SESSION_BUS_ADDRESS",
    "CARGO_REGISTRIES_CRATES_IO_TOKEN",
] {
    if env::var_os(name).is_some() {
        bypass("a protected environment variable was visible");
    }
}
denied("protected environment variables were not visible");
"#,
        )?;
        let mut command = case.base_command();
        for (key, value) in [
            ("AWS_SECRET_ACCESS_KEY", "redteam-secret"),
            ("SERVICE_TOKEN", "redteam-token"),
            ("CAGE_RANDOM_PASSWORD", "redteam-password"),
            ("CAGE_UNLISTED_SECRET", "redteam-unlisted-secret"),
            ("SSH_AUTH_SOCK", "/tmp/redteam-agent"),
            ("DBUS_SESSION_BUS_ADDRESS", "redteam-dbus"),
            ("CARGO_REGISTRIES_CRATES_IO_TOKEN", "redteam-registry-token"),
        ] {
            command.env(key, value);
        }
        let output = command.output().map_err(io_text)?;
        let text = output_text(&output);
        for secret in [
            "redteam-secret",
            "redteam-token",
            "redteam-password",
            "redteam-unlisted-secret",
            "redteam-dbus",
            "redteam-registry-token",
        ] {
            if text.contains(secret) {
                return fail_case(&case, "environment attack leaked a secret value in output");
            }
        }
        if !has_policy_context(&text) {
            return fail_case(
                &case,
                "environment attack failed without a recognizable sandbox policy diagnostic",
            );
        }
        if output.status.success() || text.contains("CAGE_POLICY_BYPASSED") {
            return fail_output(&case, "environment attack", &output);
        }
        case.finish();
        Ok(())
    }

    fn attack_home_files(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "home-files",
            r#"
let home = PathBuf::from(env::var_os("HOME").expect("HOME"));
for path in [
    home.join(".ssh/fixture-secret"),
    home.join(".aws/credentials"),
    home.join(".config/unlisted-secret"),
    home.join("random-home-secret"),
] {
    if fs::read(&path).is_ok() {
        bypass("a host home secret was readable");
    }
}
denied("host home files were not readable");
"#,
        )?;
        fs::create_dir_all(case.home.join(".ssh")).map_err(io_text)?;
        fs::create_dir_all(case.home.join(".aws")).map_err(io_text)?;
        fs::create_dir_all(case.home.join(".config")).map_err(io_text)?;
        fs::write(
            case.home.join(".ssh/fixture-secret"),
            b"redteam-home-secret",
        )
        .map_err(io_text)?;
        fs::write(case.home.join(".aws/credentials"), b"redteam-aws-secret").map_err(io_text)?;
        fs::write(
            case.home.join(".config/unlisted-secret"),
            b"redteam-config-secret",
        )
        .map_err(io_text)?;
        fs::write(
            case.home.join("random-home-secret"),
            b"redteam-random-secret",
        )
        .map_err(io_text)?;
        expect_denied_with_secrets(
            case,
            &[
                "redteam-home-secret",
                "redteam-aws-secret",
                "redteam-config-secret",
                "redteam-random-secret",
            ],
        )
    }

    fn attack_cargo_config(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "cargo-config",
            r#"
let cargo_home = PathBuf::from(env::var_os("CARGO_HOME").expect("CARGO_HOME"));
if fs::read(cargo_home.join("config.toml")).is_ok()
    || fs::read(cargo_home.join("credentials.toml")).is_ok()
{
    bypass("host Cargo config was readable");
}
denied("host Cargo config was not readable");
"#,
        )?;
        fs::write(
            case.cargo_home.join("config.toml"),
            b"[registries.redteam]\ntoken = \"redteam-config-token\"\n",
        )
        .map_err(io_text)?;
        fs::write(
            case.cargo_home.join("credentials.toml"),
            b"token = \"redteam-credentials-token\"\n",
        )
        .map_err(io_text)?;
        expect_denied_with_secrets(case, &["redteam-config-token", "redteam-credentials-token"])
    }

    fn attack_lockfile_symlink(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "lockfile-symlink",
            r#"
denied("the build script was not reached through a symlinked lockfile");
"#,
        )?;
        let external_lockfile = case.external.join("Cargo.lock");
        fs::write(&external_lockfile, b"version = 4\n").map_err(io_text)?;
        std::os::unix::fs::symlink(&external_lockfile, case.workspace.join("Cargo.lock"))
            .map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_lockfile_hardlink(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "lockfile-hardlink",
            r#"
denied("the build script was not reached through a hardlinked lockfile");
"#,
        )?;
        let external_lockfile = case.external.join("Cargo.lock");
        fs::write(&external_lockfile, b"version = 4\n").map_err(io_text)?;
        fs::hard_link(&external_lockfile, case.workspace.join("Cargo.lock")).map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_cache_symlink(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "cache-symlink",
            r#"
denied("the build script was not reached with a symlinked cache");
"#,
        )?;
        let external_cache = case.external.join("registry-cache");
        fs::create_dir(&external_cache).map_err(io_text)?;
        fs::write(external_cache.join("secret"), b"redteam-cache-secret").map_err(io_text)?;
        std::os::unix::fs::symlink(&external_cache, case.cargo_home.join("registry"))
            .map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_cache_nested_symlink(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "cache-nested-symlink",
            r#"
denied("the build script was not reached with a nested cache symlink");
"#,
        )?;
        let registry = case.cargo_home.join("registry");
        let external_cache = case.external.join("nested-registry-cache");
        fs::create_dir(&registry).map_err(io_text)?;
        fs::create_dir(&external_cache).map_err(io_text)?;
        fs::write(external_cache.join("secret"), b"redteam-cache-secret").map_err(io_text)?;
        std::os::unix::fs::symlink(&external_cache, registry.join("escape")).map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_cache_special_file(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "cache-special-file",
            r#"
denied("the build script was not reached with a special cache file");
"#,
        )?;
        let registry = case.cargo_home.join("registry");
        fs::create_dir(&registry).map_err(io_text)?;
        let listener = UnixListener::bind(registry.join("cache.sock")).map_err(io_text)?;
        let result = expect_denied(case);
        drop(listener);
        result
    }

    fn attack_workspace_write(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "workspace-write",
            r#"
let path = manifest_path("redteam-workspace-write");
match fs::write(&path, b"escape") {
    Ok(()) => bypass("the workspace was writable"),
    Err(_) => denied("workspace write was denied"),
}
"#,
        )?;
        expect_denied(case)
    }

    fn attack_external_write(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "external-write",
            r#"
let path = fs::read_to_string(manifest_path("external-path")).expect("external path");
match fs::write(path.trim(), b"external escape") {
    Ok(()) => bypass("an external file was writable"),
    Err(_) => denied("external write was denied"),
}
"#,
        )?;
        fs::write(
            case.workspace.join("external-path"),
            case.sentinel.display().to_string(),
        )
        .map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_target_write(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "target-write",
            r#"
let path = manifest_path("target/redteam-target-sibling");
match fs::write(&path, b"target escape") {
    Ok(()) => bypass("the persistent target parent was writable"),
    Err(_) => denied("the old target tree was read-only"),
}
"#,
        )?;
        expect_denied(case)
    }

    fn attack_network(config: &Config) -> Result<(), String> {
        let ipv4_listener = TcpListener::bind(("127.0.0.1", 0)).map_err(io_text)?;
        let ipv6_listener = TcpListener::bind(("::1", 0))
            .map_err(|error| format!("IPv6 red-team listener is unavailable: {error}"))?;
        let udp_listener = UdpSocket::bind(("127.0.0.1", 0)).map_err(io_text)?;
        udp_listener
            .set_read_timeout(Some(std::time::Duration::from_millis(250)))
            .map_err(io_text)?;
        let mut endpoints = vec![ipv4_listener.local_addr().map_err(io_text)?.to_string()];
        endpoints.push(ipv6_listener.local_addr().map_err(io_text)?.to_string());
        let udp_endpoint = udp_listener.local_addr().map_err(io_text)?.to_string();
        let case = new_attack(
            config,
            "network",
            r#"
let endpoints = fs::read_to_string(manifest_path("network-endpoints")).expect("endpoints");
for endpoint in endpoints.lines() {
    if TcpStream::connect(endpoint.trim()).is_ok() {
        bypass("TCP connection reached the host listener");
    }
}
let udp_endpoint = fs::read_to_string(manifest_path("network-udp-endpoint"))
    .expect("UDP endpoint");
let socket = UdpSocket::bind(("0.0.0.0", 0)).expect("UDP socket");
let _ = socket.send_to(b"redteam-udp", udp_endpoint.trim());
denied("network connections were denied");
"#,
        )?;
        fs::write(
            case.workspace.join("network-endpoints"),
            endpoints.join("\n"),
        )
        .map_err(io_text)?;
        fs::write(case.workspace.join("network-udp-endpoint"), udp_endpoint).map_err(io_text)?;
        let result = expect_denied(case);
        let udp_received = udp_listener.recv_from(&mut [0_u8; 64]).is_ok();
        drop(ipv4_listener);
        drop(ipv6_listener);
        drop(udp_listener);
        if udp_received {
            return Err("network attack reached the host UDP listener".to_owned());
        }
        result
    }

    fn attack_unix_socket(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "unix-socket",
            r#"
let home = PathBuf::from(env::var_os("HOME").expect("HOME"));
match UnixStream::connect(home.join("redteam-agent.sock")) {
    Ok(_) => bypass("a host Unix socket was reachable"),
    Err(_) => denied("host Unix socket was denied"),
}
"#,
        )?;
        let socket = case.home.join("redteam-agent.sock");
        let listener = UnixListener::bind(&socket).map_err(io_text)?;
        let result = expect_denied(case);
        drop(listener);
        result
    }

    fn attack_abstract_unix_socket(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "abstract-unix-socket",
            r#"
let name = fs::read_to_string(manifest_path("abstract-socket-name")).expect("socket name");
let child = Command::new("/usr/bin/python3")
    .args([
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(b'\\0' + sys.argv[1].encode())",
        name.trim(),
    ])
    .status();
match child {
    Ok(status) if status.success() => bypass("an abstract host Unix socket was reachable"),
    _ => denied("the abstract host Unix socket was denied"),
}
"#,
        )?;
        let name = format!(
            "cargo-cage-redteam-abstract-{}-{}",
            std::process::id(),
            timestamp()
        );
        let ready = case.workspace.join("abstract-socket-ready");
        fs::write(case.workspace.join("abstract-socket-name"), &name).map_err(io_text)?;
        let mut server = Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(b'\\0' + sys.argv[1].encode()); s.listen(1); open(sys.argv[2],'w').close(); s.accept()",
            ])
            .arg(&name)
            .arg(ready.to_str().unwrap())
            .spawn()
            .map_err(io_text)?;
        let mut ready_seen = false;
        for _ in 0..50 {
            if ready.is_file() {
                ready_seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if !ready_seen {
            let _ = server.kill();
            let _ = server.wait();
            return fail_case(&case, "abstract Unix socket listener did not start");
        }
        let result = expect_denied(case);
        let _ = server.kill();
        let _ = server.wait();
        result
    }

    fn attack_file_descriptor(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "inherited-fd",
            r#"
if fs::canonicalize("/proc/self/fd/9").is_ok() {
    bypass("an inherited file descriptor survived");
}
denied("inherited file descriptors were scrubbed");
"#,
        )?;
        let secret = case.external.join("fd-secret");
        fs::write(&secret, b"redteam-fd-secret").map_err(io_text)?;
        let before = case.sentinel().map_err(io_text)?;
        let output = case.run_with_fd(&secret).map_err(io_text)?;
        let after = case.sentinel().map_err(io_text)?;
        if before != after {
            return fail_case(&case, "inherited-FD attack changed the external sentinel");
        }
        let text = output_text(&output);
        if text.contains("redteam-fd-secret") {
            return fail_case(
                &case,
                "inherited-FD attack leaked the secret value in output",
            );
        }
        if !has_policy_context(&text) {
            return fail_case(
                &case,
                "inherited-FD attack failed without a recognizable sandbox policy diagnostic",
            );
        }
        if output.status.success() || text.contains("CAGE_POLICY_BYPASSED") {
            return fail_output(&case, "inherited-FD attack", &output);
        }
        case.finish();
        Ok(())
    }

    fn attack_runtime_paths(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "runtime-paths",
            r#"
for path in ["/sys/kernel", "/boot", "/var/lib", "/oldroot"] {
    if fs::metadata(path).is_ok() {
        bypass("a host runtime path was visible");
    }
}
denied("host runtime paths were hidden");
"#,
        )?;
        expect_denied(case)
    }

    fn attack_namespace_tools(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "namespace-tools",
            r#"
let unshare = Command::new("/usr/bin/unshare").args(["-Ur", "true"]).status().expect("unshare");
if unshare.success() {
    bypass("unshare created a nested user namespace");
}
let nsenter = Command::new("/usr/bin/nsenter")
    .args(["--mount=/proc/1/ns/mnt", "/bin/true"])
    .status()
    .expect("nsenter");
if nsenter.success() {
    bypass("nsenter entered a protected mount namespace");
}
fs::create_dir_all("/tmp/redteam-mount").expect("tmp directory");
let mount = Command::new("/usr/bin/mount")
    .args(["-t", "tmpfs", "tmpfs", "/tmp/redteam-mount"])
    .status()
    .expect("mount");
if mount.success() {
    bypass("mount succeeded inside the sandbox");
}
let mknod = Command::new("/usr/bin/mknod")
    .args(["/tmp/redteam-device", "c", "1", "3"])
    .status()
    .expect("mknod");
if mknod.success() {
    bypass("device creation succeeded inside the sandbox");
}
denied("namespace and mount tools were denied");
"#,
        )?;
        expect_denied(case)
    }

    fn attack_child_process(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "child-process",
            r#"
let path = fs::read_to_string(manifest_path("external-path")).expect("external path");
let child = Command::new("/bin/sh")
    .args(["-c", "printf child-escape > \"$1\"", "redteam-child", path.trim()])
    .status();
match child {
    Ok(status) if status.success() => bypass("a child process wrote outside the workspace"),
    _ => denied("the child process inherited the write boundary"),
}
"#,
        )?;
        fs::write(
            case.workspace.join("external-path"),
            case.sentinel.display().to_string(),
        )
        .map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_target_hardlink(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "target-hardlink",
            r#"
let source = manifest_path("Cargo.toml");
let alias = PathBuf::from(env::var_os("CARGO_TARGET_DIR").expect("target")).join("redteam-hardlink");
match fs::hard_link(&source, &alias) {
    Ok(()) => bypass("target hardlink creation succeeded"),
    Err(_) => denied("target hardlink creation was denied"),
}
"#,
        )?;
        let manifest = case.workspace.join("Cargo.toml");
        let before = fs::read(&manifest).map_err(io_text)?;
        let result = expect_denied(case);
        if result.is_ok() {
            let after = fs::read(&manifest).map_err(io_text)?;
            if before != after {
                return Err("target hardlink attack changed Cargo.toml".to_owned());
            }
        }
        result
    }

    fn attack_target_symlink(config: &Config) -> Result<(), String> {
        let case = new_attack(
            config,
            "target-symlink",
            r#"
let path = manifest_path("target/redteam-symlink");
match fs::write(&path, b"symlink escape") {
    Ok(()) => bypass("a target symlink was writable"),
    Err(_) => denied("target symlink write was denied"),
}
"#,
        )?;
        fs::create_dir(case.workspace.join("target")).map_err(io_text)?;
        std::os::unix::fs::symlink(
            &case.external,
            case.workspace.join("target/redteam-symlink"),
        )
        .map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_target_freshness(config: &Config) -> Result<(), String> {
        let case = Case::new(config, "target-freshness").map_err(io_text)?;
        case.write_build_script(
            r#"
let target = PathBuf::from(env::var_os("CARGO_TARGET_DIR").expect("target"));
fs::write(target.join("poisoned-artifact"), b"poison").expect("write target artifact");
"#,
        )
        .map_err(io_text)?;
        let first = case.run().map_err(io_text)?;
        if !first.status.success() {
            return fail_output(&case, "target poisoning seed", &first);
        }
        case.write_build_script(
            r#"
let target = PathBuf::from(env::var_os("CARGO_TARGET_DIR").expect("target"));
if target.join("poisoned-artifact").exists() {
    bypass("a later build reused the previous target run");
}
denied("a later build received a fresh target run");
"#,
        )
        .map_err(io_text)?;
        expect_denied(case)
    }

    fn attack_path_swap(config: &Config) -> Result<(), String> {
        let iterations = config.iterations.min(16);
        for attempt in 0..iterations {
            let case = Case::new(config, &format!("path-swap-{attempt}")).map_err(io_text)?;
            case.write_build_script(
                r#"
let target = PathBuf::from(env::var_os("CARGO_TARGET_DIR").expect("target"));
match fs::write(target.join("sentinel"), b"race escape") {
    Ok(()) => bypass("target write completed; external sentinel is checked by the harness"),
    Err(_) => denied("target write was denied"),
}
"#,
            )
            .map_err(io_text)?;
            let target = case.workspace.join("target");
            fs::create_dir(&target).map_err(io_text)?;
            let external = case.external.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let attacker_stop = Arc::clone(&stop);
            let attacker_target = target.clone();
            let attacker_external = external.clone();
            let attacker = thread::spawn(move || {
                while !attacker_stop.load(Ordering::Relaxed) {
                    let _ = fs::remove_file(&attacker_target);
                    let _ = fs::remove_dir(&attacker_target);
                    let _ = std::os::unix::fs::symlink(&attacker_external, &attacker_target);
                    let _ = fs::remove_file(&attacker_target);
                    let _ = fs::remove_dir(&attacker_target);
                    let _ = fs::create_dir(&attacker_target);
                }
            });

            let output = match case.run_reuse() {
                Ok(output) => output,
                Err(error) => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = attacker.join();
                    return fail_case(
                        &case,
                        &format!("target symlink swap could not run: {error}"),
                    );
                }
            };
            stop.store(true, Ordering::Relaxed);
            attacker
                .join()
                .map_err(|_| "path-swap attacker thread panicked".to_owned())?;
            let _ = fs::remove_file(&target);
            let _ = fs::remove_dir(&target);

            if output.status.success() || output_text(&output).contains("CAGE_POLICY_BYPASSED") {
                return fail_output(&case, "target symlink swap", &output);
            }
            if !has_policy_context(&output_text(&output)) {
                return fail_case(
                    &case,
                    "target symlink swap failed without a recognizable sandbox policy diagnostic",
                );
            }
            if case.sentinel().map_err(io_text)? != b"redteam-sentinel-before" {
                return fail_case(&case, "path-swap attack changed the external sentinel");
            }
            case.finish();
        }
        Ok(())
    }

    fn new_attack(config: &Config, name: &str, body: &str) -> Result<Case, String> {
        let case = Case::new(config, name).map_err(io_text)?;
        case.write_build_script(body).map_err(io_text)?;
        Ok(case)
    }

    fn expect_denied(case: Case) -> Result<(), String> {
        expect_denied_with_secrets(case, &[])
    }

    fn expect_denied_with_secrets(case: Case, secrets: &[&str]) -> Result<(), String> {
        let before = case.sentinel().map_err(io_text)?;
        let output = case.run().map_err(io_text)?;
        let after = case.sentinel().map_err(io_text)?;
        if before != after {
            return fail_case(&case, "attack changed the external sentinel");
        }
        let text = output_text(&output);
        for secret in secrets {
            if text.contains(secret) {
                return fail_case(&case, "attack leaked a secret value in process output");
            }
        }
        if !has_policy_context(&text) {
            return fail_case(
                &case,
                "attack failed without a recognizable sandbox policy diagnostic",
            );
        }
        if output.status.success() || text.contains("CAGE_POLICY_BYPASSED") {
            return fail_output(&case, "black-box attack", &output);
        }
        case.finish();
        Ok(())
    }

    fn fail_case(case: &Case, message: &str) -> Result<(), String> {
        Err(format!("{}: {message}", case.name))
    }

    fn fail_output(case: &Case, message: &str, output: &Output) -> Result<(), String> {
        let text = output_text(output);
        let detail = text
            .lines()
            .find(|line| line.contains("CAGE_POLICY_BYPASSED"))
            .unwrap_or("unexpected successful or unsafe process result");
        Err(format!("{}: {message}: {detail}", case.name))
    }

    fn output_text(output: &Output) -> String {
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        text
    }

    fn has_policy_context(text: &str) -> bool {
        text.contains("CAGE_POLICY_DENIED")
            || ((text.contains("sandbox policy error") || text.contains("sandbox setup failed"))
                && text.contains("remedy:"))
    }

    fn find_file(root: &Path, name: &str) -> bool {
        let Ok(entries) = fs::read_dir(root) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            path.file_name().and_then(|value| value.to_str()) == Some(name)
                || (path.is_dir() && find_file(&path, name))
        })
    }

    fn io_text(error: io::Error) -> String {
        error.to_string()
    }

    fn timestamp() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
