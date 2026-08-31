#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

pub struct Fixture {
    root: PathBuf,
}

impl Fixture {
    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn file(&self, name: impl AsRef<Path>) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn materialize(name: &str) -> io::Result<Fixture> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    if !source.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("fixture does not exist: {}", source.display()),
        ));
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let destination = std::env::temp_dir().join(format!(
        "cargo-cage-fixture-{}-{}-{}",
        std::process::id(),
        timestamp,
        id
    ));
    fs::create_dir(&destination)?;
    copy_directory(&source, &destination)?;
    Ok(Fixture { root: destination })
}

fn copy_directory(source: &Path, destination: &Path) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.is_dir() {
            fs::create_dir(&destination_path)?;
            copy_directory(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported fixture entry: {}", source_path.display()),
            ));
        }
    }
    Ok(())
}
