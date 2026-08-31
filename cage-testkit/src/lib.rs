#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

pub struct Fixture {
    root: PathBuf,
    cleanup_paths: RefCell<Vec<PathBuf>>,
}

impl Fixture {
    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn file(&self, name: impl AsRef<Path>) -> PathBuf {
        self.root.join(name)
    }

    /// Create a temporary directory beside the fixture, outside the workspace
    /// that will be mounted read-only by cargo-cage.
    pub fn temporary_dir(&self, name: &str) -> io::Result<PathBuf> {
        let root_name = self
            .root
            .file_name()
            .ok_or_else(|| io::Error::other("fixture root has no file name"))?;
        let path = self
            .root
            .parent()
            .ok_or_else(|| io::Error::other("fixture root has no parent"))?
            .join(format!("{}-{name}", root_name.to_string_lossy()));
        fs::create_dir_all(&path)?;
        let mut cleanup_paths = self.cleanup_paths.borrow_mut();
        if !cleanup_paths.contains(&path) {
            cleanup_paths.push(path.clone());
        }
        Ok(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for path in self.cleanup_paths.get_mut().drain(..) {
            let _ = fs::remove_dir_all(path);
        }
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
    Ok(Fixture {
        root: destination,
        cleanup_paths: RefCell::new(Vec::new()),
    })
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
