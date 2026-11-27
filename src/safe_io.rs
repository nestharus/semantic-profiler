//! Bounded, symlink- and reparse-point-safe file reading utilities.
//! Pure zero-fan-out leaf module shared by discovery, profile loading, and CLI.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

pub fn is_reparse_or_symlink(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Normalize away trailing path separators (preserving filesystem roots like `/` or `C:\`).
pub fn strip_trailing_separators(path: &Path) -> PathBuf {
    let cleaned: PathBuf = path.components().collect();
    if cleaned.as_os_str().is_empty() {
        path.to_path_buf()
    } else {
        cleaned
    }
}

/// Reject any existing symlink or Windows reparse-point component along `path`
/// and all of its existing ancestors (skipping only the bare filesystem root).
pub fn reject_reparse_or_symlink_ancestors(path: &Path, label: &str) -> Result<PathBuf, String> {
    let cleaned = strip_trailing_separators(path);
    for anc in cleaned.ancestors() {
        if anc.as_os_str().is_empty() || anc.parent().is_none() {
            continue;
        }
        match fs::symlink_metadata(anc) {
            Ok(meta) => {
                if is_reparse_or_symlink(&meta) {
                    return Err(format!(
                        "refusing symlink or reparse point in {label} path: {}",
                        anc.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "failed to stat {label} ancestor {}: {e}",
                    anc.display()
                ));
            }
        }
    }
    Ok(cleaned)
}

/// Read a regular file with an enforced upper byte bound using `Read::take(limit + 1)`,
/// preventing TOCTOU growth past the configured limit.
pub fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("open error: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("metadata error: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    if meta.len() > max_bytes {
        return Err(format!("file exceeds {max_bytes} bytes"));
    }
    let mut buf = Vec::with_capacity(meta.len().min(max_bytes) as usize);
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited
        .read_to_end(&mut buf)
        .map_err(|e| format!("read error: {e}"))?;
    if (buf.len() as u64) > max_bytes {
        return Err(format!("file exceeds {max_bytes} bytes"));
    }
    Ok(buf)
}
