//! Bounded, symlink- and reparse-point-safe file reading utilities.
//! Pure zero-fan-out leaf module shared by discovery, profile loading, and CLI.

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;

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
