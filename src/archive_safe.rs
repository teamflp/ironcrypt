//! Safe directory archive helpers (path traversal / symlink / bomb limits).
//!
//! Available when the `cli` feature is enabled (`encrypt-dir` / `decrypt-dir`).

use crate::limits::{
    MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_ENTRY_BYTES, MAX_ARCHIVE_UNPACKED_BYTES,
};
use crate::IronCryptError;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

/// Refuse symlink roots and non-directories before packing.
pub fn assert_safe_source_dir(dir: &Path) -> Result<(), IronCryptError> {
    let meta = fs::symlink_metadata(dir).map_err(|e| {
        IronCryptError::IOError(std::io::Error::new(
            e.kind(),
            format!("stat {}: {e}", dir.display()),
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(IronCryptError::ConfigurationError(format!(
            "refusing to pack through symlink: {}",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(IronCryptError::ConfigurationError(format!(
            "not a directory: {}",
            dir.display()
        )));
    }
    Ok(())
}

fn normalize_components(path: &Path) -> PathBuf {
    let mut stacked = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(p) => {
                stacked = PathBuf::new();
                stacked.push(Component::Prefix(p));
            }
            Component::RootDir => {
                stacked = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
            }
            Component::ParentDir => {
                let _ = stacked.pop();
            }
            Component::CurDir => {}
            Component::Normal(s) => stacked.push(s),
        }
    }
    stacked
}

/// Ensure `child` resolves inside `base` (no `..` escape).
///
/// Prefer a **relative** `child` (as in tar entry names). Absolute paths are
/// accepted only when they canonicalize under `base` (existing paths).
pub fn path_is_within(base: &Path, child: &Path) -> bool {
    let Ok(base) = fs::canonicalize(base) else {
        return false;
    };
    if let Ok(child_c) = fs::canonicalize(child) {
        return child_c.starts_with(&base);
    }
    if child.is_absolute() {
        // Non-existent absolute paths cannot be safely compared across
        // symlink roots (e.g. macOS `/var` → `/private/var`).
        return false;
    }
    if child
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
    {
        return false;
    }
    let joined = base.join(normalize_components(child));
    joined.starts_with(&base)
}

/// Unpack a tar into `output_dir` with bomb / traversal limits.
pub fn safe_unpack_tar<R: Read>(
    archive: &mut tar::Archive<R>,
    output_dir: &Path,
) -> Result<(), IronCryptError> {
    fs::create_dir_all(output_dir)?;
    let mut entries = 0u32;
    let mut total = 0u64;

    for entry in archive
        .entries()
        .map_err(|e| IronCryptError::DecryptionError(format!("tar entries: {e}")))?
    {
        #[allow(unused_mut)] // needed for `Read` body copy below on file entries
        let mut entry =
            entry.map_err(|e| IronCryptError::DecryptionError(format!("tar entry: {e}")))?;
        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            return Err(IronCryptError::DecryptionError(format!(
                "archive exceeds MAX_ARCHIVE_ENTRIES ({MAX_ARCHIVE_ENTRIES})"
            )));
        }

        let path = entry
            .path()
            .map_err(|e| IronCryptError::DecryptionError(format!("tar path: {e}")))?;
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(IronCryptError::DecryptionError(format!(
                "refusing path traversal in archive entry: {}",
                path.display()
            )));
        }

        let is_link = {
            let t = entry.header().entry_type();
            t.is_symlink() || t.is_hard_link()
        };
        if is_link {
            return Err(IronCryptError::DecryptionError(format!(
                "refusing symlink/hardlink in archive: {}",
                path.display()
            )));
        }

        let size = entry.size();
        if size > MAX_ARCHIVE_ENTRY_BYTES {
            return Err(IronCryptError::DecryptionError(format!(
                "archive entry {} exceeds MAX_ARCHIVE_ENTRY_BYTES ({MAX_ARCHIVE_ENTRY_BYTES})",
                path.display()
            )));
        }
        total = total.saturating_add(size);
        if total > MAX_ARCHIVE_UNPACKED_BYTES {
            return Err(IronCryptError::DecryptionError(format!(
                "archive unpacked size exceeds MAX_ARCHIVE_UNPACKED_BYTES ({MAX_ARCHIVE_UNPACKED_BYTES})"
            )));
        }

        let dest = output_dir.join(&path);
        if !path_is_within(output_dir, path.as_ref()) {
            return Err(IronCryptError::DecryptionError(format!(
                "refusing extract outside output dir: {}",
                path.display()
            )));
        }

        // Refuse extract through a pre-existing symlink in the destination tree.
        for ancestor in dest.ancestors().take_while(|p| p.starts_with(output_dir)) {
            if ancestor.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                return Err(IronCryptError::DecryptionError(format!(
                    "refusing extract via symlink component: {}",
                    ancestor.display()
                )));
            }
        }

        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = File::create(&dest).map_err(|e| {
            IronCryptError::IOError(std::io::Error::new(
                e.kind(),
                format!("create {}: {e}", dest.display()),
            ))
        })?;
        let mut limited = entry.take(MAX_ARCHIVE_ENTRY_BYTES);
        std::io::copy(&mut limited, &mut out)?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tar::Builder;

    #[test]
    fn rejects_parent_escape() {
        let dir = tempfile::tempdir().unwrap();
        let escape = dir.path().join("..").join("outside");
        assert!(!path_is_within(dir.path(), &escape));
        assert!(!path_is_within(dir.path(), Path::new("/etc/passwd")));
    }

    #[test]
    fn path_within_ok() {
        let dir = tempfile::tempdir().unwrap();
        assert!(path_is_within(dir.path(), Path::new("a/b.txt")));
        let existing = dir.path().join("a");
        fs::create_dir_all(&existing).unwrap();
        assert!(path_is_within(dir.path(), &existing));
    }

    #[test]
    fn unpack_ok_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut buf = Vec::new();
        {
            let mut b = Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            header.set_path("ok.txt").unwrap();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, Cursor::new(b"x")).unwrap();
            b.finish().unwrap();
        }
        let mut archive = tar::Archive::new(Cursor::new(buf));
        safe_unpack_tar(&mut archive, dir.path()).unwrap();
        assert!(dir.path().join("ok.txt").exists());
    }
}
