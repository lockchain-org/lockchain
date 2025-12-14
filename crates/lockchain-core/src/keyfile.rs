//! Keyfile parsing and persistence helpers shared by CLI, daemon, and UI.

use crate::error::{LockchainError, LockchainResult};
use hex::FromHex;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Result of decoding a key file or byte stream.
///
/// The boolean flag indicates whether the original material was hex encoded and
/// therefore required normalisation to raw bytes.
pub type DecodedKey = (Zeroizing<Vec<u8>>, bool);

/// Read bytes from `path` and decode them into raw key material.
pub fn read_key_file(path: &Path) -> LockchainResult<DecodedKey> {
    let contents = fs::read(path)?;
    decode_key_bytes(path, &contents)
}

/// Decode raw bytes into key material, accepting either a 32-byte binary key
/// or a 64-digit hex string (whitespace ignored).
pub fn decode_key_bytes(origin: &Path, bytes: &[u8]) -> LockchainResult<DecodedKey> {
    if bytes.len() == 32 {
        return Ok((Zeroizing::new(bytes.to_vec()), false));
    }

    if bytes.is_empty() {
        return Err(invalid_key(origin, "file is empty"));
    }

    let mut filtered = Vec::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err(invalid_key(
                origin,
                format!("found non-hex byte 0x{byte:02x}"),
            ));
        }
        filtered.push(*byte);
    }

    if filtered.is_empty() {
        return Err(invalid_key(origin, "file is empty"));
    }

    if filtered.len() != 64 {
        return Err(invalid_key(
            origin,
            format!(
                "hex key must contain exactly 64 hex digits (got {})",
                filtered.len()
            ),
        ));
    }

    let filtered = String::from_utf8(filtered)
        .map_err(|_| invalid_key(origin, "hex key contains non-UTF-8 characters"))?;
    let key = Vec::from_hex(filtered.as_str())
        .map_err(|err| invalid_key(origin, format!("hex decode failed: {err}")))?;

    if key.len() != 32 {
        return Err(invalid_key(
            origin,
            format!("decoded key must be 32 bytes (got {})", key.len()),
        ));
    }

    Ok((Zeroizing::new(key), true))
}

/// Write raw key material to `path`, applying restrictive permissions.
pub fn write_raw_key_file(path: &Path, key: &[u8]) -> LockchainResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, key)?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

fn invalid_key(path: &Path, reason: impl Into<String>) -> LockchainError {
    LockchainError::InvalidHexKey {
        path: PathBuf::from(path),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn decode_accepts_binary() {
        let bytes = [0x11u8; 32];
        let (decoded, converted) = decode_key_bytes(Path::new("dummy"), &bytes).unwrap();
        assert!(!converted);
        assert_eq!(&decoded[..], &bytes);
    }

    #[test]
    fn decode_accepts_hex() {
        let hex = b"ab".repeat(32);
        let (decoded, converted) = decode_key_bytes(Path::new("dummy"), &hex).unwrap();
        assert!(converted);
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn decode_accepts_hex_with_whitespace() {
        let base = hex::encode([0xABu8; 32]);
        let mut with_ws = Vec::new();
        for chunk in base.as_bytes().chunks(8) {
            with_ws.extend_from_slice(chunk);
            with_ws.push(b'\n');
        }
        let (decoded, converted) = decode_key_bytes(Path::new("dummy"), &with_ws).unwrap();
        assert!(converted);
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn decode_rejects_non_hex() {
        let err = decode_key_bytes(Path::new("/tmp/key"), b"zz").unwrap_err();
        match err {
            LockchainError::InvalidHexKey { path, .. } => {
                assert_eq!(path, PathBuf::from("/tmp/key"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn write_raw_key_file_sets_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.bin");
        let key = vec![0x42; 32];
        write_raw_key_file(&path, &key).unwrap();
        assert_eq!(fs::read(&path).unwrap(), key);
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
    }

    #[test]
    fn write_raw_key_file_creates_parent() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested").join("key.bin");
        write_raw_key_file(&nested, &[0x11; 32]).unwrap();
        assert!(nested.exists());
    }
}
