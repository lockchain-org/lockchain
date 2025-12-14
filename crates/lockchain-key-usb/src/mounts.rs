use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const MOUNTS_OVERRIDE_ENV: &str = "LOCKCHAIN_KEY_USB_MOUNTS_PATH";

pub(crate) fn find_mount_point(devnode: &Path) -> Result<Option<PathBuf>> {
    let mounts = read_mount_table()?;
    let devnode_str = devnode.to_string_lossy();
    Ok(parse_mounts(&mounts, devnode_str.as_ref()))
}

fn read_mount_table() -> Result<String> {
    if let Ok(path) = env::var(MOUNTS_OVERRIDE_ENV) {
        return fs::read_to_string(&path).with_context(|| format!("read mounts file {path}"));
    }
    fs::read_to_string("/proc/mounts").context("read /proc/mounts")
}

fn parse_mounts(mounts: &str, devnode: &str) -> Option<PathBuf> {
    for line in mounts.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let device = parts.next()?;
        let mountpoint = parts.next()?;
        if device == devnode {
            return Some(PathBuf::from(unescape_mount_field(mountpoint)));
        }
    }
    None
}

fn unescape_mount_field(input: &str) -> String {
    let mut chars = input.chars().peekable();
    let mut output = String::with_capacity(input.len());

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let mut oct = String::new();
            for _ in 0..3 {
                if let Some(next) = chars.peek() {
                    if !next.is_ascii_digit() {
                        break;
                    }
                }
                if let Some(next) = chars.next() {
                    oct.push(next);
                }
            }
            if oct.len() == 3 {
                if let Ok(value) = u8::from_str_radix(&oct, 8) {
                    output.push(value as char);
                    continue;
                }
            }
            output.push('\\');
            output.push_str(&oct);
        } else {
            output.push(ch);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl Into<String>) -> Self {
            let prev = env::var(key).ok();
            env::set_var(key, value.into());
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = &self.prev {
                env::set_var(self.key, prev);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn parse_mounts_finds_matching_device() {
        let snapshot = "/dev/sdb1 /media/LOCK\\040CHAIN ext4 rw 0 0\n";
        let mount = parse_mounts(snapshot, "/dev/sdb1").unwrap();
        assert_eq!(mount, PathBuf::from("/media/LOCK CHAIN"));
    }

    #[test]
    fn find_mount_point_honours_override() {
        let dir = tempdir().unwrap();
        let mount_file = dir.path().join("mounts");
        fs::write(
            &mount_file,
            "/dev/sdb1 /media/lockchain ext4 rw,relatime 0 0\n",
        )
        .unwrap();

        let _guard = EnvGuard::set(
            MOUNTS_OVERRIDE_ENV,
            mount_file.to_string_lossy().into_owned(),
        );

        let result = find_mount_point(Path::new("/dev/sdb1")).unwrap();
        assert_eq!(result, Some(PathBuf::from("/media/lockchain")));
    }

    #[test]
    fn unescape_mount_field_decodes_octals() {
        assert_eq!(
            unescape_mount_field("/media/LOCK\\040CHAIN"),
            "/media/LOCK CHAIN"
        );
        assert_eq!(unescape_mount_field("/mnt/keys"), "/mnt/keys");
    }
}
