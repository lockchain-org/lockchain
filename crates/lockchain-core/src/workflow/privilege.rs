use crate::error::{LockchainError, LockchainResult};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

pub(crate) const PKEXEC_BINARIES: &[&str] = &["/usr/bin/pkexec", "/bin/pkexec"];

/// Scratch wrapper around `std::process::Output` for external command wrappers.
#[derive(Debug)]
pub(crate) struct CommandOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) status: std::process::ExitStatus,
}

/// Try each binary in `candidates` until one executes successfully.
pub(crate) fn run_external(
    candidates: &[&str],
    args: &[OsString],
) -> LockchainResult<CommandOutput> {
    let mut permission_denied_without_escalation = false;

    for candidate in candidates {
        let path = Path::new(candidate);
        if !path.exists() {
            continue;
        }

        match Command::new(candidate).args(args).output() {
            Ok(raw) => {
                let mut result = CommandOutput {
                    stdout: raw.stdout,
                    stderr: raw.stderr,
                    status: raw.status,
                };
                if should_retry_with_pkexec(&result) && !running_as_root() {
                    if pkexec_available() {
                        if let Some(escalated) = run_with_pkexec(candidate, args)? {
                            result = escalated;
                        } else {
                            return Err(missing_privilege_error());
                        }
                    } else {
                        return Err(missing_privilege_error());
                    }
                }
                return Ok(result);
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied && !running_as_root() {
                    if pkexec_available() {
                        if let Some(escalated) = run_with_pkexec(candidate, args)? {
                            return Ok(escalated);
                        } else {
                            return Err(missing_privilege_error());
                        }
                    } else {
                        permission_denied_without_escalation = true;
                        continue;
                    }
                }
                return Err(LockchainError::Provider(err.to_string()));
            }
        }
    }

    if permission_denied_without_escalation && !running_as_root() {
        return Err(missing_privilege_error());
    }
    Err(LockchainError::Provider(format!(
        "none of {:?} are available on this system",
        candidates
    )))
}

fn should_retry_with_pkexec(output: &CommandOutput) -> bool {
    if output.status.success() {
        return false;
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    for haystack in [&stderr, &stdout] {
        if haystack.contains("permission denied")
            || haystack.contains("operation not permitted")
            || haystack.contains("must be run as root")
            || haystack.contains("requires superuser")
            || haystack.contains("superuser privileges")
        {
            return true;
        }
    }
    false
}

fn run_with_pkexec(binary: &str, args: &[OsString]) -> LockchainResult<Option<CommandOutput>> {
    for pkexec in PKEXEC_BINARIES {
        if !Path::new(pkexec).exists() {
            continue;
        }
        let mut command = Command::new(pkexec);
        command.arg("--disable-internal-agent");
        command.arg(binary);
        for arg in args {
            command.arg(arg);
        }
        match command.output() {
            Ok(output) => {
                return Ok(Some(CommandOutput {
                    stdout: output.stdout,
                    stderr: output.stderr,
                    status: output.status,
                }));
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    continue;
                }
                return Err(LockchainError::Provider(err.to_string()));
            }
        }
    }
    Ok(None)
}

pub fn ensure_privilege_support() -> LockchainResult<()> {
    if running_as_root() || pkexec_available() {
        Ok(())
    } else {
        Err(missing_privilege_error())
    }
}

fn pkexec_available() -> bool {
    PKEXEC_BINARIES.iter().any(|path| Path::new(path).exists())
}

#[cfg(unix)]
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    true
}

fn missing_privilege_error() -> LockchainError {
    LockchainError::Privilege(
        "Polkit (pkexec) is not available and LockChain is running without the required ZFS privileges. Install a polkit agent (e.g. `sudo apt install policykit-1`), run the LockChain daemon via systemd as root, or delegate ZFS permissions with `sudo zfs allow lockchain load-key,key <dataset>` before retrying."
            .into(),
    )
}
