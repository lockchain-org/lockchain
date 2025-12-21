//! Execution wrapper for invoking `cryptsetup`.
//!
//! The goal is to keep shell integration isolated so provider logic stays
//! testable (fake binaries, deterministic stdout parsing).

use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_provider::luks::LuksState;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Debug, Clone)]
pub(crate) struct CryptsetupCommand {
    binary: PathBuf,
    timeout: Duration,
}

#[derive(Debug)]
struct Output {
    stdout: String,
    stderr: String,
    status: i32,
}

impl CryptsetupCommand {
    pub(crate) fn new(binary: PathBuf, timeout: Duration) -> Self {
        Self { binary, timeout }
    }

    pub(crate) fn mapping_state(&self, name: &str) -> LockchainResult<LuksState> {
        if dev_mapper_node_exists(name) {
            return Ok(LuksState::Active);
        }
        let out = self.run(&["status", name], None)?;
        Ok(classify_status(name, &out))
    }

    pub(crate) fn unlock_mapping_with_keyfile(
        &self,
        source: &str,
        name: &str,
        keyfile: &Path,
    ) -> LockchainResult<()> {
        if dev_mapper_node_exists(name) {
            return Ok(());
        }

        let key_arg = keyfile.to_string_lossy().into_owned();
        let key_desc = format!("keyfile {}", keyfile.display());
        self.open_mapping(source, name, &key_arg, None, &key_desc)
    }

    pub(crate) fn unlock_mapping_with_key_bytes(
        &self,
        source: &str,
        name: &str,
        key: &[u8],
    ) -> LockchainResult<()> {
        if dev_mapper_node_exists(name) {
            return Ok(());
        }

        self.open_mapping(source, name, "-", Some(key), "provided key bytes")
    }

    pub(crate) fn enroll_keyfile(
        &self,
        source: &str,
        existing_passphrase: &[u8],
        keyfile: &Path,
    ) -> LockchainResult<()> {
        if existing_passphrase.is_empty() {
            return Err(LockchainError::InvalidConfig(
                "existing LUKS passphrase cannot be empty".into(),
            ));
        }

        let key_arg = keyfile.to_string_lossy().into_owned();
        let args = vec![
            "luksAddKey".to_string(),
            "--batch-mode".to_string(),
            "--key-file".to_string(),
            "-".to_string(),
            source.to_string(),
            key_arg,
        ];
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = self.run(&arg_refs, Some(existing_passphrase))?;
        if out.status == 0 {
            return Ok(());
        }

        let diagnostic = output_diagnostic(&out);
        let message = classify_addkey_failure(source, keyfile, &diagnostic);
        Err(LockchainError::Provider(format!(
            "{message} (exit code {})",
            out.status
        )))
    }

    pub(crate) fn close_mapping(&self, name: &str) -> LockchainResult<()> {
        let mut out = self.run(&["close", name], None)?;
        if out.status != 0 && action_unsupported(&out) {
            out = self.run(&["luksClose", name], None)?;
        }

        if out.status == 0 {
            return Ok(());
        }

        let diagnostic = output_diagnostic(&out);
        let diagnostic_lower = diagnostic.to_ascii_lowercase();
        if diagnostic_lower.contains("does not exist")
            || diagnostic_lower.contains("doesn't exist")
            || diagnostic_lower.contains("not active")
        {
            return Ok(());
        }

        let message = classify_close_failure(name, &diagnostic);
        Err(LockchainError::Provider(format!(
            "{message} (exit code {})",
            out.status
        )))
    }

    fn run(&self, args: &[&str], input: Option<&[u8]>) -> LockchainResult<Output> {
        let mut command = Command::new(&self.binary);
        command.args(args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        if input.is_some() {
            command.stdin(Stdio::piped());
        }

        let mut child = command.spawn()?;

        if let Some(payload) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(payload)?;
                stdin.flush().ok();
            }
        }

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        self.wait_with_timeout(child, stdout_pipe, stderr_pipe)
    }

    fn wait_with_timeout(
        &self,
        mut child: Child,
        stdout_pipe: Option<ChildStdout>,
        stderr_pipe: Option<ChildStderr>,
    ) -> LockchainResult<Output> {
        let start = Instant::now();
        let stdout_handle = spawn_output_reader(stdout_pipe);
        let stderr_handle = spawn_output_reader(stderr_pipe);
        let mut exit_status = None;

        while start.elapsed() <= self.timeout {
            if let Some(status) = child.try_wait()? {
                exit_status = Some(status);
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }

        if exit_status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(LockchainError::Provider(format!(
                "{} timed out after {:?}",
                self.binary.display(),
                self.timeout
            )));
        }

        let stdout = stdout_handle
            .join()
            .map_err(|_| LockchainError::Provider("stdout reader thread panicked".into()))??;
        let stderr = stderr_handle
            .join()
            .map_err(|_| LockchainError::Provider("stderr reader thread panicked".into()))??;

        let status = exit_status.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);

        Ok(Output {
            stdout,
            stderr,
            status,
        })
    }

    fn open_mapping(
        &self,
        source: &str,
        name: &str,
        key_arg: &str,
        input: Option<&[u8]>,
        key_desc: &str,
    ) -> LockchainResult<()> {
        if input.is_some() && key_arg != "-" {
            return Err(LockchainError::Provider(
                "cryptsetup open internal misuse: stdin input requires key_arg '-'".into(),
            ));
        }

        let primary_args = [
            "open",
            "--type",
            "luks",
            "--batch-mode",
            "--key-file",
            key_arg,
            source,
            name,
        ];
        let mut out = self.run(&primary_args, input)?;

        if out.status != 0 && action_unsupported(&out) {
            let fallback_args = [
                "luksOpen",
                "--batch-mode",
                "--key-file",
                key_arg,
                source,
                name,
            ];
            out = self.run(&fallback_args, input)?;
        }

        if out.status == 0 || dev_mapper_node_exists(name) {
            return Ok(());
        }

        let diagnostic = output_diagnostic(&out);
        let message = classify_open_failure(name, source, key_desc, &diagnostic);
        Err(LockchainError::Provider(format!(
            "{message} (exit code {})",
            out.status
        )))
    }
}

fn dev_mapper_node_exists(name: &str) -> bool {
    let root = Path::new("/dev/mapper");
    root.is_dir() && root.join(name).exists()
}

fn action_unsupported(output: &Output) -> bool {
    let diagnostic = output_diagnostic(output);
    let diagnostic_lower = diagnostic.to_ascii_lowercase();
    diagnostic_lower.contains("unknown action")
        || diagnostic_lower.contains("unknown command")
        || diagnostic_lower.contains("invalid action")
        || diagnostic_lower.contains("invalid command")
        || diagnostic_lower.contains("unknown option")
}

fn classify_open_failure(name: &str, source: &str, key_desc: &str, diagnostic: &str) -> String {
    let trimmed = diagnostic.trim();
    let lower = trimmed.to_ascii_lowercase();
    let diagnostic = if trimmed.is_empty() {
        "no additional output".to_string()
    } else {
        trimmed.to_string()
    };

    if lower.contains("no key available")
        || lower.contains("wrong key")
        || lower.contains("keyslot")
        || lower.contains("key slot")
        || lower.contains("passphrase is incorrect")
        || lower.contains("invalid passphrase")
    {
        return format!(
            "cryptsetup rejected the provided key material for mapping `{name}` from `{source}` using {key_desc}: {diagnostic}. Verify the staged USB key matches the LUKS keyslot"
        );
    }

    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("not permitted")
    {
        return format!(
            "cryptsetup could not unlock mapping `{name}` from `{source}` using {key_desc}: {diagnostic}. This usually requires elevated privileges (run via the daemon/service or as root)"
        );
    }

    if lower.contains("no such file")
        || lower.contains("does not exist")
        || lower.contains("not found")
        || lower.contains("cannot open device")
    {
        return format!(
            "cryptsetup could not access source `{source}` for mapping `{name}` using {key_desc}: {diagnostic}. Confirm the device is present and crypttab points at the correct UUID/path"
        );
    }

    if lower.contains("already exists") && dev_mapper_node_exists(name) {
        return format!(
            "mapping `{name}` already appears active under /dev/mapper; cryptsetup reported: {diagnostic}"
        );
    }

    format!(
        "cryptsetup failed to unlock mapping `{name}` from `{source}` using {key_desc}: {diagnostic}"
    )
}

fn classify_addkey_failure(source: &str, keyfile: &Path, diagnostic: &str) -> String {
    let trimmed = diagnostic.trim();
    let lower = trimmed.to_ascii_lowercase();
    let diagnostic = if trimmed.is_empty() {
        "no additional output".to_string()
    } else {
        trimmed.to_string()
    };

    if lower.contains("no key available")
        || lower.contains("wrong key")
        || lower.contains("passphrase is incorrect")
        || lower.contains("invalid passphrase")
    {
        return format!(
            "cryptsetup rejected the supplied existing passphrase while enrolling key at {} for `{source}`: {diagnostic}. Re-enter the current LUKS passphrase and retry",
            keyfile.display()
        );
    }

    if lower.contains("not a valid luks device") || lower.contains("is not a luks device") {
        return format!(
            "cryptsetup refused to enroll key at {} because `{source}` is not a LUKS device: {diagnostic}",
            keyfile.display()
        );
    }

    if lower.contains("no remaining keyslot")
        || lower.contains("no remaining keyslots")
        || lower.contains("no free key slot")
        || lower.contains("no free keyslot")
        || lower.contains("all key slots full")
    {
        return format!(
            "cryptsetup could not enroll the LockChain key at {} because `{source}` has no free keyslots: {diagnostic}. Remove an unused keyslot before retrying",
            keyfile.display()
        );
    }

    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("not permitted")
    {
        return format!(
            "cryptsetup could not enroll key at {} for `{source}`: {diagnostic}. This usually requires elevated privileges (run via the daemon/service or as root)",
            keyfile.display()
        );
    }

    if lower.contains("no such file")
        || lower.contains("does not exist")
        || lower.contains("not found")
        || lower.contains("cannot open device")
    {
        return format!(
            "cryptsetup could not access `{source}` while enrolling key at {}: {diagnostic}. Confirm the device path/UUID is correct and present",
            keyfile.display()
        );
    }

    format!(
        "cryptsetup failed to enroll key at {} for `{source}`: {diagnostic}",
        keyfile.display()
    )
}

fn classify_close_failure(name: &str, diagnostic: &str) -> String {
    let trimmed = diagnostic.trim();
    let lower = trimmed.to_ascii_lowercase();
    let diagnostic = if trimmed.is_empty() {
        "no additional output".to_string()
    } else {
        trimmed.to_string()
    };

    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("not permitted")
    {
        return format!(
            "cryptsetup could not close mapping `{name}`: {diagnostic}. This usually requires elevated privileges (run via the daemon/service or as root)"
        );
    }

    format!("cryptsetup failed to close mapping `{name}`: {diagnostic}")
}

fn spawn_output_reader<R>(pipe: Option<R>) -> thread::JoinHandle<LockchainResult<String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || -> LockchainResult<String> {
        if let Some(mut reader) = pipe {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf)?;
            Ok(String::from_utf8_lossy(&buf).to_string())
        } else {
            Ok(String::new())
        }
    })
}

fn classify_status(name: &str, output: &Output) -> LuksState {
    match output.status {
        0 => return LuksState::Active,
        4 => return LuksState::Inactive,
        _ => {}
    }

    let diagnostic = status_diagnostic(output);
    let diagnostic_lower = diagnostic.to_ascii_lowercase();

    if diagnostic_lower.contains("is inactive")
        || diagnostic_lower.contains("not active")
        || diagnostic_lower.contains("does not exist")
        || diagnostic_lower.contains("doesn't exist")
    {
        return LuksState::Inactive;
    }

    LuksState::Unknown(if diagnostic.is_empty() {
        format!(
            "cryptsetup status {name} exited with code {}",
            output.status
        )
    } else {
        format!(
            "cryptsetup status {name} exited with code {}: {}",
            output.status, diagnostic
        )
    })
}

fn status_diagnostic(output: &Output) -> String {
    let stderr = output.stderr.trim();
    let stdout = output.stdout.trim();
    if !stderr.is_empty() {
        stderr.to_string()
    } else {
        stdout.to_string()
    }
}

fn output_diagnostic(output: &Output) -> String {
    status_diagnostic(output)
}
