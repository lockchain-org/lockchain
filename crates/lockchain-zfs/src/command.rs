//! Runs the host `zfs`/`zpool` binaries with timeouts and structured output capture.
//!
//! Keeping process execution here lets the provider focus on ZFS semantics and keeps
//! command parsing testable with fake binaries.

use lockchain_core::error::{LockchainError, LockchainResult};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
/// Wraps a concrete binary path and timeout used to run ZFS CLI commands.
pub struct CommandRunner {
    path: PathBuf,
    timeout: Duration,
}

#[derive(Debug)]
/// Collects stdout, stderr, and exit status from a finished command.
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

impl CommandRunner {
    /// Build a new runner targeting the supplied binary and timeout.
    pub fn new(path: PathBuf, timeout: Duration) -> Self {
        Self { path, timeout }
    }

    /// Return the binary path this runner will execute.
    pub fn binary(&self) -> &std::path::Path {
        &self.path
    }

    /// Execute the binary with arguments, optional stdin payload, and capture the result.
    pub fn run(&self, args: &[&str], input: Option<&[u8]>) -> LockchainResult<Output> {
        let mut command = Command::new(&self.path);
        command.args(args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        if input.is_some() {
            command.stdin(Stdio::piped());
        }

        let mut child = command.spawn()?;

        if let Some(bytes) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(bytes)?;
                stdin.flush().ok();
            }
        }

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        self.wait_with_timeout(child, stdout_pipe, stderr_pipe)
    }

    /// Wait for the child process until it finishes or exceeds the configured timeout.
    fn wait_with_timeout(
        &self,
        mut child: Child,
        stdout_pipe: Option<ChildStdout>,
        stderr_pipe: Option<ChildStderr>,
    ) -> LockchainResult<Output> {
        let start = Instant::now();
        let stdout_handle = Self::spawn_output_reader(stdout_pipe);
        let stderr_handle = Self::spawn_output_reader(stderr_pipe);
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
                self.path.display(),
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

    /// Spin up a helper thread to drain a pipe and return the collected text.
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
}
