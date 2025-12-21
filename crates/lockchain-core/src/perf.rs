//! Performance logging helpers for profiling unlock flows without touching the
//! primary application logging pipeline.

use crate::config::project_dirs;
use directories_next::UserDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOG_ROOT_ENV: &str = "LOCKCHAIN_LOG_ROOT";
const EXPORT_ROOT_ENV: &str = "LOCKCHAIN_LOG_EXPORT_DIR";
const LOG_DIR: &str = "logs";
const PERF_DIR: &str = "perf";
const LOG_FILE: &str = "unlock_profile.jsonl";
const BASELINE_FILE: &str = "unlock_baseline.json";

/// Captured unlock timing entry written to the performance log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnlockTimingEntry {
    /// Dataset used during the run.
    pub dataset: String,
    /// Total unlock duration in milliseconds.
    pub duration_ms: u128,
    /// Whether the unlock workflow completed successfully.
    pub success: bool,
    /// Milliseconds since the Unix epoch when the run finished.
    pub timestamp_ms: u128,
    /// Baseline duration captured for this dataset.
    pub baseline_ms: u128,
    /// Delta between the current run and the recorded baseline.
    pub delta_ms: i128,
    /// Optional free-form note to tag the run.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct UnlockBaseline {
    duration_ms: u128,
    recorded_at_ms: u128,
}

/// Describes the resolved log paths for performance profiling.
#[derive(Debug, Clone)]
pub struct PerformanceLogPaths {
    /// Root directory that contains the performance log files.
    pub root: PathBuf,
    /// JSONL file that collects unlock timings.
    pub log_file: PathBuf,
    /// Baseline snapshot file keyed by dataset.
    pub baseline_file: PathBuf,
}

/// Outcome of a recorded profiling run.
#[derive(Debug, Clone)]
pub struct RecordedUnlockTiming {
    /// The entry appended to the log.
    pub entry: UnlockTimingEntry,
    /// Location of the JSONL log file.
    pub log_path: PathBuf,
    /// Location of the baseline cache file.
    pub baseline_path: PathBuf,
    /// Whether this run created a new baseline for the dataset.
    pub baseline_created: bool,
}

/// Resolve the log/baseline locations, creating directories when necessary.
pub fn log_paths() -> io::Result<PerformanceLogPaths> {
    let base = std::env::var(LOG_ROOT_ENV)
        .map(PathBuf::from)
        .ok()
        .or_else(|| project_dirs().map(|dirs| dirs.data_local_dir().to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("/var/log/lockchain"));

    let root = base.join(LOG_DIR).join(PERF_DIR);
    fs::create_dir_all(&root)?;

    Ok(PerformanceLogPaths {
        root: root.clone(),
        log_file: root.join(LOG_FILE),
        baseline_file: root.join(BASELINE_FILE),
    })
}

/// Append a timing entry for an unlock run and establish a baseline when missing.
pub fn record_unlock_timing(
    dataset: &str,
    duration: Duration,
    success: bool,
    note: Option<String>,
) -> io::Result<RecordedUnlockTiming> {
    let paths = log_paths()?;
    let mut baselines = load_baselines(&paths.baseline_file)?;
    let timestamp_ms = timestamp_ms();
    let duration_ms = duration.as_millis();
    let mut baseline_created = false;

    let baseline_ms = if success {
        match baselines.entry(dataset.to_string()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.get().duration_ms,
            std::collections::hash_map::Entry::Vacant(slot) => {
                baseline_created = true;
                slot.insert(UnlockBaseline {
                    duration_ms,
                    recorded_at_ms: timestamp_ms,
                });
                duration_ms
            }
        }
    } else {
        baselines
            .get(dataset)
            .map(|b| b.duration_ms)
            .unwrap_or(duration_ms)
    };

    let entry = UnlockTimingEntry {
        dataset: dataset.to_string(),
        duration_ms,
        success,
        timestamp_ms,
        baseline_ms,
        delta_ms: duration_ms as i128 - baseline_ms as i128,
        note,
    };

    append_jsonl(&paths.log_file, &entry)?;
    if baseline_created {
        save_baselines(&paths.baseline_file, &baselines)?;
    }

    Ok(RecordedUnlockTiming {
        entry,
        log_path: paths.log_file,
        baseline_path: paths.baseline_file,
        baseline_created,
    })
}

/// Generate a text bundle containing baselines and the raw JSONL log.
pub fn bundle_logs(target_dir: Option<PathBuf>) -> io::Result<PathBuf> {
    let paths = log_paths()?;
    let export_root = target_dir
        .or_else(default_download_dir)
        .unwrap_or_else(|| paths.root.clone());

    fs::create_dir_all(&export_root)?;
    let bundle_path = export_root.join(format!("lockchain-logs-{}.txt", timestamp_ms()));
    let mut bundle = File::create(&bundle_path)?;

    writeln!(
        bundle,
        "# LockChain unlock performance bundle\n# source log: {}\n",
        paths.log_file.display()
    )?;

    if paths.baseline_file.exists() {
        let baselines = fs::read_to_string(&paths.baseline_file)?;
        writeln!(
            bundle,
            "## Baselines ({})\n{}\n",
            paths.baseline_file.display(),
            baselines
        )?;
    } else {
        writeln!(bundle, "## Baselines\nno baselines recorded yet\n")?;
    }

    if paths.log_file.exists() {
        let log = fs::read_to_string(&paths.log_file)?;
        writeln!(
            bundle,
            "## Unlock runs ({})\n{}",
            paths.log_file.display(),
            log
        )?;
    } else {
        writeln!(bundle, "## Unlock runs\nno unlock runs recorded yet")?;
    }

    Ok(bundle_path)
}

fn load_baselines(path: &Path) -> io::Result<HashMap<String, UnlockBaseline>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let data = fs::read_to_string(path)?;
    let parsed: HashMap<String, UnlockBaseline> = serde_json::from_str(&data).unwrap_or_default();
    Ok(parsed)
}

fn save_baselines(path: &Path, baselines: &HashMap<String, UnlockBaseline>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_string_pretty(baselines)?;
    fs::write(path, payload)
}

fn append_jsonl(path: &Path, entry: &UnlockTimingEntry) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(entry)?;
    writeln!(file, "{line}")
}

fn default_download_dir() -> Option<PathBuf> {
    if let Ok(root) = std::env::var(EXPORT_ROOT_ENV) {
        return Some(PathBuf::from(root));
    }

    UserDirs::new().and_then(|dirs| dirs.download_dir().map(|p| p.to_path_buf()))
}

fn timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::ffi::OsString;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Serialize environment mutations to avoid cross-test interference.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = env::var_os(key);
            env::set_var(key, value);
            EnvVarGuard { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(val) => env::set_var(self.key, val),
                None => env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn record_unlock_timing_sets_baseline_once() {
        let tmp = TempDir::new().unwrap();
        let _env_lock = ENV_LOCK.lock().unwrap();
        let _log_root_guard = EnvVarGuard::set(LOG_ROOT_ENV, tmp.path());

        let first = record_unlock_timing("tank/secure", Duration::from_millis(120), true, None)
            .expect("baseline should be recorded");
        assert!(first.baseline_created);
        assert_eq!(first.entry.baseline_ms, 120);
        assert_eq!(first.entry.delta_ms, 0);

        let second = record_unlock_timing("tank/secure", Duration::from_millis(180), true, None)
            .expect("second run should succeed");
        assert!(!second.baseline_created);
        assert_eq!(second.entry.baseline_ms, 120);
        assert_eq!(second.entry.delta_ms, 60);

        let log_contents = fs::read_to_string(&first.log_path).unwrap();
        assert_eq!(log_contents.lines().count(), 2);
    }

    #[test]
    fn bundle_logs_renders_summary() {
        let tmp = TempDir::new().unwrap();
        let _env_lock = ENV_LOCK.lock().unwrap();
        let _log_root_guard = EnvVarGuard::set(LOG_ROOT_ENV, tmp.path());
        let _export_guard = EnvVarGuard::set(EXPORT_ROOT_ENV, tmp.path());

        record_unlock_timing("tank/secure", Duration::from_millis(90), true, None)
            .expect("profiling run");

        let bundle = bundle_logs(None).expect("bundle should be created");
        let content = fs::read_to_string(bundle).expect("read bundle");
        assert!(content.contains("Baselines"));
        assert!(content.contains("Unlock runs"));
    }
}
