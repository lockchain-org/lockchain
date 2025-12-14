//! Lightweight logging bootstrapper shared by every Lockchain binary.

use env_logger::Env;
use serde_json::json;
use std::env;
use std::io::Write;
use std::sync::OnceLock;

static INIT: OnceLock<()> = OnceLock::new();

const FORMAT_ENV: &str = "LOCKCHAIN_LOG_FORMAT";
const LEVEL_ENV: &str = "LOCKCHAIN_LOG_LEVEL";

/// Initialize a global logger for Lockchain binaries.
///
/// The first caller wins; subsequent calls are no-ops. If `RUST_LOG` is
/// unset, the `default_level` argument is used, overridable via
/// `LOCKCHAIN_LOG_LEVEL`. `LOCKCHAIN_LOG_FORMAT` can be set to `plain` to
/// disable JSON output.
pub fn init(default_level: &str) {
    let _ = INIT.get_or_init(|| configure(default_level));
}

fn configure(default_level: &str) {
    let default_level = env::var(LEVEL_ENV).unwrap_or_else(|_| default_level.to_string());
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", &default_level);
    }

    let format = env::var(FORMAT_ENV)
        .unwrap_or_else(|_| String::from("json"))
        .to_lowercase();

    let mut builder = env_logger::Builder::from_env(Env::default());
    if format == "json" {
        builder.format(|buf, record| {
            let ts = buf.timestamp().to_string();
            let payload = json!({
                "timestamp": ts,
                "level": record.level().to_string().to_lowercase(),
                "target": record.target(),
                "message": record.args().to_string(),
            });
            writeln!(buf, "{}", payload)
        });
    } else {
        builder.format(|buf, record| {
            writeln!(
                buf,
                "{} {} {} - {}",
                buf.timestamp(),
                record.level().to_string().to_lowercase(),
                record.target(),
                record.args()
            )
        });
    }

    if let Err(err) = builder.try_init() {
        eprintln!("failed to initialize logger: {}", err);
    }
}
