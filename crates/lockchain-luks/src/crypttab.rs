//! Minimal `crypttab` parsing and modelling helpers.
//!
//! Parsing stays intentionally small while ADR-003 is in progress. Types are kept close to the
//! provider surface to reduce churn for callers.

use lockchain_core::error::{LockchainError, LockchainResult};

/// One line of `/etc/crypttab`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CrypttabEntry {
    pub name: String,
    pub source: String,
    pub key: Option<String>,
    pub options: Vec<String>,
}

/// Parse a `crypttab` document.
#[allow(dead_code)]
pub fn parse_crypttab(contents: &str) -> LockchainResult<Vec<CrypttabEntry>> {
    let mut entries = Vec::new();

    for (idx, raw_line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = strip_inline_comment(line).trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split_whitespace();
        let name = fields.next().ok_or_else(|| {
            LockchainError::InvalidConfig(format!("crypttab line {line_no} missing mapping name"))
        })?;
        let source = fields.next().ok_or_else(|| {
            LockchainError::InvalidConfig(format!(
                "crypttab line {line_no} missing source device for mapping `{name}`"
            ))
        })?;

        let key = fields.next();
        let options = fields.next();
        if fields.next().is_some() {
            return Err(LockchainError::InvalidConfig(format!(
                "crypttab line {line_no} has unexpected extra fields (mapping `{name}`)"
            )));
        }

        entries.push(CrypttabEntry {
            name: name.to_string(),
            source: source.to_string(),
            key: key.and_then(normalize_key_field),
            options: options
                .map(parse_options_field)
                .unwrap_or_else(|| Vec::new()),
        });
    }

    Ok(entries)
}

fn strip_inline_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

fn normalize_key_field(field: &str) -> Option<String> {
    let trimmed = field.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") || trimmed == "-" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_options_field(field: &str) -> Vec<String> {
    field
        .split(',')
        .map(str::trim)
        .filter(|opt| !opt.is_empty())
        .map(|opt| opt.to_string())
        .collect()
}
