//! Helpers for turning `zfs` and `zpool` CLI output into data structures the
//! rest of the crate can reason about.

/// Turn `-H -o name,value` style command output into name/value pairs.
pub(crate) fn parse_tabular_pairs(output: &str) -> Vec<(String, String)> {
    output.lines().filter_map(parse_pair_line).collect()
}

/// Normalize a single line from the CLI into a `(name, value)` pair if possible.
fn parse_pair_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((left, right)) = trimmed.split_once('\t') {
        let name = left.trim();
        if name.is_empty() {
            return None;
        }
        return Some((name.to_string(), right.trim().to_string()));
    }

    let mut parts = trimmed.split_whitespace();
    let name = parts.next()?.trim();
    let value = parts.next()?.trim();
    if name.is_empty() {
        return None;
    }

    let rest = parts.collect::<Vec<_>>();
    if !rest.is_empty() {
        // Preserve the remaining columns by stitching them back so the value
        // matches the unstructured formatting the CLI emitted.
        let mut combined = String::from(value);
        for extra in rest {
            combined.push(' ');
            combined.push_str(extra);
        }
        return Some((name.to_string(), combined));
    }

    Some((name.to_string(), value.to_string()))
}

/// Peel off the pool name prefix from a dataset identifier.
pub(crate) fn pool_from_dataset(dataset: &str) -> Option<&str> {
    let candidate = dataset.split('/').next()?;
    if candidate.is_empty() {
        None
    } else {
        Some(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tabular_pairs_handles_tabs() {
        let out = "pool/ds\tpool\npool/ds/child\tpool\n";
        let parsed = parse_tabular_pairs(out);
        assert_eq!(
            parsed,
            vec![
                ("pool/ds".to_string(), "pool".to_string()),
                ("pool/ds/child".to_string(), "pool".to_string())
            ]
        );
    }

    #[test]
    fn parse_tabular_pairs_handles_spaces() {
        let out = "pool ONLINE\n";
        let parsed = parse_tabular_pairs(out);
        assert_eq!(parsed, vec![("pool".to_string(), "ONLINE".to_string())]);
    }

    #[test]
    fn pool_from_dataset_extracts_pool() {
        assert_eq!(pool_from_dataset("tank/secure"), Some("tank"));
        assert_eq!(pool_from_dataset("tank"), Some("tank"));
        assert_eq!(pool_from_dataset("/invalid"), None);
    }
}
