//! Shared helpers used by more than one scouter26 command.

pub mod discover;
pub mod ports;
pub mod scan;
pub mod subnet;

/// The hard ceiling for --workers in the scanning commands. Beyond a few
/// thousand, the threads cost more than they save and local
/// file-descriptor limits start to bite.
pub(crate) const MAX_WORKERS: usize = 2000;

/// Live progress lines are only worth their screen noise on long jobs.
pub(crate) const PROGRESS_THRESHOLD: usize = 100;

/// A lock() only fails when a thread panicked while holding it
/// ("poisoned"). The data itself is still fine, so recover it instead of
/// silently dropping results. Generic so every mutex in this crate can use it.
pub(crate) fn unlock<T>(
    poisoned: std::sync::PoisonError<std::sync::MutexGuard<'_, T>>,
) -> std::sync::MutexGuard<'_, T> {
    poisoned.into_inner()
}

/// Validate the tunables shared by the scanning commands (--timeout in
/// seconds, --workers in threads).
pub(crate) fn validate_tunables(timeout_secs: f64, workers: usize) -> Result<(), String> {
    if !(0.05..=60.0).contains(&timeout_secs) {
        return Err("timeout must be between 0.05 and 60 seconds".to_string());
    }
    if workers == 0 || workers > MAX_WORKERS {
        return Err(format!("workers must be between 1 and {}", MAX_WORKERS));
    }
    Ok(())
}

/// Parse a port specification: "80", "22,80,443", or "1-1024".
/// Returns a sorted list with no duplicates.
/// (Shared by `scan` and `discover`.)
pub(crate) fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start_str, end_str)) = part.split_once('-') {
            let start: u16 = start_str
                .trim()
                .parse()
                .map_err(|_| format!("'{}' is not a valid port", start_str.trim()))?;
            let end: u16 = end_str
                .trim()
                .parse()
                .map_err(|_| format!("'{}' is not a valid port", end_str.trim()))?;
            if start == 0 || end == 0 {
                return Err("Port 0 is reserved and cannot be scanned".to_string());
            }
            if start > end {
                return Err(format!(
                    "Range {}-{} is backwards. Did you mean {}-{}?",
                    start, end, end, start
                ));
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("'{}' is not a valid port", part))?;
            if port == 0 {
                return Err("Port 0 is reserved and cannot be scanned".to_string());
            }
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err("No valid ports were given".to_string());
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}
