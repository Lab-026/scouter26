//! Shared helpers used by more than one scouter26 command.

pub mod discover;
pub mod ports;
pub mod scan;
pub mod subnet;
pub mod syn;
pub mod udp;

use std::net::{IpAddr, ToSocketAddrs};

/// The hard ceiling for --workers in the scanning commands. Beyond a few
/// thousand, the threads cost more than they save and local
/// file-descriptor limits start to bite.
pub(crate) const MAX_WORKERS: usize = 2000;

/// Live progress lines are only worth their screen noise on long jobs.
pub(crate) const PROGRESS_THRESHOLD: usize = 100;

/// Turn a hostname or IP string into one IP address (either family).
///
/// A bare IP skips DNS entirely. A hostname that resolves to both
/// families gets its IPv4 address first — the same default nmap uses —
/// unless the user asked for IPv6 with --ipv6. Single-family names
/// simply get whatever they have, so IPv6-only hosts work normally.
pub(crate) fn resolve_target(target: &str, prefer_ipv6: bool) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addrs = match (target, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(_) => return Err(format!("could not resolve '{}' to an IP address", target)),
    };

    let pick = |want_v6: bool| {
        addrs.iter().find_map(|addr| match addr.ip() {
            IpAddr::V6(v6) if want_v6 => Some(IpAddr::V6(v6)),
            IpAddr::V4(v4) if !want_v6 => Some(IpAddr::V4(v4)),
            _ => None,
        })
    };

    pick(prefer_ipv6)
        .or_else(|| pick(!prefer_ipv6))
        .ok_or_else(|| format!("'{}' did not resolve to any usable IP address", target))
}

/// Write a report as pretty JSON to a file (--output).
///
/// Used by every scanning command so the saved format is identical
/// everywhere: what lands on disk is byte-for-byte what --json would
/// have printed.
pub(crate) fn write_report(
    path: &std::path::Path,
    report: &impl serde::Serialize,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|error| format!("could not serialize the report: {}", error))?;
    std::fs::write(path, json + "\n")
        .map_err(|error| format!("could not write '{}': {}", path.display(), error))
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_land_on_disk_as_valid_json() {
        let mut path = std::env::temp_dir();
        path.push(format!("scouter26-test-report-{}.json", std::process::id()));
        #[derive(serde::Serialize)]
        struct Sample {
            tool: String,
            version: u32,
        }
        write_report(
            &path,
            &Sample {
                tool: "scouter26".into(),
                version: 1,
            },
        )
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(value["tool"], "scouter26");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn unwritable_paths_fail_with_a_clear_message() {
        let result = write_report(
            std::path::Path::new("/nonexistent-dir-1964/report.json"),
            &"x",
        );
        assert!(result.is_err());
        let message = result.unwrap_err();
        assert!(
            message.contains("could not write"),
            "message was: {}",
            message
        );
    }
}
