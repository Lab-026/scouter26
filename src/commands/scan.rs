use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use colored::*;

use super::ports;

/// One scan result: a port number plus whatever banner the service
/// announced (None when it stayed quiet).
type ScanResult = (u16, Option<String>);

/// The hard ceiling for --workers. Beyond a few thousand, the threads cost
/// more than they save and local file-descriptor limits start to bite.
const MAX_WORKERS: usize = 2000;

/// How long to wait for a banner after connecting, and how much of it to keep.
/// Short on purpose: this is a bonus, not a reason to slow the scan down.
const BANNER_TIMEOUT: Duration = Duration::from_millis(400);
const BANNER_MAX_BYTES: usize = 128;
const BANNER_MAX_CHARS: usize = 80;

/// The ports scanned when the user does not pick their own.
const DEFAULT_PORTS: [u16; 10] = [22, 23, 25, 53, 80, 110, 143, 443, 445, 3389];

/// Live progress is only worth its screen noise on long scans.
const PROGRESS_THRESHOLD: usize = 100;

/// Parse a port specification: "80", "22,80,443", or "1-1024".
/// Returns a sorted list with no duplicates.
fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
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

/// Turn a hostname or IP string into one IPv4 address.
///
/// scouter26 is an IPv4 tool (the `subnet` command rejects IPv6 too), so
/// AAAA answers are deliberately skipped. A bare IP skips DNS entirely;
/// a name that only resolves to IPv6 gets a clear error instead of being
/// scanned over the wrong protocol family.
fn resolve_ipv4(target: &str) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    let addrs = match (target, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(_) => return Err(format!("could not resolve '{}' to an IP address", target)),
    };

    addrs
        .iter()
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            format!(
                "'{}' only resolves to IPv6 addresses, and scouter26 scans IPv4 only",
                target
            )
        })
}

/// After a successful connect, some services announce themselves
/// immediately (SSH, FTP, SMTP...). Read whatever arrives within
/// BANNER_TIMEOUT; silence is normal — HTTP waits for a request first —
/// and simply returns None.
fn grab_banner(mut stream: TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(BANNER_TIMEOUT)).ok()?;
    let mut buf = [0u8; BANNER_MAX_BYTES];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let text = sanitize_banner(&buf[..n]);
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Keep only printable ASCII and stop at the first control character,
/// then cap the length — banners go straight to the terminal.
fn sanitize_banner(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| (0x20..0x7f).contains(&b))
        .map(|&b| b as char)
        .collect::<String>()
        .trim_end()
        .chars()
        .take(BANNER_MAX_CHARS)
        .collect()
}

/// A lock() only fails when a thread panicked while holding it
/// ("poisoned"). The data itself is still fine, so recover it instead of
/// silently dropping results. Generic so every mutex in this file can use it.
fn unlock<T>(poisoned: std::sync::PoisonError<std::sync::MutexGuard<'_, T>>) -> std::sync::MutexGuard<'_, T> {
    poisoned.into_inner()
}

/// Probe the given ports on one IPv4 address and return the open ones
/// (sorted, each with whatever banner the service announced).
///
/// Pure worker: no printing except the progress line, so it can be
/// unit-tested against a real local listener.
fn scan_ports(
    target: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
    workers: usize,
) -> Vec<ScanResult> {
    let worker_count = workers.clamp(1, MAX_WORKERS).min(ports.len().max(1));
    let total = ports.len();

    // The shared to-do list of ports and the shared results list.
    // Arc   = a pointer that many threads can hold at the same time.
    // Mutex = a lock so only one thread touches a list at a time.
    let todo: Arc<Mutex<VecDeque<u16>>> = Arc::new(Mutex::new(ports.iter().copied().collect()));
    let open_ports: Arc<Mutex<Vec<ScanResult>>> = Arc::new(Mutex::new(Vec::new()));
    let tried = Arc::new(AtomicUsize::new(0));

    // Live progress for long scans: one line, updated in place with \r.
    // The loop re-checks `tried` after every sleep, so it always stops
    // once the last port has been attempted.
    let progress_thread = if total >= PROGRESS_THRESHOLD {
        let tried = Arc::clone(&tried);
        Some(thread::spawn(move || {
            while tried.load(Ordering::Relaxed) < total {
                print!("\r [..] {} / {} ports tried", tried.load(Ordering::Relaxed), total);
                let _ = std::io::stdout().flush();
                thread::sleep(Duration::from_millis(250));
            }
        }))
    } else {
        None
    };

    let mut workers_handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let todo = Arc::clone(&todo);
        let open_ports = Arc::clone(&open_ports);
        let tried = Arc::clone(&tried);

        workers_handles.push(thread::spawn(move || loop {
            // Take the next port off the to-do list. The statement ends
            // the borrow immediately, so we never hold the lock while
            // doing network work - that would make workers wait in line.
            let next_port = todo.lock().unwrap_or_else(unlock).pop_front();

            let port = match next_port {
                Some(port) => port,
                None => break, // to-do list is empty - work is done
            };

            let address = SocketAddr::from((target, port));
            if let Ok(stream) = TcpStream::connect_timeout(&address, timeout) {
                let banner = grab_banner(stream);
                open_ports
                    .lock()
                    .unwrap_or_else(unlock)
                    .push((port, banner));
            }

            tried.fetch_add(1, Ordering::Relaxed);
        }));
    }

    // Wait for every worker to finish.
    for worker in workers_handles {
        if worker.join().is_err() {
            eprintln!("{}", "Warning: a scanner worker exited unexpectedly".yellow());
        }
    }

    if let Some(progress) = progress_thread {
        progress.join().ok();
        println!("\r [ok] {} / {} ports tried", total, total);
    }

    let mut results = open_ports.lock().unwrap_or_else(unlock).clone();
    results.sort_unstable_by_key(|entry| entry.0);
    results
}

pub fn execute(
    target: &str,
    ports_arg: &Option<String>,
    timeout_secs: f64,
    workers: usize,
) -> Result<(), String> {
    let started_at = std::time::Instant::now();

    // 1. Validate the tunables before anything touches the network.
    if !(0.05..=60.0).contains(&timeout_secs) {
        return Err("timeout must be between 0.05 and 60 seconds".to_string());
    }
    if workers == 0 || workers > MAX_WORKERS {
        return Err(format!("workers must be between 1 and {}", MAX_WORKERS));
    }

    // 2. Decide which ports to scan.
    let ports: Vec<u16> = match ports_arg {
        Some(spec) => parse_ports(spec).map_err(|message| {
            format!(
                "{}\nExamples: --ports 80, --ports 22,80,443, --ports 1-1024",
                message
            )
        })?,
        None => DEFAULT_PORTS.to_vec(),
    };

    // 3. Resolve the hostname ONCE, IPv4 only.
    let target_ip = resolve_ipv4(target)?;

    // If the user gave us a bare IP, don't print "1.2.3.4 (1.2.3.4)".
    let target_label = if target.parse::<Ipv4Addr>().is_ok() {
        target.to_string()
    } else {
        format!("{} ({})", target, target_ip)
    };

    println!("{}", "========================================".cyan());
    println!("{}", " Scouter26 - Port Scanner".cyan().bold());
    println!(" {}{}", "Target: ".cyan(), target_label.cyan());
    println!(" {}{}", "Ports:  ".cyan(), ports.len().to_string().cyan());
    println!("{}", "----------------------------------------".cyan());
    println!(
        "{}",
        " [!] Only scan hosts you own or have permission to scan.".yellow()
    );

    // 4. Scan. Progress (if any) is handled inside scan_ports.
    let results = scan_ports(
        target_ip,
        &ports,
        Duration::from_secs_f64(timeout_secs),
        workers,
    );

    // 5. Print the results, sorted.
    if results.is_empty() {
        println!("{}", " No open ports found.".yellow());
    } else {
        for (port, banner) in results {
            let banner_text = banner
                .map(|text| format!("  {}", text.dimmed()))
                .unwrap_or_default();
            println!(
                " Port {:<6} {:<10} {}{}",
                port,
                ports::service_name(port),
                "OPEN".green().bold(),
                banner_text
            );
        }
    }

    println!("{}", "========================================".cyan());
    println!(
        "{}",
        format!(" Scan complete in {:.2}s.", started_at.elapsed().as_secs_f32()).cyan()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_port() {
        assert_eq!(parse_ports("80"), Ok(vec![80]));
    }

    #[test]
    fn comma_separated_list() {
        assert_eq!(parse_ports("22,80,443"), Ok(vec![22, 80, 443]));
    }

    #[test]
    fn range() {
        assert_eq!(parse_ports("1-5"), Ok(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn list_and_range_mixed() {
        assert_eq!(parse_ports("22, 80, 100-102"), Ok(vec![22, 80, 100, 101, 102]));
    }

    #[test]
    fn duplicates_are_removed() {
        assert_eq!(parse_ports("80,80,80"), Ok(vec![80]));
    }

    #[test]
    fn port_zero_is_rejected() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("0-10").is_err());
    }

    #[test]
    fn backwards_range_is_rejected() {
        assert!(parse_ports("100-50").is_err());
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse_ports("banana").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn bare_ipv4_resolves_without_dns() {
        assert_eq!(resolve_ipv4("127.0.0.1"), Ok(Ipv4Addr::LOCALHOST));
        assert_eq!(resolve_ipv4("192.168.1.1"), Ok(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn banners_are_sanitized() {
        // Stops at the first control character (the newline here).
        assert_eq!(sanitize_banner(b"SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6");
        // Binary garbage becomes an empty string.
        assert_eq!(sanitize_banner(&[0x01, 0x02, 0x03]), "");
        // Long banners are capped.
        let long = vec![b'x'; 500];
        assert_eq!(sanitize_banner(&long).len(), BANNER_MAX_CHARS);
    }

    #[test]
    fn finds_a_real_listening_port_and_skips_closed_ones() {
        // Bind a real listener on a random free port, and reserve a port
        // we then release so we know it is (almost certainly) closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();

        let closed_handle = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed_handle.local_addr().unwrap().port();
        drop(closed_handle);

        let results = scan_ports(
            Ipv4Addr::LOCALHOST,
            &[open_port, closed_port],
            Duration::from_millis(300),
            2,
        );

        let open: Vec<u16> = results.iter().map(|(port, _)| *port).collect();
        assert!(open.contains(&open_port), "the listening port must be found open");
        assert!(!open.contains(&closed_port), "the released port must be closed");
    }
}
