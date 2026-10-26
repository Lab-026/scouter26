use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use colored::*;
use std::path::PathBuf;

use super::ports;
use super::{
    MAX_WORKERS, PROGRESS_THRESHOLD, atomic_bool, parse_ports, resolve_target, unlock,
    validate_tunables,
};

/// One scan result: a port number plus whatever banner the service
/// announced (None when it stayed quiet).
type ScanResult = (u16, Option<String>);

// ============================================================
// The JSON report (--json). Serde turns these structs into JSON;
// the field names become the keys machines will read.
// ============================================================

#[derive(serde::Serialize)]
struct PortFinding {
    port: u16,
    service: String,
    banner: Option<String>,
}

#[derive(serde::Serialize)]
struct ScanReport {
    target: String,
    resolved_ip: IpAddr,
    ports_probed: usize,
    timeout_seconds: f64,
    workers: usize,
    duration_seconds: f32,
    open_ports: Vec<PortFinding>,
}

/// How long to wait for a banner after connecting, and how much of it to keep.
/// Short on purpose: this is a bonus, not a reason to slow the scan down.
const BANNER_TIMEOUT: Duration = Duration::from_millis(400);
const BANNER_MAX_BYTES: usize = 128;
const BANNER_MAX_CHARS: usize = 80;

/// The ports scanned when the user does not pick their own.
/// (Shared with the SYN scanner, which defaults to the same list.)
pub(crate) const DEFAULT_PORTS: [u16; 10] = [22, 23, 25, 53, 80, 110, 143, 443, 445, 3389];

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
    if text.is_empty() { None } else { Some(text) }
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

/// Probe the given ports on one IP address (IPv4 or IPv6) and return
/// the open ones (sorted, each with whatever banner the service
/// announced).
///
/// Pure worker: no printing except the progress line, so it can be
/// unit-tested against a real local listener.
fn scan_ports(
    target: IpAddr,
    ports: &[u16],
    timeout: Duration,
    workers: usize,
    show_progress: bool,
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
    // The loop stops when every port has been dispatched, or the moment
    // the workers are declared finished — whichever comes first. (A
    // worker that panics mid-probe must not strand this line forever.)
    let finished = Arc::new(atomic_bool());
    let progress_thread = if show_progress && total >= PROGRESS_THRESHOLD {
        let tried = Arc::clone(&tried);
        let finished = Arc::clone(&finished);
        Some(thread::spawn(move || {
            while !finished.load(Ordering::Relaxed) && tried.load(Ordering::Relaxed) < total {
                print!(
                    "\r [..] {} / {} ports tried",
                    tried.load(Ordering::Relaxed),
                    total
                );
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

        workers_handles.push(thread::spawn(move || {
            loop {
                // Take the next port off the to-do list. The statement ends
                // the borrow immediately, so we never hold the lock while
                // doing network work - that would make workers wait in line.
                let next_port = todo.lock().unwrap_or_else(unlock).pop_front();

                let port = match next_port {
                    Some(port) => port,
                    None => break, // to-do list is empty - work is done
                };

                // Counted as dispatched the moment it leaves the queue: a
                // worker that panics mid-probe must not strand the progress
                // line waiting for a count that can never complete.
                tried.fetch_add(1, Ordering::Relaxed);

                let address = SocketAddr::from((target, port));
                if let Ok(stream) = TcpStream::connect_timeout(&address, timeout) {
                    let banner = grab_banner(stream);
                    open_ports
                        .lock()
                        .unwrap_or_else(unlock)
                        .push((port, banner));
                }
            }
        }));
    }

    // Wait for every worker to finish, then release the progress thread.
    for worker in workers_handles {
        if worker.join().is_err() {
            eprintln!(
                "{}",
                "Warning: a scanner worker exited unexpectedly".yellow()
            );
        }
    }
    finished.store(true, Ordering::Relaxed);

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
    prefer_ipv6: bool,
    json: bool,
    output: &Option<PathBuf>,
) -> Result<(), String> {
    let started_at = std::time::Instant::now();

    // 1. Validate the tunables before anything touches the network.
    validate_tunables(timeout_secs, workers)?;

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

    // 3. Resolve the hostname ONCE, IPv4 by default, --ipv6 to switch.
    let target_ip = resolve_target(target, prefer_ipv6)?;

    // If the user gave us a bare IP, don't print "1.2.3.4 (1.2.3.4)".
    let target_label = if target.parse::<IpAddr>().is_ok() {
        target.to_string()
    } else {
        format!("{} ({})", target, target_ip)
    };

    // The permission warning goes to stderr in JSON mode so a pipeline
    // reading stdout never sees anything but the report itself.
    if json {
        eprintln!(
            "{}",
            " [!] Only scan hosts you own or have permission to scan.".yellow()
        );
    } else {
        println!("{}", "========================================".cyan());
        println!("{}", " Scouter26 - Port Scanner".cyan().bold());
        println!(" {}{}", "Target: ".cyan(), target_label.cyan());
        println!(" {}{}", "Ports:  ".cyan(), ports.len().to_string().cyan());
        println!("{}", "----------------------------------------".cyan());
        println!(
            "{}",
            " [!] Only scan hosts you own or have permission to scan.".yellow()
        );
    }

    // 4. Scan. Progress (if any) is handled inside scan_ports, and is
    //    suppressed in JSON mode so machines get a clean pipe.
    let results = scan_ports(
        target_ip,
        &ports,
        Duration::from_secs_f64(timeout_secs),
        workers,
        !json,
    );

    // 5. Report: JSON for machines, the banner table for humans.
    // Report: JSON for machines, the banner table for humans — and a
    // saved copy on disk whenever --output asks for one.
    if json || output.is_some() {
        let report = ScanReport {
            target: target.to_string(),
            resolved_ip: target_ip,
            ports_probed: ports.len(),
            timeout_seconds: timeout_secs,
            workers,
            duration_seconds: started_at.elapsed().as_secs_f32(),
            open_ports: results
                .iter()
                .map(|(port, banner)| PortFinding {
                    port: *port,
                    service: ports::service_name(*port).to_string(),
                    banner: banner.clone(),
                })
                .collect(),
        };
        if let Some(path) = output {
            super::write_report(path, &report)?;
            eprintln!("{}", format!(" Report saved to {}", path.display()).cyan());
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("ScanReport always serializes")
            );
            return Ok(());
        }
    }

    if results.is_empty() {
        println!("{}", " No open ports found.".yellow());
    } else {
        for (port, banner) in &results {
            let banner_text = banner
                .as_ref()
                .map(|text| format!("  {}", text.dimmed()))
                .unwrap_or_default();
            println!(
                " Port {:<6} {:<10} {}{}",
                port,
                ports::service_name(*port),
                "OPEN".green().bold(),
                banner_text
            );
        }
    }

    println!("{}", "========================================".cyan());
    println!(
        "{}",
        format!(
            " Scan complete in {:.2}s.",
            started_at.elapsed().as_secs_f32()
        )
        .cyan()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
        assert_eq!(
            parse_ports("22, 80, 100-102"),
            Ok(vec![22, 80, 100, 101, 102])
        );
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
    fn bare_ips_resolve_without_dns() {
        assert_eq!(
            resolve_target("127.0.0.1", false),
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            resolve_target("::1", true),
            Ok(IpAddr::V6("::1".parse().unwrap()))
        );
        assert!(resolve_target("not_a_host", false).is_err());
    }

    #[test]
    fn banners_are_sanitized() {
        // Stops at the first control character (the newline here).
        assert_eq!(
            sanitize_banner(b"SSH-2.0-OpenSSH_9.6\r\n"),
            "SSH-2.0-OpenSSH_9.6"
        );
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
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[open_port, closed_port],
            Duration::from_millis(300),
            2,
            false,
        );

        let open: Vec<u16> = results.iter().map(|(port, _)| *port).collect();
        assert!(
            open.contains(&open_port),
            "the listening port must be found open"
        );
        assert!(
            !open.contains(&closed_port),
            "the released port must be closed"
        );
    }

    #[test]
    fn finds_a_real_listening_port_over_ipv6() {
        // Same idea on the IPv6 loopback — the whole point of Phase 11.
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();

        let results = scan_ports(
            IpAddr::V6("::1".parse().unwrap()),
            &[open_port],
            Duration::from_millis(300),
            2,
            false,
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, open_port);
    }

    #[test]
    fn scan_report_serializes_to_json() {
        let report = ScanReport {
            target: "example.test".to_string(),
            resolved_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ports_probed: 2,
            timeout_seconds: 1.0,
            workers: 200,
            duration_seconds: 0.5,
            open_ports: vec![PortFinding {
                port: 22,
                service: "ssh".to_string(),
                banner: Some("SSH-2.0-Test".to_string()),
            }],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["target"], "example.test");
        assert_eq!(value["resolved_ip"], "192.0.2.1");
        assert_eq!(value["open_ports"][0]["port"], 22);
        assert_eq!(value["open_ports"][0]["service"], "ssh");
        assert_eq!(value["open_ports"][0]["banner"], "SSH-2.0-Test");
    }
}
