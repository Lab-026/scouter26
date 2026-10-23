use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use colored::*;

use super::ports;

/// How many ports we try at the same time. This is a "worker pool":
/// a fixed team of workers pulling ports from a shared to-do list,
/// instead of hiring (and paying for) one thread per port.
const MAX_WORKERS: usize = 200;

/// How long to wait for a connection before calling a port closed.
const TIMEOUT: Duration = Duration::from_secs(1);

/// The ports scanned when the user does not pick their own.
const DEFAULT_PORTS: [u16; 10] = [22, 23, 25, 53, 80, 110, 143, 443, 445, 3389];

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

/// Turn a hostname or IP string into an IP address.
fn resolve(target: &str) -> Option<IpAddr> {
    // The 0 is a placeholder port - we only want the IP address.
    match (target, 0u16).to_socket_addrs() {
        Ok(mut addresses) => addresses.next().map(|socket_addr| socket_addr.ip()),
        Err(_) => None,
    }
}

pub fn execute(target: &str, ports_arg: &Option<String>) {
    let started_at = Instant::now();

    // 1. Decide which ports to scan.
    let ports: Vec<u16> = match ports_arg {
        Some(spec) => match parse_ports(spec) {
            Ok(ports) => ports,
            Err(message) => {
                eprintln!("{}", format!("Error: {}", message).red().bold());
                eprintln!(
                    "{}",
                    "Examples: --ports 80    --ports 22,80,443    --ports 1-1024".yellow()
                );
                // Exit with code 1 so shell scripts can detect the failure
                std::process::exit(1);
            }
        },
        None => DEFAULT_PORTS.to_vec(),
    };

    // 2. Resolve the hostname ONCE.
    //    (The old code resolved it once per port - scanning a hostname
    //    meant ten identical DNS lookups.)
    let target_ip: IpAddr = match resolve(target) {
        Some(ip) => ip,
        None => {
            eprintln!(
                "{}",
                format!("Error: could not resolve '{}' to an IP address", target)
                    .red()
                    .bold()
            );
            // Exit with code 1 so shell scripts can detect the failure
            std::process::exit(1);
        }
    };

    // If the user gave us a bare IP, don't print "1.2.3.4 (1.2.3.4)".
    let target_label = if target.parse::<IpAddr>().is_ok() {
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

    // 3. The shared to-do list of ports and the shared results list.
    //    Arc   = a pointer that many threads can hold at the same time.
    //    Mutex = a lock so only one thread touches a list at a time.
    let worker_count = MAX_WORKERS.min(ports.len());
    let todo: Arc<Mutex<VecDeque<u16>>> = Arc::new(Mutex::new(VecDeque::from(ports)));
    let open_ports: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));

    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let todo = Arc::clone(&todo);
        let open_ports = Arc::clone(&open_ports);

        workers.push(thread::spawn(move || {
            loop {
                // Take the next port off the to-do list. The { } block ends
                // the borrow immediately, so we never hold the lock while
                // doing network work - that would make workers wait in line.
                let next_port = {
                    match todo.lock() {
                        Ok(mut queue) => queue.pop_front(),
                        Err(_) => return,
                    }
                };

                let port = match next_port {
                    Some(port) => port,
                    None => break, // to-do list is empty - work is done
                };

                let address = SocketAddr::new(target_ip, port);
                if TcpStream::connect_timeout(&address, TIMEOUT).is_ok() {
                    if let Ok(mut results) = open_ports.lock() {
                        results.push(port);
                    }
                }
            }
        }));
    }

    // 4. Wait for every worker to finish.
    for worker in workers {
        if worker.join().is_err() {
            eprintln!("{}", "Warning: a scanner worker exited unexpectedly".yellow());
        }
    }

    // 5. Print the results, sorted.
    let mut results = match open_ports.lock() {
        Ok(results) => results.clone(),
        Err(_) => Vec::new(),
    };
    results.sort_unstable();

    if results.is_empty() {
        println!("{}", " No open ports found.".yellow());
    } else {
        for port in results {
            println!(
                " Port {:<6} {:<10} {}",
                port,
                ports::service_name(port),
                "OPEN".green().bold()
            );
        }
    }

    println!("{}", "========================================".cyan());
    println!(
        "{}",
        format!(" Scan complete in {:.2}s.", started_at.elapsed().as_secs_f32()).cyan()
    );
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
}