use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use colored::*;
use ipnet::IpNet;

use super::ports;
use super::{parse_ports, unlock, validate_tunables, MAX_WORKERS, PROGRESS_THRESHOLD};
use super::subnet::normalize_cidr;

/// Ports probed on every host when the user does not pick their own —
/// the classic LAN services: SSH, HTTP, HTTPS, SMB, RDP.
const DEFAULT_DISCOVERY_PORTS: [u16; 5] = [22, 80, 443, 445, 3389];

/// Sweeps are capped: probing a whole /16 (65,534 hosts × 5 ports) at one
/// second per probe would take half an hour of silent waiting. 4096 hosts
/// keeps the worst case in minutes — wider networks need a longer prefix.
const MAX_SWEEP_HOSTS: usize = 4096;

/// One (host, port) pair waiting in the shared to-do list.
struct Probe {
    host: IpAddr,
    port: u16,
}

/// All usable host addresses of a network, ascending.
///
/// IPv4 skips the network and broadcast addresses — nothing usable lives
/// there, and probing a broadcast address is impolite. IPv6 skips nothing:
/// it has no broadcast concept, so every address is fair game.
pub fn hosts_in_net(net: IpNet) -> Vec<IpAddr> {
    match net {
        IpNet::V4(v4) => {
            let start = u32::from(v4.network());
            let end = u32::from(v4.broadcast());
            // /31 and /32 have no reserved network/broadcast pair (RFC 3021).
            let (start, end) = if v4.prefix_len() >= 31 {
                (start, end)
            } else {
                (start + 1, end - 1)
            };
            (start..=end).map(Ipv4Addr::from).map(IpAddr::V4).collect()
        }
        IpNet::V6(v6) => {
            let start = u128::from(v6.network());
            let end = u128::from(v6.broadcast());
            (start..=end).map(Ipv6Addr::from).map(IpAddr::V6).collect()
        }
    }
}

/// The verdict of one TCP probe.
///
/// The interesting one is Refused: an RST packet came back, which means a
/// machine is alive and saying "nothing listens here". A host that answers
/// with refusals is just as discovered as one with an open port — this is
/// why TCP discovery finds machines that block ICMP ping.
enum ProbeVerdict {
    Open,
    Refused,
    NoAnswer,
}

fn probe(host: IpAddr, port: u16, timeout: Duration) -> ProbeVerdict {
    let address = SocketAddr::new(host, port);
    match TcpStream::connect_timeout(&address, timeout) {
        Ok(_) => ProbeVerdict::Open,
        Err(error) => match error.kind() {
            std::io::ErrorKind::ConnectionRefused => ProbeVerdict::Refused,
            _ => ProbeVerdict::NoAnswer,
        },
    }
}

/// Sweep hosts × ports with the same worker-pool pattern as `scan`.
/// Returns the alive hosts, ascending, each with its open ports sorted
/// (an empty Vec means: alive, but none of the probed ports were open).
fn sweep(
    hosts: &[IpAddr],
    probe_ports: &[u16],
    timeout: Duration,
    workers: usize,
) -> Vec<(IpAddr, Vec<u16>)> {
    let total_probes = hosts.len() * probe_ports.len();
    let worker_count = workers.clamp(1, MAX_WORKERS).min(total_probes.max(1));

    let todo: Arc<Mutex<VecDeque<Probe>>> = Arc::new(Mutex::new(
        hosts
            .iter()
            .flat_map(|host| probe_ports.iter().map(move |&port| Probe { host: *host, port }))
            .collect(),
    ));

    // host -> its open ports. An entry with an empty Vec is a host that
    // answered with refusals only — alive, but nothing open.
    let alive: Arc<Mutex<HashMap<IpAddr, Vec<u16>>>> = Arc::new(Mutex::new(HashMap::new()));
    let tried = Arc::new(AtomicUsize::new(0));

    let progress_thread = if total_probes >= PROGRESS_THRESHOLD {
        let tried = Arc::clone(&tried);
        Some(thread::spawn(move || {
            while tried.load(Ordering::Relaxed) < total_probes {
                print!(
                    "\r [..] {} / {} probes sent",
                    tried.load(Ordering::Relaxed),
                    total_probes
                );
                let _ = std::io::Write::flush(&mut std::io::stdout());
                thread::sleep(Duration::from_millis(250));
            }
        }))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let todo = Arc::clone(&todo);
        let alive = Arc::clone(&alive);
        let tried = Arc::clone(&tried);

        handles.push(thread::spawn(move || loop {
            let next = todo.lock().unwrap_or_else(unlock).pop_front();
            let task = match next {
                Some(task) => task,
                None => break, // to-do list is empty - work is done
            };

            match probe(task.host, task.port, timeout) {
                ProbeVerdict::Open => {
                    alive
                        .lock()
                        .unwrap_or_else(unlock)
                        .entry(task.host)
                        .or_default()
                        .push(task.port);
                }
                ProbeVerdict::Refused => {
                    alive.lock().unwrap_or_else(unlock).entry(task.host).or_default();
                }
                ProbeVerdict::NoAnswer => {}
            }

            tried.fetch_add(1, Ordering::Relaxed);
        }));
    }

    // Wait for every worker to finish.
    for handle in handles {
        if handle.join().is_err() {
            eprintln!("{}", "Warning: a discovery worker exited unexpectedly".yellow());
        }
    }

    if let Some(progress) = progress_thread {
        progress.join().ok();
        println!("\r [ok] {} / {} probes sent", total_probes, total_probes);
    }

    let mut results: Vec<(IpAddr, Vec<u16>)> = alive
        .lock()
        .unwrap_or_else(unlock)
        .clone()
        .into_iter()
        .collect();
    results.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, open) in results.iter_mut() {
        open.sort_unstable();
    }
    results
}

/// Entry point for `scouter26 discover <cidr>`.
pub fn execute(
    cidr: &str,
    ports_arg: &Option<String>,
    timeout_secs: f64,
    workers: usize,
) -> Result<(), String> {
    let started_at = Instant::now();

    validate_tunables(timeout_secs, workers)?;

    let probe_ports: Vec<u16> = match ports_arg {
        Some(spec) => parse_ports(spec)?,
        None => DEFAULT_DISCOVERY_PORTS.to_vec(),
    };

    let net = IpNet::from_str(&normalize_cidr(cidr)).map_err(|error| {
        format!(
            "invalid CIDR '{}'\nDetails: {}\nExamples: 192.168.1.0/24, 2001:db8::/120",
            cidr, error
        )
    })?;

    let hosts = hosts_in_net(net);
    if hosts.len() > MAX_SWEEP_HOSTS {
        return Err(format!(
            "{} hosts is too wide for a sweep (max {}). Use a longer prefix, e.g. /24.",
            hosts.len(),
            MAX_SWEEP_HOSTS
        ));
    }

    let total_probes = hosts.len() * probe_ports.len();
    let port_list = probe_ports
        .iter()
        .map(|p| format!("{} ({})", p, ports::service_name(*p)))
        .collect::<Vec<_>>()
        .join(", ");

    println!("{}", "========================================".cyan());
    println!("{}", " Scouter26 - Host Discovery".cyan().bold());
    println!(" {}{}", "Network:     ".cyan(), net.to_string().cyan());
    println!(" {}{}", "Hosts:       ".cyan(), hosts.len().to_string().cyan());
    println!(" {}{}", "Probe ports: ".cyan(), port_list.cyan());
    println!(" {}{}", "Total probes:".cyan(), format!(" {}", total_probes).cyan());
    println!("{}", "----------------------------------------".cyan());
    println!(
        "{}",
        " [!] Only scan networks you own or have permission to scan.".yellow()
    );

    let results = sweep(
        &hosts,
        &probe_ports,
        Duration::from_secs_f64(timeout_secs),
        workers,
    );

    println!("{}", "========================================".cyan());
    if results.is_empty() {
        println!("{}", " No live hosts found.".yellow());
    } else {
        for (host, open) in &results {
            let label = host.to_string();
            if open.is_empty() {
                println!(
                    " {:<39} {}  {}",
                    label.green().bold(),
                    "ALIVE".green(),
                    "(answered, but no open ports)".dimmed()
                );
            } else {
                let port_list = open
                    .iter()
                    .map(|p| format!("{} ({})", p, ports::service_name(*p)))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    " {:<39} {}  {}",
                    label.green().bold(),
                    "ALIVE".green().bold(),
                    port_list.dimmed()
                );
            }
        }
    }
    println!("{}", "========================================".cyan());
    println!(
        "{}",
        format!(
            " Found {} live host(s) out of {} probed in {:.2}s.",
            results.len(),
            hosts.len(),
            started_at.elapsed().as_secs_f32()
        )
        .cyan()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn host_enumeration_v4_skips_network_and_broadcast() {
        let net = IpNet::from_str("192.168.1.0/24").unwrap();
        let hosts = hosts_in_net(net);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts[253], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)));
    }

    #[test]
    fn host_enumeration_small_prefixes() {
        // /30: two usable hosts
        let hosts = hosts_in_net(IpNet::from_str("10.0.0.0/30").unwrap());
        assert_eq!(hosts.len(), 2);

        // /31 point-to-point (RFC 3021): both addresses are usable
        let hosts = hosts_in_net(IpNet::from_str("10.0.0.0/31").unwrap());
        assert_eq!(hosts.len(), 2);

        // /32: a single host
        let hosts = hosts_in_net(IpNet::from_str("10.0.0.7/32").unwrap());
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn host_enumeration_v6_includes_everything() {
        let hosts = hosts_in_net(IpNet::from_str("2001:db8::/126").unwrap());
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0], IpAddr::V6("2001:db8::".parse().unwrap()));
        assert_eq!(hosts[3], IpAddr::V6("2001:db8::3".parse().unwrap()));
    }

    #[test]
    fn sweep_finds_a_real_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();

        let results = sweep(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[open_port],
            Duration::from_millis(300),
            2,
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(results[0].1, vec![open_port]);
    }

    #[test]
    fn a_refused_port_still_marks_the_host_alive() {
        // Reserve a port, then release it: connecting to it now produces
        // a refusal, and a refusal is proof of life.
        let handle = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = handle.local_addr().unwrap().port();
        drop(handle);

        let results = sweep(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[closed_port],
            Duration::from_millis(300),
            2,
        );

        assert_eq!(results.len(), 1, "the host must be found alive");
        assert!(results[0].1.is_empty(), "but the port must not count as open");
    }
}
