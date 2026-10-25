use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use colored::*;
use ipnet::IpNet;
use std::path::PathBuf;

use super::ports;
use super::subnet::normalize_cidr;
use super::{MAX_WORKERS, PROGRESS_THRESHOLD, parse_ports, unlock, validate_tunables};

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

/// How many hosts a network holds, computed from the prefix length alone —
/// no memory allocated. This is what makes the sweep cap check safe to run
/// BEFORE generating anything: counting a /0 must never cost 137 GB.
fn count_hosts(net: IpNet) -> u128 {
    match net {
        IpNet::V4(v4) => {
            let prefix = v4.prefix_len();
            if prefix >= 32 {
                1
            } else if prefix == 31 {
                2
            } else {
                (super::subnet::total_addresses(prefix) - 2) as u128
            }
        }
        IpNet::V6(v6) => {
            let prefix = v6.prefix_len();
            if prefix >= 128 {
                1
            } else if prefix == 0 {
                u128::MAX // 2^128 does not fit; saturate — any cap rejects it
            } else {
                1u128 << (128 - prefix)
            }
        }
    }
}

/// The gate every sweep passes through: count first, refuse anything
/// wider than the cap, and only then materialise the address list.
pub(crate) fn plan_hosts(net: IpNet) -> Result<Vec<IpAddr>, String> {
    let count = count_hosts(net);
    if count > MAX_SWEEP_HOSTS as u128 {
        return Err(format!(
            "{} hosts is too wide for a sweep (max {}). Use a longer prefix, e.g. /24.",
            super::subnet::group_digits(&count.to_string()),
            MAX_SWEEP_HOSTS
        ));
    }
    Ok(hosts_in_net(net))
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
    show_progress: bool,
) -> Vec<(IpAddr, Vec<u16>)> {
    let total_probes = hosts.len() * probe_ports.len();
    let worker_count = workers.clamp(1, MAX_WORKERS).min(total_probes.max(1));

    let todo: Arc<Mutex<VecDeque<Probe>>> = Arc::new(Mutex::new(
        hosts
            .iter()
            .flat_map(|host| {
                probe_ports
                    .iter()
                    .map(move |&port| Probe { host: *host, port })
            })
            .collect(),
    ));

    // host -> its open ports. An entry with an empty Vec is a host that
    // answered with refusals only — alive, but nothing open.
    let alive: Arc<Mutex<HashMap<IpAddr, Vec<u16>>>> = Arc::new(Mutex::new(HashMap::new()));
    let tried = Arc::new(AtomicUsize::new(0));

    let progress_thread = if show_progress && total_probes >= PROGRESS_THRESHOLD {
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

        handles.push(thread::spawn(move || {
            loop {
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
                        alive
                            .lock()
                            .unwrap_or_else(unlock)
                            .entry(task.host)
                            .or_default();
                    }
                    ProbeVerdict::NoAnswer => {}
                }

                tried.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Wait for every worker to finish.
    for handle in handles {
        if handle.join().is_err() {
            eprintln!(
                "{}",
                "Warning: a discovery worker exited unexpectedly".yellow()
            );
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
    results.sort_by_key(|result| result.0);
    for (_, open) in results.iter_mut() {
        open.sort_unstable();
    }
    results
}

// ============================================================
// The JSON report (--json). Serde turns these structs into JSON;
// the field names become the keys machines will read. An entry in
// live_hosts with an empty open_ports list is a host that answered
// with refusals only — alive, but nothing open.
// ============================================================

#[derive(serde::Serialize)]
struct HostFinding {
    ip: IpAddr,
    open_ports: Vec<u16>,
}

#[derive(serde::Serialize)]
struct DiscoverReport {
    network: String,
    hosts_probed: usize,
    probed_ports: Vec<u16>,
    duration_seconds: f32,
    live_hosts: Vec<HostFinding>,
}

/// Entry point for `scouter26 discover <cidr>`.
pub fn execute(
    cidr: &str,
    ports_arg: &Option<String>,
    timeout_secs: f64,
    workers: usize,
    json: bool,
    output: &Option<PathBuf>,
) -> Result<(), String> {
    let started_at = Instant::now();

    validate_tunables(timeout_secs, workers)?;

    let probe_ports: Vec<u16> = match ports_arg {
        Some(spec) => parse_ports(spec).map_err(|message| {
            format!(
                "{}\nExamples: --ports 80, --ports 22,80,443, --ports 1-1024",
                message
            )
        })?,
        None => DEFAULT_DISCOVERY_PORTS.to_vec(),
    };

    let net = IpNet::from_str(&normalize_cidr(cidr)).map_err(|error| {
        format!(
            "invalid CIDR '{}'\nDetails: {}\nExamples: 192.168.1.0/24, 2001:db8::/120",
            cidr, error
        )
    })?;

    let hosts = plan_hosts(net)?;
    let total_probes = hosts.len() * probe_ports.len();
    let port_list = probe_ports
        .iter()
        .map(|p| format!("{} ({})", p, ports::service_name(*p)))
        .collect::<Vec<_>>()
        .join(", ");

    // The permission warning goes to stderr in JSON mode so a pipeline
    // reading stdout never sees anything but the report itself.
    if json {
        eprintln!(
            "{}",
            " [!] Only scan networks you own or have permission to scan.".yellow()
        );
    } else {
        println!("{}", "========================================".cyan());
        println!("{}", " Scouter26 - Host Discovery".cyan().bold());
        println!(" {}{}", "Network:     ".cyan(), net.to_string().cyan());
        println!(
            " {}{}",
            "Hosts:       ".cyan(),
            hosts.len().to_string().cyan()
        );
        println!(" {}{}", "Probe ports: ".cyan(), port_list.cyan());
        println!(
            " {}{}",
            "Total probes:".cyan(),
            format!(" {}", total_probes).cyan()
        );
        println!("{}", "----------------------------------------".cyan());
        println!(
            "{}",
            " [!] Only scan networks you own or have permission to scan.".yellow()
        );
    }

    let results = sweep(
        &hosts,
        &probe_ports,
        Duration::from_secs_f64(timeout_secs),
        workers,
        !json,
    );

    // Report: JSON for machines, the human table otherwise — and a saved
    // copy on disk whenever --output asks for one (the same JSON either
    // way, so scripts and archives always agree).
    if json || output.is_some() {
        let report = DiscoverReport {
            network: net.to_string(),
            hosts_probed: hosts.len(),
            probed_ports: probe_ports,
            duration_seconds: started_at.elapsed().as_secs_f32(),
            live_hosts: results
                .iter()
                .map(|(ip, open_ports)| HostFinding {
                    ip: *ip,
                    open_ports: open_ports.clone(),
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
                serde_json::to_string_pretty(&report).expect("DiscoverReport always serializes")
            );
            return Ok(());
        }
    }

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
            false,
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
            false,
        );

        assert_eq!(results.len(), 1, "the host must be found alive");
        assert!(
            results[0].1.is_empty(),
            "but the port must not count as open"
        );
    }

    #[test]
    fn discover_report_serializes_to_json() {
        let report = DiscoverReport {
            network: "192.168.1.0/24".to_string(),
            hosts_probed: 254,
            probed_ports: vec![22, 80],
            duration_seconds: 6.4,
            live_hosts: vec![HostFinding {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                open_ports: vec![80],
            }],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["network"], "192.168.1.0/24");
        assert_eq!(value["hosts_probed"], 254);
        assert_eq!(value["live_hosts"][0]["ip"], "192.168.1.1");
        assert_eq!(value["live_hosts"][0]["open_ports"][0], 80);
    }

    #[test]
    fn host_counts_come_from_prefix_math_alone() {
        // No memory is allocated to answer these — that is the point.
        assert_eq!(
            count_hosts(IpNet::from_str("0.0.0.0/0").unwrap()),
            4_294_967_294
        );
        assert_eq!(count_hosts(IpNet::from_str("2001:db8::/120").unwrap()), 256);
    }

    #[test]
    fn the_sweep_cap_is_enforced_before_generation() {
        // Regression guards for the memory bug: these must be refused
        // BEFORE any address is materialised. Generating 4 billion IPs
        // (a /4... or a /0) to then refuse them would exhaust memory first.
        assert!(plan_hosts(IpNet::from_str("192.168.0.0/16").unwrap()).is_err());
        assert!(plan_hosts(IpNet::from_str("2001:db8::/64").unwrap()).is_err());
        assert!(plan_hosts(IpNet::from_str("2001:db8::/0").unwrap()).is_err());
        // Small networks pass through untouched.
        assert_eq!(
            plan_hosts(IpNet::from_str("192.168.1.0/24").unwrap())
                .unwrap()
                .len(),
            254
        );
        assert_eq!(
            plan_hosts(IpNet::from_str("2001:db8::/124").unwrap())
                .unwrap()
                .len(),
            16
        );
    }
}
