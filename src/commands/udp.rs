use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use colored::*;

use super::ports;
use super::{
    MAX_WORKERS, PROGRESS_THRESHOLD, parse_ports, resolve_target, unlock, validate_tunables,
};

/// The ports probed when the user does not pick their own — the classic
/// UDP services that are common, interesting, or loud. Kept small on
/// purpose: blasting thousands of UDP ports trips the target kernel's
/// ICMP rate limit, which makes closed ports start LOOKING filtered.
const DEFAULT_UDP_PORTS: [u16; 6] = [53, 69, 123, 137, 161, 514];

// ============================================================
// Protocol payloads.
//
// UDP has no handshake, so an empty datagram rarely wakes a service
// up. These minimal, well-formed requests ask each service a question
// it likes answering — the same trick nmap's payload scripts use.
// ============================================================

/// A DNS "A?" query for example.com — every recursive resolver on
/// earth answers this, which is how `dig` works.
///   header (id, flags=RD, 1 question) + "example.com" + A + IN
const DNS_QUERY: &[u8] = &[
    0xAB, 0xCD, // transaction id (arbitrary)
    0x01, 0x00, // flags: recursion desired
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT = 0
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x00, // ARCOUNT = 0
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // label "example"
    0x03, b'c', b'o', b'm', //                      label "com"
    0x00, // root label, ends the name
    0x00, 0x01, // QTYPE = A
    0x00, 0x01, // QCLASS = IN
];

/// An NTP mode-3 (client) request: LI=0, version=3, mode=3, then zeros.
/// 48 bytes is fixed by the protocol; servers reply with their time.
const NTP_CLIENT: &[u8] = &{
    let mut request = [0u8; 48];
    request[0] = 0x1B; // LI=0, version=3, mode=3 (client)
    request
};

/// An SNMPv1 GET for sysDescr.0 (1.3.6.1.2.1.1.1.0) with community
/// "public" — the single most common read query in the SNMP world.
/// Hand-encoded ASN.1 BER: SEQ{ INT 0, OCTET "public", GetRequest{...} }.
const SNMP_GET_SYSDESCR: &[u8] = &[
    0x30, 0x26, // SEQUENCE, 38 bytes of content
    0x02, 0x01, 0x00, // INTEGER version 0 (SNMPv1)
    0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community "public"
    0xA0, 0x19, // GetRequest PDU, 25 bytes of content
    0x02, 0x01, 0x01, // request-id = 1
    0x02, 0x01, 0x00, // error-status = 0
    0x02, 0x01, 0x00, // error-index = 0
    0x30, 0x0E, // varbind list
    0x30, 0x0C, // one varbind
    0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID sysDescr.0
    0x05, 0x00, // NULL value
];

/// The payload to send for a given port: protocol-aware when we know
/// one, an empty (but still valid) datagram otherwise. Empty datagrams
/// still work — some services answer anything; most answer nothing,
/// which is exactly what open|filtered is about.
fn probe_payload(port: u16) -> &'static [u8] {
    match port {
        53 => DNS_QUERY,
        123 => NTP_CLIENT,
        161 => SNMP_GET_SYSDESCR,
        _ => &[],
    }
}

// ============================================================
// Probing and verdicts.
// ============================================================

/// The outcome of one UDP probe. Note there is no plain "open or
/// closed" world: silence is genuinely ambiguous, and pretending
/// otherwise would make the tool lie.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UdpVerdict {
    /// The service answered — proof of life, plus how many bytes came back.
    Open(usize),
    /// The host's kernel sent back ICMP port-unreachable: a machine is
    /// there and nothing listens on this port.
    Closed,
    /// Silence. An open-but-quiet service and a filtering firewall look
    /// identical over UDP, so the honest verdict is both at once.
    OpenFiltered,
}

impl UdpVerdict {
    fn label(&self) -> &'static str {
        match self {
            UdpVerdict::Open(_) => "OPEN",
            UdpVerdict::Closed => "CLOSED",
            UdpVerdict::OpenFiltered => "OPEN|FILTERED",
        }
    }

    fn json_name(&self) -> &'static str {
        match self {
            UdpVerdict::Open(_) => "open",
            UdpVerdict::Closed => "closed",
            UdpVerdict::OpenFiltered => "open|filtered",
        }
    }
}

/// Probe one UDP port and return its verdict.
///
/// Uses a *connected* UDP socket: connecting is what tells the kernel to
/// deliver ICMP errors for this destination as normal socket errors.
/// Each silent port is probed twice — the retransmit is not just
/// politeness. On Linux the ICMP error from attempt 1 is often only
/// handed to the socket by the NEXT syscall, so attempt 2's send/recv is
/// what actually notices closed ports. (nmap retransmits for the same
/// reason.)
fn udp_probe(
    target: IpAddr,
    port: u16,
    timeout: Duration,
    socket_errors: &AtomicUsize,
) -> UdpVerdict {
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(bind_addr) else {
        socket_errors.fetch_add(1, Ordering::Relaxed);
        return UdpVerdict::OpenFiltered;
    };
    if socket.connect(SocketAddr::new(target, port)).is_err() {
        socket_errors.fetch_add(1, Ordering::Relaxed);
        return UdpVerdict::OpenFiltered;
    }
    if socket.set_read_timeout(Some(timeout)).is_err() {
        socket_errors.fetch_add(1, Ordering::Relaxed);
        return UdpVerdict::OpenFiltered;
    }

    let payload = probe_payload(port);
    let mut buf = [0u8; 1024];

    for _ in 0..2 {
        if let Err(error) = socket.send(payload) {
            if error.kind() == std::io::ErrorKind::ConnectionRefused {
                return UdpVerdict::Closed; // the flush of a pending ICMP error
            }
            socket_errors.fetch_add(1, Ordering::Relaxed);
            return UdpVerdict::OpenFiltered;
        }

        match socket.recv(&mut buf) {
            Ok(n) => return UdpVerdict::Open(n),
            Err(error) => match error.kind() {
                std::io::ErrorKind::ConnectionRefused => return UdpVerdict::Closed,
                // TimedOut/WouldBlock = silence this attempt; try once more.
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {}
                _ => {
                    socket_errors.fetch_add(1, Ordering::Relaxed);
                    return UdpVerdict::OpenFiltered;
                }
            },
        }
    }

    UdpVerdict::OpenFiltered
}

/// Probe the given UDP ports with the same worker-pool pattern as the
/// other scanning commands. Returns (port, verdict) pairs, sorted by port.
fn sweep(
    target: IpAddr,
    ports: &[u16],
    timeout: Duration,
    workers: usize,
    show_progress: bool,
) -> (Vec<(u16, UdpVerdict)>, usize) {
    let total = ports.len();
    let worker_count = workers.clamp(1, MAX_WORKERS).min(total.max(1));

    let todo: Arc<Mutex<VecDeque<u16>>> = Arc::new(Mutex::new(ports.iter().copied().collect()));
    let results: Arc<Mutex<Vec<(u16, UdpVerdict)>>> = Arc::new(Mutex::new(Vec::new()));
    let tried = Arc::new(AtomicUsize::new(0));
    let socket_errors = Arc::new(AtomicUsize::new(0));

    let progress_thread = if show_progress && total >= PROGRESS_THRESHOLD {
        let tried = Arc::clone(&tried);
        Some(thread::spawn(move || {
            while tried.load(Ordering::Relaxed) < total {
                print!(
                    "\r [..] {} / {} probes sent",
                    tried.load(Ordering::Relaxed),
                    total
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
        let results = Arc::clone(&results);
        let tried = Arc::clone(&tried);
        let socket_errors = Arc::clone(&socket_errors);

        handles.push(thread::spawn(move || {
            loop {
                let next = todo.lock().unwrap_or_else(unlock).pop_front();
                let port = match next {
                    Some(port) => port,
                    None => break,
                };
                let verdict = udp_probe(target, port, timeout, &socket_errors);
                results.lock().unwrap_or_else(unlock).push((port, verdict));
                tried.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for handle in handles {
        if handle.join().is_err() {
            eprintln!("{}", "Warning: a UDP worker exited unexpectedly".yellow());
        }
    }

    if let Some(progress) = progress_thread {
        progress.join().ok();
        println!("\r [ok] {} / {} probes sent", total, total);
    }

    let mut results = results.lock().unwrap_or_else(unlock).clone();
    results.sort_unstable_by_key(|(port, _)| *port);
    (results, socket_errors.load(Ordering::Relaxed))
}

// ============================================================
// The JSON report (--json).
// ============================================================

#[derive(serde::Serialize)]
struct UdpFinding {
    port: u16,
    service: String,
    verdict: String,
    response_bytes: usize,
}

#[derive(serde::Serialize)]
struct UdpReport {
    target: String,
    resolved_ip: IpAddr,
    ports_probed: usize,
    timeout_seconds: f64,
    workers: usize,
    duration_seconds: f32,
    results: Vec<UdpFinding>,
}

/// Entry point for `scouter26 udp <target>`.
pub fn execute(
    target: &str,
    ports_arg: &Option<String>,
    timeout_secs: f64,
    workers: usize,
    prefer_ipv6: bool,
    json: bool,
) -> Result<(), String> {
    let started_at = Instant::now();

    validate_tunables(timeout_secs, workers)?;

    let ports: Vec<u16> = match ports_arg {
        Some(spec) => parse_ports(spec)?,
        None => DEFAULT_UDP_PORTS.to_vec(),
    };

    let target_ip = resolve_target(target, prefer_ipv6)?;

    let target_label = if target.parse::<IpAddr>().is_ok() {
        target.to_string()
    } else {
        format!("{} ({})", target, target_ip)
    };

    if json {
        eprintln!(
            "{}",
            " [!] Only scan hosts you own or have permission to scan.".yellow()
        );
    } else {
        println!("{}", "========================================".cyan());
        println!("{}", " Scouter26 - UDP Scan".cyan().bold());
        println!(" {}{}", "Target: ".cyan(), target_label.cyan());
        println!(" {}{}", "Ports:  ".cyan(), ports.len().to_string().cyan());
        println!("{}", "----------------------------------------".cyan());
        println!(
            "{}",
            " [!] Only scan hosts you own or have permission to scan.".yellow()
        );
    }

    let (results, socket_errors) = sweep(
        target_ip,
        &ports,
        Duration::from_secs_f64(timeout_secs),
        workers,
        !json,
    );

    if socket_errors > 0 {
        eprintln!(
            "{}",
            format!(
                " Warning: {} probe(s) could not create or use a socket and were counted as open|filtered.",
                socket_errors
            )
            .yellow()
        );
    }

    if json {
        let report = UdpReport {
            target: target.to_string(),
            resolved_ip: target_ip,
            ports_probed: ports.len(),
            timeout_seconds: timeout_secs,
            workers,
            duration_seconds: started_at.elapsed().as_secs_f32(),
            results: results
                .iter()
                .map(|(port, verdict)| UdpFinding {
                    port: *port,
                    service: ports::service_name(*port).to_string(),
                    verdict: verdict.json_name().to_string(),
                    response_bytes: match verdict {
                        UdpVerdict::Open(n) => *n,
                        _ => 0,
                    },
                })
                .collect(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("UdpReport always serializes")
        );
        return Ok(());
    }

    println!("{}", "========================================".cyan());
    let (mut open, mut closed, mut filtered) = (0usize, 0usize, 0usize);
    for (port, verdict) in &results {
        match verdict {
            UdpVerdict::Open(_) => open += 1,
            UdpVerdict::Closed => closed += 1,
            UdpVerdict::OpenFiltered => filtered += 1,
        }
        let detail = match verdict {
            UdpVerdict::Open(n) => format!("({} bytes received)", n),
            UdpVerdict::Closed => "host says: nothing listens here".to_string(),
            UdpVerdict::OpenFiltered => "(no response — open or firewalled)".to_string(),
        };
        let colored_label = match verdict {
            UdpVerdict::Open(_) => verdict.label().green().bold(),
            UdpVerdict::Closed => verdict.label().red(),
            UdpVerdict::OpenFiltered => verdict.label().yellow(),
        };
        println!(
            " Port {:<6} {:<10} {}  {}",
            port,
            ports::service_name(*port),
            colored_label,
            detail.dimmed()
        );
    }
    println!("{}", "========================================".cyan());
    println!(
        "{}",
        format!(
            " UDP scan complete in {:.2}s — open: {}, closed: {}, open|filtered: {}.",
            started_at.elapsed().as_secs_f32(),
            open,
            closed,
            filtered
        )
        .cyan()
    );
    println!(
        "{}",
        " open|filtered = no answer. UDP cannot tell an open-but-quiet service from a firewall drop."
            .dimmed()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_match_their_protocols() {
        assert_eq!(
            probe_payload(53).len(),
            29,
            "DNS query: header + example.com + A/IN"
        );
        assert_eq!(
            probe_payload(123).len(),
            48,
            "NTP requests are fixed at 48 bytes"
        );
        assert_eq!(probe_payload(161).len(), 40, "hand-encoded SNMPv1 GET");
        assert_eq!(
            probe_payload(123)[0],
            0x1B,
            "LI=0, version=3, mode=3 (client)"
        );
        assert_eq!(probe_payload(514).len(), 0, "syslog gets an empty datagram");
        // The DNS question must be a proper name: 7"example" 3"com" 0.
        assert_eq!(
            &probe_payload(53)[12..21],
            &[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03]
        );
    }

    #[test]
    fn verdicts_map_to_labels_and_json_names() {
        assert_eq!(UdpVerdict::Open(1).label(), "OPEN");
        assert_eq!(UdpVerdict::Closed.label(), "CLOSED");
        assert_eq!(UdpVerdict::OpenFiltered.label(), "OPEN|FILTERED");
        assert_eq!(UdpVerdict::Open(1).json_name(), "open");
        assert_eq!(UdpVerdict::Closed.json_name(), "closed");
        assert_eq!(UdpVerdict::OpenFiltered.json_name(), "open|filtered");
    }

    #[test]
    fn an_answering_udp_service_is_open() {
        // A real UDP echo responder on the loopback.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((n, source)) = socket.recv_from(&mut buf) {
                    let _ = socket.send_to(&buf[..n], source);
                }
            }
        });

        let (results, socket_errors) = sweep(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &[port],
            Duration::from_millis(300),
            2,
            false,
        );

        assert_eq!(socket_errors, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].1,
            UdpVerdict::Open(probe_payload(port).len()),
            "the echo must come back with the same payload we sent"
        );
    }

    #[test]
    fn a_dropped_udp_port_reads_as_closed_on_loopback() {
        // Bind a UDP port, then release it: the kernel now answers our
        // probe with ICMP port-unreachable — the "closed" signal.
        let handle = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = handle.local_addr().unwrap().port();
        drop(handle);

        let (results, socket_errors) = sweep(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &[port],
            Duration::from_millis(300),
            2,
            false,
        );

        assert_eq!(socket_errors, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, UdpVerdict::Closed);
    }

    #[test]
    fn udp_report_serializes_to_json() {
        let report = UdpReport {
            target: "example.test".to_string(),
            resolved_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            ports_probed: 2,
            timeout_seconds: 1.0,
            workers: 200,
            duration_seconds: 1.5,
            results: vec![
                UdpFinding {
                    port: 53,
                    service: "dns".to_string(),
                    verdict: "open".to_string(),
                    response_bytes: 29,
                },
                UdpFinding {
                    port: 123,
                    service: "ntp".to_string(),
                    verdict: "open|filtered".to_string(),
                    response_bytes: 0,
                },
            ],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["results"][0]["port"], 53);
        assert_eq!(value["results"][0]["verdict"], "open");
        assert_eq!(value["results"][1]["verdict"], "open|filtered");
    }
}
