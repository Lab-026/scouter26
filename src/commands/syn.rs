//! The half-open SYN scanner.
//!
//! Everything in this module works at the packet level: we forge complete
//! IPv4+TCP SYN packets by hand (checksums and all), send them through a
//! raw socket, and classify whatever comes back. No packet library is
//! involved — the same hand-rolled-bytes spirit as the UDP payloads, one
//! level deeper.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use colored::*;
use std::path::PathBuf;

use super::ports;
use super::scan::DEFAULT_PORTS;
use super::{internet_checksum, parse_ports, resolve_target, unlock};

const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// ============================================================
// Packet surgery.
// ============================================================

// (internet_checksum lives in commands/mod.rs — the ping command's ICMP
// headers need the exact same math.)

/// Build one complete 40-byte IPv4+TCP packet with the given TCP flags.
///
/// IP header (20 bytes) + TCP header (20 bytes), no options — the
/// smallest honest packet the protocol allows.
fn build_tcp4(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    ip_id: u16,
) -> Vec<u8> {
    let mut packet = vec![0u8; 40];

    // --- IPv4 header, 20 bytes ---
    packet[0] = 0x45; // version 4, IHL 5 (no options)
    packet[1] = 0x00; // DSCP / ECN
    packet[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    packet[8] = 64; // TTL
    packet[9] = 6; // protocol: TCP
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());
    // The checksum covers the header with its own field zeroed, so it is
    // computed last and written into bytes 10..12.
    let ip_checksum = internet_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // --- TCP header, 20 bytes ---
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..28].copy_from_slice(&1u32.to_be_bytes()); // sequence number
    packet[28..32].copy_from_slice(&0u32.to_be_bytes()); // acknowledgement
    packet[32] = 0x50; // data offset: 5 words = 20 bytes, no options
    packet[33] = flags;
    packet[34..36].copy_from_slice(&1024u16.to_be_bytes()); // window
    // The TCP checksum covers a "pseudo-header" (the parts of the IP
    // header that identify this segment) plus the whole TCP header —
    // that is how the receiver knows the segment reached the right
    // address and port intact.
    let mut checksum_input = Vec::with_capacity(12 + 20);
    checksum_input.extend_from_slice(&src_ip.octets());
    checksum_input.extend_from_slice(&dst_ip.octets());
    checksum_input.push(0); // zero byte, then the protocol number
    checksum_input.push(6); // TCP
    checksum_input.extend_from_slice(&20u16.to_be_bytes()); // TCP length
    checksum_input.extend_from_slice(&packet[20..40]);
    let tcp_checksum = internet_checksum(&checksum_input);
    packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
    packet[38..40].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer

    packet
}

/// The verdict for one probed port, decoded from the reply's TCP flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SynVerdict {
    /// SYN-ACK: the port is listening. We never complete the handshake,
    /// so from the service's point of view the connection never happened.
    Open,
    /// RST: a machine is there and refuses the port outright.
    Closed,
    /// Nothing came back — firewall drop, most likely.
    Filtered,
}

impl SynVerdict {
    fn label(&self) -> &'static str {
        match self {
            SynVerdict::Open => "OPEN",
            SynVerdict::Closed => "CLOSED",
            SynVerdict::Filtered => "FILTERED",
        }
    }

    fn json_name(&self) -> &'static str {
        match self {
            SynVerdict::Open => "open",
            SynVerdict::Closed => "closed",
            SynVerdict::Filtered => "filtered",
        }
    }
}

/// Decide whether one raw IP datagram is a meaningful reply to our probe.
///
/// A reply must be IPv4/TCP, come from the target, land on our source
/// port, and carry SYN+ACK (open) or RST (closed). Anything else — other
/// hosts' traffic, our own SYNs bouncing back, stray ACKs — is ignored.
fn parse_reply(
    datagram: &[u8],
    our_port: u16,
    target: Ipv4Addr,
    probed: &HashSet<u16>,
) -> Option<(u16, SynVerdict)> {
    if datagram.len() < 28 {
        return None; // too short to hold IP + TCP headers
    }
    let version = datagram[0] >> 4;
    let header_words = (datagram[0] & 0x0F) as usize;
    if version != 4 || header_words < 5 {
        return None;
    }
    if datagram[9] != 6 {
        return None; // not TCP
    }
    if datagram[12..16] != target.octets() {
        return None; // not from the target
    }

    let total_len = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let end = total_len.min(datagram.len());
    // IHL counts 32-bit words; the TCP header starts at word_count * 4.
    let tcp = datagram.get(header_words * 4..end)?;
    if tcp.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    if dst_port != our_port || !probed.contains(&src_port) {
        return None;
    }

    let flags = tcp[13];
    if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
        Some((src_port, SynVerdict::Open))
    } else if flags & TCP_RST != 0 {
        Some((src_port, SynVerdict::Closed))
    } else {
        None
    }
}

// ============================================================
// The raw socket.
// ============================================================

/// A SOCK_RAW / IPPROTO_TCP socket with IP_HDRINCL: we supply the whole
/// IPv4 header ourselves. Creating one needs root (CAP_NET_RAW) — that
/// is not a bug, it is the kernel defending everyone else from packet
/// forgery.
struct RawSocket {
    fd: libc::c_int,
}

impl RawSocket {
    fn new() -> Result<Self, io::Error> {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let one: libc::c_int = 1;
            let ok = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ok != 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            Ok(RawSocket { fd })
        }
    }

    fn send(&self, packet: &[u8], dst: Ipv4Addr) -> Result<(), io::Error> {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0, // ignored: the port lives in the header we built
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dst.octets()),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            let sent = libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn set_read_timeout(&self, timeout: Duration) {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }

    /// Read one raw datagram, or None when the timeout slice elapsed.
    fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        unsafe {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let n = libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addr_len,
            );
            if n <= 0 { None } else { Some(n as usize) }
        }
    }

    /// A second file descriptor for the same socket, so one thread can
    /// read while others send. The returned wrapper owns (and closes)
    /// its duplicated descriptor; socket options carry over, because dup
    /// shares the underlying socket.
    fn dup_for_reading(&self) -> RawSocket {
        RawSocket {
            fd: unsafe { libc::dup(self.fd) },
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

// The fd is a plain integer; every use is a thread-safe syscall and the
// reader gets its own dup'd descriptor, so sharing is sound.
unsafe impl Send for RawSocket {}
unsafe impl Sync for RawSocket {}

/// Which local IP would the kernel use to reach this target? The trick:
/// connect a UDP socket (that only picks a route, sends nothing) and ask
/// it for its local address.
fn local_source_ip(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("could not bind a probe socket: {}", e))?;
    socket
        .connect(SocketAddr::new(IpAddr::V4(target), 9))
        .map_err(|e| format!("could not pick a route to {}: {}", target, e))?;
    match socket
        .local_addr()
        .map_err(|e| format!("could not read the local address: {}", e))?
        .ip()
    {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err("routing picked an IPv6 source for an IPv4 target".to_string()),
    }
}

// ============================================================
// The JSON report (--json).
// ============================================================

#[derive(serde::Serialize)]
struct SynFinding {
    port: u16,
    service: String,
    verdict: String,
}

#[derive(serde::Serialize)]
struct SynReport {
    target: String,
    resolved_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_port: u16,
    ports_probed: usize,
    timeout_seconds: f64,
    duration_seconds: f32,
    results: Vec<SynFinding>,
}

/// Entry point for `scouter26 syn <target>`.
pub fn execute(
    target: &str,
    ports_arg: &Option<String>,
    timeout_secs: f64,
    json: bool,
    output: &Option<PathBuf>,
) -> Result<(), String> {
    let started_at = Instant::now();

    if !(0.05..=60.0).contains(&timeout_secs) {
        return Err("timeout must be between 0.05 and 60 seconds".to_string());
    }

    let ports: Vec<u16> = match ports_arg {
        Some(spec) => parse_ports(spec)?,
        None => DEFAULT_PORTS.to_vec(),
    };

    // SYN scanning is IPv4-only: raw IPv6 injection follows different
    // kernel rules entirely. (The `scan` command covers IPv6 fine.)
    let target_ip = match resolve_target(target, false)? {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(format!(
                "'{}' is an IPv6 target and SYN scanning is IPv4-only for now",
                target
            ));
        }
    };

    // Raw packet surgery needs root; make the failure self-explanatory.
    let socket = RawSocket::new().map_err(|error| {
        if error.raw_os_error() == Some(libc::EPERM) {
            "SYN scanning forges raw packets, which the kernel only allows to root.\n\
             Run it with:  sudo scouter26 syn <target>\n\
             (scouter26's other commands never need root.)"
                .to_string()
        } else {
            format!("could not open a raw socket: {}", error)
        }
    })?;

    let src_ip = local_source_ip(target_ip)?;
    // A per-run source port: replies are recognized by it, and any late
    // SYN-ACK retransmits get RST by the kernel on our behalf.
    let src_port = 40000u16 + (std::process::id() % 20000) as u16;

    let probed: HashSet<u16> = ports.iter().copied().collect();
    let verdicts: Arc<Mutex<HashMap<u16, SynVerdict>>> = Arc::new(Mutex::new(HashMap::new()));
    let send_errors = Arc::new(AtomicUsize::new(0));

    if json {
        eprintln!(
            "{}",
            " [!] Only scan hosts you own or have permission to scan.".yellow()
        );
    } else {
        println!("{}", "========================================".cyan());
        println!("{}", " Scouter26 - SYN Scan (half-open)".cyan().bold());
        println!(
            " {}{} from {}:{}",
            "Target: ".cyan(),
            format!("{} ({})", target, target_ip).cyan(),
            src_ip.to_string().cyan(),
            src_port.to_string().cyan()
        );
        println!(" {}{}", "Ports:  ".cyan(), ports.len().to_string().cyan());
        println!("{}", "----------------------------------------".cyan());
        println!(
            "{}",
            " [!] Only scan hosts you own or have permission to scan.".yellow()
        );
    }

    // The reader thread: the single place replies get classified. It owns
    // its own dup'd descriptor and listens until the deadline expires.
    let reader = {
        let verdicts = Arc::clone(&verdicts);
        let probed = probed.clone();
        let read_socket = socket.dup_for_reading();
        let window = Duration::from_secs_f64(timeout_secs * 2.0);
        thread::spawn(move || {
            // read_socket closes itself (and its fd) when this thread returns
            read_socket.set_read_timeout(Duration::from_millis(100));
            let deadline = Instant::now() + window + Duration::from_millis(250);
            let mut buf = [0u8; 2048];
            loop {
                if Instant::now() >= deadline {
                    break;
                }
                match read_socket.recv(&mut buf) {
                    Some(n) => {
                        if let Some((port, verdict)) =
                            parse_reply(&buf[..n], src_port, target_ip, &probed)
                        {
                            verdicts.lock().unwrap_or_else(unlock).insert(port, verdict);
                        }
                    }
                    None => continue, // timeout slice with no datagram
                }
            }
        })
    };

    // Send one SYN. Sending is a cheap syscall — the waiting is where the
    // time goes — so the send phase is a plain loop, not a worker pool.
    let ip_id = AtomicUsize::new(0x1964);
    let send_syn = |port: u16| {
        let id = ip_id.fetch_add(1, Ordering::Relaxed) as u16;
        let packet = build_tcp4(src_ip, target_ip, src_port, port, TCP_SYN, id);
        if socket.send(&packet, target_ip).is_err() {
            send_errors.fetch_add(1, Ordering::Relaxed);
        }
    };

    // Pass 1: every port. Pass 2 (after half the window): only the ports
    // still silent — same retransmit logic as the UDP scanner, because a
    // lost SYN and a dropped reply are indistinguishable from silence.
    let window = Duration::from_secs_f64(timeout_secs * 2.0);
    for &port in &ports {
        send_syn(port);
    }
    thread::sleep(window / 2);
    let silent: Vec<u16> = {
        let map = verdicts.lock().unwrap_or_else(unlock);
        ports
            .iter()
            .filter(|p| !map.contains_key(p))
            .copied()
            .collect()
    };
    for port in silent {
        send_syn(port);
    }
    thread::sleep(window / 2 + Duration::from_millis(250));

    reader
        .join()
        .map_err(|_| "reader thread crashed".to_string())?;

    if send_errors.load(Ordering::Relaxed) > 0 {
        eprintln!(
            "{}",
            format!(
                " Warning: {} packet(s) could not be sent.",
                send_errors.load(Ordering::Relaxed)
            )
            .yellow()
        );
    }

    let results: Vec<(u16, SynVerdict)> = ports
        .iter()
        .map(|&port| {
            let verdict = verdicts
                .lock()
                .unwrap_or_else(unlock)
                .get(&port)
                .copied()
                .unwrap_or(SynVerdict::Filtered);
            (port, verdict)
        })
        .collect();

    // Report: JSON for machines, the human table otherwise — and a saved
    // copy on disk whenever --output asks for one.
    if json || output.is_some() {
        let report = SynReport {
            target: target.to_string(),
            resolved_ip: target_ip,
            source_ip: src_ip,
            source_port: src_port,
            ports_probed: ports.len(),
            timeout_seconds: timeout_secs,
            duration_seconds: started_at.elapsed().as_secs_f32(),
            results: results
                .iter()
                .map(|(port, verdict)| SynFinding {
                    port: *port,
                    service: ports::service_name(*port).to_string(),
                    verdict: verdict.json_name().to_string(),
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
                serde_json::to_string_pretty(&report).expect("SynReport always serializes")
            );
            return Ok(());
        }
    }

    println!("{}", "========================================".cyan());
    let (mut open, mut closed, mut filtered) = (0usize, 0usize, 0usize);
    for (port, verdict) in &results {
        match verdict {
            SynVerdict::Open => open += 1,
            SynVerdict::Closed => closed += 1,
            SynVerdict::Filtered => filtered += 1,
        }
        let detail = match verdict {
            SynVerdict::Open => "SYN-ACK received — handshake abandoned".to_string(),
            SynVerdict::Closed => "RST received".to_string(),
            SynVerdict::Filtered => "(no reply)".to_string(),
        };
        let colored_label = match verdict {
            SynVerdict::Open => verdict.label().green().bold(),
            SynVerdict::Closed => verdict.label().red(),
            SynVerdict::Filtered => verdict.label().yellow(),
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
            " SYN scan complete in {:.2}s — open: {}, closed: {}, filtered: {}.",
            started_at.elapsed().as_secs_f32(),
            open,
            closed,
            filtered
        )
        .cyan()
    );
    println!(
        "{}",
        " half-open: no TCP handshake was ever completed, so most services never logged you."
            .dimmed()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_the_reference_vector() {
        // The classic worked example (Wikipedia, IPv4 header): the same
        // header with its checksum field zeroed must checksum to 0xB861.
        // If this test passes, our checksum math is certified against an
        // external source, not just against itself.
        let header: &[u8] = &[
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, //
            0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, //
            0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(header), 0xB861);
    }

    #[test]
    fn a_syn_packet_is_well_formed() {
        let packet = build_tcp4(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            40000,
            80,
            TCP_SYN,
            0x1964,
        );
        assert_eq!(packet.len(), 40);
        assert_eq!(packet[0], 0x45, "IPv4, no options");
        assert_eq!(packet[9], 6, "protocol TCP");
        assert_eq!(packet[33], TCP_SYN);
        // A SYN (no ACK) is our own outgoing packet, not a verdict.
        assert!(
            parse_reply(&packet, 40000, Ipv4Addr::new(192, 0, 2, 1), &HashSet::new()).is_none()
        );
    }

    #[test]
    fn syn_ack_and_rst_replies_are_classified() {
        let our_ip = Ipv4Addr::new(192, 0, 2, 10);
        let target = Ipv4Addr::new(192, 0, 2, 1);
        let our_port = 40000;
        let probed_port = 80u16;
        let probed: HashSet<u16> = [probed_port].into();

        // The target's reply: from the probed port, to our source port.
        let syn_ack = build_tcp4(target, our_ip, probed_port, our_port, TCP_SYN | TCP_ACK, 7);
        assert_eq!(
            parse_reply(&syn_ack, our_port, target, &probed),
            Some((probed_port, SynVerdict::Open))
        );

        let rst = build_tcp4(target, our_ip, probed_port, our_port, TCP_RST, 8);
        assert_eq!(
            parse_reply(&rst, our_port, target, &probed),
            Some((probed_port, SynVerdict::Closed))
        );
    }

    #[test]
    fn unrelated_traffic_is_ignored() {
        let our_ip = Ipv4Addr::new(192, 0, 2, 10);
        let target = Ipv4Addr::new(192, 0, 2, 1);
        let probed: HashSet<u16> = [80u16].into();

        // Reply to a port we did not probe from: must be ignored.
        let stranger = build_tcp4(target, our_ip, 9999, 40000, TCP_SYN | TCP_ACK, 9);
        assert!(parse_reply(&stranger, 40000, target, &probed).is_none());

        // Reply landing on the wrong local port: must be ignored.
        let wrong_dst = build_tcp4(target, our_ip, 80, 12345, TCP_SYN | TCP_ACK, 10);
        assert!(parse_reply(&wrong_dst, 40000, target, &probed).is_none());

        // Not from the target at all: must be ignored.
        let other_host = build_tcp4(
            Ipv4Addr::new(192, 0, 2, 99),
            our_ip,
            80,
            40000,
            TCP_SYN | TCP_ACK,
            11,
        );
        assert!(parse_reply(&other_host, 40000, target, &probed).is_none());
    }

    #[test]
    fn raw_sockets_fail_cleanly_without_root() {
        match RawSocket::new() {
            // If this environment grants CAP_NET_RAW after all, creating
            // the socket is legitimately fine and there is nothing to test.
            Ok(_) => {}
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EPERM)),
        }
    }

    #[test]
    fn syn_report_serializes_to_json() {
        let report = SynReport {
            target: "example.test".to_string(),
            resolved_ip: Ipv4Addr::new(192, 0, 2, 1),
            source_ip: Ipv4Addr::new(192, 0, 2, 10),
            source_port: 40123,
            ports_probed: 2,
            timeout_seconds: 1.0,
            duration_seconds: 2.5,
            results: vec![
                SynFinding {
                    port: 22,
                    service: "ssh".to_string(),
                    verdict: "open".to_string(),
                },
                SynFinding {
                    port: 445,
                    service: "smb".to_string(),
                    verdict: "filtered".to_string(),
                },
            ],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["source_port"], 40123);
        assert_eq!(value["results"][0]["verdict"], "open");
        assert_eq!(value["results"][1]["verdict"], "filtered");
    }
}
