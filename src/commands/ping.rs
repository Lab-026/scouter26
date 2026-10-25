//! The `ping` command — the most-used diagnostic in IT Support.
//!
//! Two engines, chosen honestly and shown in the output:
//!   * ICMP mode: a Linux "ping socket" (SOCK_DGRAM + IPPROTO_ICMP) lets
//!     unprivileged users send real echo requests on Fedora-family systems
//!     (kernel sysctl net.ipv4.ping_group_range permitting).
//!   * TCP mode: when ICMP is unavailable (or the target is IPv6, which
//!     this command does not do yet), we measure reachability and latency
//!     by opening a TCP connection instead — and say so in every line.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use colored::*;

use super::{internet_checksum, resolve_target};

/// Every probe carries this magic so a reply can be identified as ours
/// even though the kernel rewrites the ICMP identifier on ping sockets.
const PAYLOAD_MAGIC: &[u8; 12] = b"SCOUTER26PNG";
/// Magic (12) + sequence (2) + send-timestamp in microseconds (8) + slack.
const PAYLOAD_LEN: usize = 32;

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

// ============================================================
// ICMP echo packets, hand-built (same spirit as the SYN scanner).
// ============================================================

/// Build an ICMP echo request: 8-byte header (type, code, checksum,
/// identifier, sequence) plus our payload. Type 8 = "echo me".
fn build_echo_request(identifier: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.push(8); // type: echo request
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum, written below
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(payload);
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Recognise an echo reply: type 0, and return (sequence, payload).
/// Everything else — other ICMP traffic, errors, noise — is not ours.
fn parse_echo_reply(datagram: &[u8], payload_len: usize) -> Option<(u16, &[u8])> {
    if datagram.len() < 8 + payload_len || datagram[0] != 0 {
        return None;
    }
    let seq = u16::from_be_bytes([datagram[6], datagram[7]]);
    Some((seq, &datagram[8..8 + payload_len]))
}

/// Make a 32-byte payload: magic + sequence + send timestamp (micros).
/// The timestamp is how we measure round-trip time without trusting the
/// socket to tell us anything.
fn probe_payload(seq: u16, sent_micros: u64) -> [u8; PAYLOAD_LEN] {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..12].copy_from_slice(PAYLOAD_MAGIC);
    payload[12..14].copy_from_slice(&seq.to_be_bytes());
    payload[14..22].copy_from_slice(&sent_micros.to_be_bytes());
    payload
}

// ============================================================
// The ICMP ping socket (SOCK_DGRAM + IPPROTO_ICMP).
//
// Not a UDP socket: the standard library cannot pick the ICMP protocol,
// so this goes through libc directly, exactly like the SYN scanner's raw
// socket — minus IP_HDRINCL, because the kernel builds the IP header for
// datagram ICMP sockets and only lets them speak to one destination.
// ============================================================

struct IcmpSocket {
    fd: libc::c_int,
}

impl IcmpSocket {
    fn new() -> Result<Self, io::Error> {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(IcmpSocket { fd })
        }
    }

    fn connect(&self, target: SocketAddr) -> Result<(), io::Error> {
        let v4 = match target.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => unreachable!("ping sockets are IPv4"),
        };
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0, // ICMP has no ports
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.octets()),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            if libc::connect(
                self.fd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) != 0
            {
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

    fn send(&self, packet: &[u8]) -> Result<(), io::Error> {
        unsafe {
            let n = libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
            );
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        unsafe {
            let n = libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 { None } else { Some(n as usize) }
        }
    }
}

impl Drop for IcmpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

unsafe impl Send for IcmpSocket {}
unsafe impl Sync for IcmpSocket {}

// ============================================================
// Probes.
// ============================================================

/// One ICMP probe: send, then listen until the deadline for OUR reply
/// (matched by sequence and magic — the identifier cannot be trusted on
/// ping sockets, because the kernel rewrites it).
fn icmp_probe(socket: &IcmpSocket, seq: u16, timeout: Duration) -> Option<Duration> {
    let sent_micros = now_micros();
    let request = build_echo_request(0x1964, seq, &probe_payload(seq, sent_micros));
    socket.send(&request).ok()?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 256];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        socket.set_read_timeout(remaining);
        // `?` on the recv: None means the timeout slice elapsed — silence.
        let n = socket.recv(&mut buf)?;
        if let Some((reply_seq, reply_payload)) = parse_echo_reply(&buf[..n], PAYLOAD_LEN)
            && reply_seq == seq
            && reply_payload.starts_with(PAYLOAD_MAGIC)
        {
            let sent = u64::from_be_bytes(
                reply_payload[14..22]
                    .try_into()
                    .expect("payload is 32 bytes"),
            );
            return Some(Duration::from_micros(now_micros().saturating_sub(sent)));
        }
        // Not ours — keep listening until the deadline.
    }
}

/// What one TCP probe told us. A refusal is not a failure — a machine
/// that refuses is a machine that is up.
#[derive(Debug)]
enum TcpProbe {
    Open(Duration),
    Refused(Duration),
    NoAnswer,
}

fn tcp_probe(target: IpAddr, port: u16, timeout: Duration) -> TcpProbe {
    let started = Instant::now();
    match TcpStream::connect_timeout(&SocketAddr::new(target, port), timeout) {
        Ok(_) => TcpProbe::Open(started.elapsed()),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            TcpProbe::Refused(started.elapsed())
        }
        Err(_) => TcpProbe::NoAnswer,
    }
}

// ============================================================
// Statistics.
// ============================================================

fn summarise(rtts: &[Duration]) -> (f64, f64, f64) {
    let millis: Vec<f64> = rtts.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    let min = millis.iter().cloned().fold(f64::MAX, f64::min);
    let max = millis.iter().cloned().fold(f64::MIN, f64::max);
    let avg = millis.iter().sum::<f64>() / millis.len() as f64;
    (min, avg, max)
}

// ============================================================
// The JSON report (--json / --output).
// ============================================================

#[derive(serde::Serialize)]
struct PingReply {
    seq: u16,
    time_ms: Option<f64>,
    note: String,
}

#[derive(serde::Serialize)]
struct PingReport {
    target: String,
    resolved_ip: String,
    mode: String,
    probes_sent: usize,
    probes_received: usize,
    packet_loss_percent: f64,
    rtt_min_ms: Option<f64>,
    rtt_avg_ms: Option<f64>,
    rtt_max_ms: Option<f64>,
    replies: Vec<PingReply>,
}

/// Entry point for `scouter26 ping <target>`.
pub fn execute(
    target: &str,
    count: usize,
    interval_secs: f64,
    timeout_secs: f64,
    tcp_port: u16,
    json: bool,
    output: &Option<PathBuf>,
) -> Result<(), String> {
    let started_at = Instant::now();

    if count == 0 || count > 100 {
        return Err("count must be between 1 and 100".to_string());
    }
    if !(0.05..=10.0).contains(&interval_secs) {
        return Err("interval must be between 0.05 and 10 seconds".to_string());
    }
    if !(0.05..=10.0).contains(&timeout_secs) {
        return Err("timeout must be between 0.05 and 10 seconds".to_string());
    }
    if tcp_port == 0 {
        return Err("port 0 is reserved".to_string());
    }

    let resolved = resolve_target(target, false)?;
    let target_label = if target.parse::<IpAddr>().is_ok() {
        target.to_string()
    } else {
        format!("{} ({})", target, resolved)
    };

    // Engine selection: real ICMP when we can have it, TCP otherwise —
    // and the choice is printed, never silent.
    let icmp = if resolved.is_ipv4() {
        match IcmpSocket::new() {
            Ok(socket) => match socket.connect(SocketAddr::new(resolved, 0)) {
                Ok(()) => Some(socket),
                Err(error) => {
                    eprintln!(
                        "{}",
                        format!(
                            " note: ICMP connect failed ({}) — using TCP mode via port {}",
                            error, tcp_port
                        )
                        .yellow()
                    );
                    None
                }
            },
            Err(error) => {
                eprintln!(
                    "{}",
                    format!(
                        " note: ICMP ping sockets unavailable ({}) — using TCP mode via port {}",
                        error, tcp_port
                    )
                    .yellow()
                );
                None
            }
        }
    } else {
        eprintln!(
            "{}",
            format!(
                " note: IPv6 ping is not supported yet — using TCP mode via port {}",
                tcp_port
            )
            .yellow()
        );
        None
    };
    let mode = if icmp.is_some() { "icmp" } else { "tcp" };

    if !json {
        println!("{}", "========================================".cyan());
        println!("{}", " Scouter26 - Ping".cyan().bold());
        println!(" {}{}", "Target: ".cyan(), target_label.cyan());
        println!(
            " {}{}",
            "Mode:   ".cyan(),
            if icmp.is_some() {
                "ICMP echo".cyan()
            } else {
                format!("TCP connect (port {})", tcp_port).cyan()
            }
        );
        println!(
            " {}{}",
            "Probes: ".cyan(),
            format!(
                "{} (interval {}s, timeout {}s)",
                count, interval_secs, timeout_secs
            )
            .cyan()
        );
        println!("{}", "----------------------------------------".cyan());
    }

    let mut rtts: Vec<Duration> = Vec::new();
    let mut replies: Vec<PingReply> = Vec::new();

    for seq in 1..=count as u16 {
        let probe_started = Instant::now();

        let (received, time_ms, note) = match &icmp {
            Some(socket) => match icmp_probe(socket, seq, Duration::from_secs_f64(timeout_secs)) {
                Some(rtt) => {
                    let ms = rtt.as_secs_f64() * 1000.0;
                    (true, Some(ms), format!("{:.2} ms", ms))
                }
                None => (false, None, "timed out".to_string()),
            },
            None => match tcp_probe(resolved, tcp_port, Duration::from_secs_f64(timeout_secs)) {
                TcpProbe::Open(rtt) => {
                    let ms = rtt.as_secs_f64() * 1000.0;
                    (true, Some(ms), format!("{:.2} ms", ms))
                }
                TcpProbe::Refused(rtt) => {
                    let ms = rtt.as_secs_f64() * 1000.0;
                    (
                        true,
                        Some(ms),
                        format!("{:.2} ms (port {} closed, host answered)", ms, tcp_port),
                    )
                }
                TcpProbe::NoAnswer => (false, None, "timed out".to_string()),
            },
        };

        if received {
            rtts.push(Duration::from_secs_f64(time_ms.unwrap_or(0.0) / 1000.0));
        }
        replies.push(PingReply {
            seq,
            time_ms,
            note: note.clone(),
        });

        if !json {
            let line = if received {
                format!(" reply from {}: seq={} time={}", resolved, seq, note)
            } else {
                format!(" request timed out: seq={}", seq)
            };
            println!("{}", if received { line.green() } else { line.red() });
        }

        // Pace at the interval, minus however long the probe itself took.
        if seq < count as u16
            && let Some(remaining) =
                Duration::from_secs_f64(interval_secs).checked_sub(probe_started.elapsed())
        {
            thread::sleep(remaining);
        }
    }

    let received_count = rtts.len();
    let loss = 100.0 * (count - received_count) as f64 / count as f64;

    if !json {
        println!("{}", "----------------------------------------".cyan());
        println!(
            " {} probes sent, {} received, {:.1}% packet loss",
            count, received_count, loss
        );
        if !rtts.is_empty() {
            let (min, avg, max) = summarise(&rtts);
            println!(
                " rtt min/avg/max: {:.2}/{:.2}/{:.2} ms ({})",
                min, avg, max, mode
            );
        }
        println!("{}", "========================================".cyan());
        println!(
            "{}",
            format!(
                " {} ping complete in {:.2}s.",
                mode,
                started_at.elapsed().as_secs_f32()
            )
            .cyan()
        );
    }

    if json || output.is_some() {
        let (min, avg, max) = if rtts.is_empty() {
            (None, None, None)
        } else {
            let (min, avg, max) = summarise(&rtts);
            (Some(min), Some(avg), Some(max))
        };
        let report = PingReport {
            target: target.to_string(),
            resolved_ip: resolved.to_string(),
            mode: mode.to_string(),
            probes_sent: count,
            probes_received: received_count,
            packet_loss_percent: loss,
            rtt_min_ms: min,
            rtt_avg_ms: avg,
            rtt_max_ms: max,
            replies,
        };
        if let Some(path) = output {
            super::write_report(path, &report)?;
            eprintln!("{}", format!(" Report saved to {}", path.display()).cyan());
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("PingReport always serializes")
            );
            return Ok(());
        }
    }

    if received_count == 0 {
        return Err(format!(
            "0 of {} probes received — {} appears unreachable via {}",
            count, resolved, mode
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_requests_are_well_formed() {
        let payload = probe_payload(7, 12345);
        let packet = build_echo_request(0x1964, 7, &payload);
        assert_eq!(packet[0], 8, "type: echo request");
        assert_eq!(packet[1], 0, "code: 0");
        // The RFC property: summing the whole packet including its own
        // checksum folds to all-ones.
        let mut sum = 0u32;
        for word in packet.as_chunks::<2>().0 {
            sum += u16::from_be_bytes(*word) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(
            sum, 0xFFFF,
            "checksum must make the whole packet sum to 0xFFFF"
        );
    }

    #[test]
    fn echo_replies_are_recognised_and_requests_are_not() {
        let payload = probe_payload(3, 999);
        let request = build_echo_request(1, 3, &payload);

        // A request (type 8) is not a reply.
        assert!(parse_echo_reply(&request, PAYLOAD_LEN).is_none());

        // The same packet with type flipped to 0 is a valid reply.
        let mut reply = request.clone();
        reply[0] = 0;
        assert_eq!(
            parse_echo_reply(&reply, PAYLOAD_LEN),
            Some((3, &reply[8..]))
        );

        // Short garbage is ignored.
        assert!(parse_echo_reply(&[0, 0, 0], PAYLOAD_LEN).is_none());
    }

    #[test]
    fn payloads_carry_the_magic_and_the_timestamp() {
        let payload = probe_payload(9, 424242);
        assert_eq!(&payload[..12], PAYLOAD_MAGIC);
        assert_eq!(u16::from_be_bytes([payload[12], payload[13]]), 9);
        assert_eq!(
            u64::from_be_bytes(payload[14..22].try_into().unwrap()),
            424242
        );
    }

    #[test]
    fn tcp_ping_sees_a_real_listener_and_a_closed_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();

        match tcp_probe(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            open_port,
            Duration::from_millis(300),
        ) {
            TcpProbe::Open(_) => {}
            other => panic!("expected Open, got {:?}", other),
        }

        let handle = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = handle.local_addr().unwrap().port();
        drop(handle);

        match tcp_probe(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            closed_port,
            Duration::from_millis(300),
        ) {
            TcpProbe::Refused(_) => {}
            other => panic!("expected Refused, got {:?}", other),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn icmp_ping_reaches_loopback_when_ping_sockets_exist() {
        // On systems without ping sockets this test simply steps aside;
        // everywhere else it proves the full ICMP round trip works.
        let Ok(socket) = IcmpSocket::new() else {
            return;
        };
        if socket
            .connect(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
            ))
            .is_err()
        {
            return;
        }
        let rtt = icmp_probe(&socket, 1, Duration::from_secs(2));
        assert!(rtt.is_some(), "loopback must answer an ICMP echo");
    }

    #[test]
    fn statistics_do_the_obvious_maths() {
        let rtts = [
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
        ];
        let (min, avg, max) = summarise(&rtts);
        assert_eq!(min, 10.0);
        assert_eq!(avg, 20.0);
        assert_eq!(max, 30.0);
    }

    #[test]
    fn ping_report_serializes_to_json() {
        let report = PingReport {
            target: "example.test".to_string(),
            resolved_ip: "192.0.2.1".to_string(),
            mode: "icmp".to_string(),
            probes_sent: 2,
            probes_received: 1,
            packet_loss_percent: 50.0,
            rtt_min_ms: Some(1.0),
            rtt_avg_ms: Some(1.0),
            rtt_max_ms: Some(1.0),
            replies: vec![PingReply {
                seq: 1,
                time_ms: Some(1.0),
                note: "1.00 ms".to_string(),
            }],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["mode"], "icmp");
        assert_eq!(value["packet_loss_percent"], 50.0);
        assert_eq!(value["replies"][0]["seq"], 1);
    }
}
