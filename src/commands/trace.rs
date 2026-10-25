//! The `trace` command — "where does the path die?"
//!
//! Classic traceroute, built by hand: echo requests whose IP time-to-live
//! climbs one hop at a time. Every router along the way decrements the
//! TTL, and the one that drops it to zero must answer with ICMP "Time
//! Exceeded" — betraying its address. The destination itself answers with
//! a normal Echo Reply, which ends the trace.
//!
//! Like the SYN scanner, this forges raw packets (the TTL field cannot be
//! set from userspace), so it needs root and speaks IPv4 only.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use colored::*;

use super::local_source_ip;
use super::resolve_target;
use super::{RawSocket, unlock};

const ICMP_ECHO_REQUEST: u8 = 8;

/// Build one complete IPv4+ICMP packet: the same hand-forgery as the SYN
/// scanner's TCP packets, but carrying an echo header instead — and with
/// a TTL we control, which is the entire trick behind traceroute.
// Eight parameters is the shape of the thing: an IP+ICMP header has
// exactly these knobs, and no struct would make the call sites clearer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_icmp4_echo(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    identifier: u16,
    seq: u16,
    payload: &[u8],
    ip_id: u16,
    icmp_type: u8,
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0u8; total_len];

    // --- IPv4 header ---
    packet[0] = 0x45; // version 4, no options
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    packet[8] = ttl; // ← the hop counter, the whole point of the command
    packet[9] = 1; // protocol: ICMP
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());
    let ip_checksum = super::internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // --- ICMP header + payload (checksummed on their own, no pseudo-header)
    let icmp = &mut packet[20..];
    icmp[0] = icmp_type;
    icmp[1] = 0; // code
    icmp[4..6].copy_from_slice(&identifier.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let icmp_checksum = super::internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

/// What an incoming ICMP datagram means for our trace. Replies are
/// matched to our probes by identifier + sequence — the payload does not
/// survive inside Time Exceeded messages, but those two fields do.
#[derive(Debug, PartialEq)]
pub(crate) enum TraceEvent {
    /// A router at this hop dropped our packet and said so.
    Router(IpAddr, u16),
    /// The destination itself answered: the trace is complete.
    Destination(u16),
}

pub(crate) fn classify_trace_reply(datagram: &[u8], our_id: u16) -> Option<TraceEvent> {
    if datagram.len() < 28 {
        return None;
    }
    let header_words = (datagram[0] & 0x0F) as usize;
    if datagram[0] >> 4 != 4 || header_words < 5 || datagram[9] != 1 {
        return None; // not IPv4, or not ICMP
    }
    let source = IpAddr::V4(Ipv4Addr::new(
        datagram[12],
        datagram[13],
        datagram[14],
        datagram[15],
    ));
    let icmp = datagram.get(header_words * 4..)?;
    if icmp.len() < 8 {
        return None;
    }

    match icmp[0] {
        0 => {
            // Echo Reply — the destination itself answered our last probe.
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            if id == our_id {
                Some(TraceEvent::Destination(seq))
            } else {
                None
            }
        }
        11 => {
            // Time Exceeded — a router dropped the packet. The message
            // embeds our original IP header + the first 8 bytes of our
            // original ICMP header, which is exactly where our
            // identifier and sequence still live.
            if icmp.len() < 8 + 28 {
                return None;
            }
            let inner_header_words = (icmp[8] & 0x0F) as usize * 4;
            let inner = icmp.get(8 + inner_header_words..)?;
            if inner.len() < 8 || inner[0] != ICMP_ECHO_REQUEST {
                return None;
            }
            let id = u16::from_be_bytes([inner[4], inner[5]]);
            let seq = u16::from_be_bytes([inner[6], inner[7]]);
            if id != our_id {
                return None;
            }
            Some(TraceEvent::Router(source, seq))
        }
        _ => None,
    }
}

// ============================================================
// The JSON report (--json / --output).
// ============================================================

#[derive(serde::Serialize)]
struct TraceHop {
    ttl: u8,
    ip: Option<String>,
    rtt_ms: Option<f64>,
    note: String,
}

#[derive(serde::Serialize)]
struct TraceReport {
    target: String,
    resolved_ip: String,
    source_ip: String,
    max_hops: u8,
    reached: bool,
    hops: Vec<TraceHop>,
}

/// Entry point for `scouter26 trace <target>`.
pub fn execute(
    target: &str,
    max_hops: u8,
    timeout_secs: f64,
    json: bool,
    output: &Option<PathBuf>,
) -> Result<(), String> {
    let started_at = Instant::now();

    if max_hops == 0 || max_hops > 30 {
        return Err("hops must be between 1 and 30".to_string());
    }
    if !(0.05..=10.0).contains(&timeout_secs) {
        return Err("timeout must be between 0.05 and 10 seconds".to_string());
    }

    // IPv4 only, like the SYN scanner: raw IPv6 follows different rules.
    let target_ip = match resolve_target(target, false)? {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(format!(
                "'{}' is an IPv6 target and tracing is IPv4-only for now",
                target
            ));
        }
    };

    let socket = RawSocket::new().map_err(|error| {
        if error.raw_os_error() == Some(libc::EPERM) {
            "Traceroute forges raw packets, which the kernel only allows to root.\n\
             Run it with:  sudo scouter26 trace <target>\n\
             (scouter26's ping, scan, discover, udp, subnet and ports commands never need root.)"
                .to_string()
        } else {
            format!("could not open a raw socket: {}", error)
        }
    })?;

    let src_ip = local_source_ip(target_ip)?;
    let identifier = 0x1964u16;
    let payload = [0u8; 16];
    let sent_times: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    if !json {
        println!("{}", "========================================".cyan());
        println!("{}", " Scouter26 - Traceroute".cyan().bold());
        println!(
            " {}{} from {}",
            "Target: ".cyan(),
            format!("{} ({})", target, target_ip).cyan(),
            src_ip.to_string().cyan()
        );
        println!(
            " {}{}",
            "Limits: ".cyan(),
            format!("{} hops max, {}s per hop", max_hops, timeout_secs).cyan()
        );
        println!("{}", "----------------------------------------".cyan());
    }

    let mut hops: Vec<TraceHop> = Vec::new();
    let mut reached = false;

    for ttl in 1..=max_hops {
        let seq = ttl as u16;
        let packet = build_icmp4_echo(
            src_ip,
            target_ip,
            ttl,
            identifier,
            seq,
            &payload,
            0x1964 + ttl as u16,
            ICMP_ECHO_REQUEST,
        );
        socket
            .send(&packet, target_ip)
            .map_err(|error| format!("could not send probe {}/{}: {}", ttl, max_hops, error))?;
        sent_times
            .lock()
            .unwrap_or_else(unlock)
            .insert(seq, Instant::now());

        // Wait for THIS probe's answer, ignoring everyone else's traffic.
        let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
        let mut outcome: Option<TraceEvent> = None;
        let mut buf = [0u8; 2048];
        loop {
            let remaining = deadline.checked_duration_since(Instant::now());
            let Some(remaining) = remaining else { break };
            socket.set_read_timeout(remaining);
            match socket.recv(&mut buf) {
                Some(n) => match classify_trace_reply(&buf[..n], identifier) {
                    Some(event @ TraceEvent::Router(_, s)) if s == seq => {
                        outcome = Some(event);
                        break;
                    }
                    Some(event @ TraceEvent::Destination(s)) if s == seq => {
                        outcome = Some(event);
                        break;
                    }
                    _ => continue, // somebody else's ICMP — ignore it
                },
                None => break, // timeout slice elapsed: no answer for this hop
            }
        }

        let rtt = |seq: u16| -> Option<f64> {
            sent_times
                .lock()
                .unwrap_or_else(unlock)
                .get(&seq)?
                .elapsed()
                .as_secs_f64()
                .mul_add(1000.0, 0.0)
                .into()
        };

        match outcome {
            Some(TraceEvent::Router(router_ip, _)) => {
                let ms = rtt(seq).unwrap_or(0.0);
                hops.push(TraceHop {
                    ttl,
                    ip: Some(router_ip.to_string()),
                    rtt_ms: Some(ms),
                    note: "time exceeded".to_string(),
                });
                if !json {
                    println!(
                        " {:>3}  {:<43} {}",
                        ttl,
                        router_ip.to_string().green(),
                        format!("{:.2} ms", ms).dimmed()
                    );
                }
            }
            Some(TraceEvent::Destination(_)) => {
                let ms = rtt(seq).unwrap_or(0.0);
                hops.push(TraceHop {
                    ttl,
                    ip: Some(target_ip.to_string()),
                    rtt_ms: Some(ms),
                    note: "destination reached".to_string(),
                });
                if !json {
                    println!(
                        " {:>3}  {:<43} {}",
                        ttl,
                        target_ip.to_string().green().bold(),
                        format!("{:.2} ms — destination reached", ms).dimmed()
                    );
                }
                reached = true;
                break;
            }
            None => {
                hops.push(TraceHop {
                    ttl,
                    ip: None,
                    rtt_ms: None,
                    note: "no reply".to_string(),
                });
                if !json {
                    println!(" {:>3}  {:<43}", ttl, "*".red());
                }
            }
        }

        // A short, fixed pause between hops keeps us polite to routers.
        if !reached {
            thread::sleep(Duration::from_millis(100));
        }
    }

    if !json {
        println!("{}", "========================================".cyan());
        println!(
            "{}",
            format!(
                " {} in {:.2}s — {} hops{}.",
                if reached {
                    "Trace complete"
                } else {
                    "Trace ended (target not reached)"
                },
                started_at.elapsed().as_secs_f32(),
                hops.len(),
                if reached {
                    ""
                } else {
                    "; the path may be filtered beyond here"
                }
            )
            .cyan()
        );
    }

    if json || output.is_some() {
        let report = TraceReport {
            target: target.to_string(),
            resolved_ip: target_ip.to_string(),
            source_ip: src_ip.to_string(),
            max_hops,
            reached,
            hops,
        };
        if let Some(path) = output {
            super::write_report(path, &report)?;
            eprintln!("{}", format!(" Report saved to {}", path.display()).cyan());
        }
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("TraceReport always serializes")
            );
            return Ok(());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_packets_carry_their_ttl_and_valid_checksums() {
        let packet = build_icmp4_echo(
            Ipv4Addr::new(192, 168, 18, 29),
            Ipv4Addr::new(1, 1, 1, 1),
            7, // TTL
            0x1964,
            7,
            &[0u8; 16],
            0x1971,
            ICMP_ECHO_REQUEST,
        );
        assert_eq!(packet[8], 7, "the TTL byte is the whole point");
        assert_eq!(packet[9], 1, "protocol: ICMP");
        assert_eq!(packet[20], 8, "ICMP type: echo request");
        // RFC property: the IP header including its checksum sums to 0xFFFF.
        let mut sum = 0u32;
        for word in packet[..20].as_chunks::<2>().0 {
            sum += u16::from_be_bytes(*word) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum, 0xFFFF, "IP checksum must be self-verifying");
    }

    #[test]
    fn echo_replies_classify_as_the_destination() {
        // Build what the destination sends back: our own echo packet with
        // the type flipped from request (8) to reply (0).
        let request = build_icmp4_echo(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(192, 168, 18, 29),
            64,
            0x1964,
            5,
            &[0u8; 16],
            0x1971,
            ICMP_ECHO_REQUEST,
        );
        let mut reply = request;
        reply[20] = 0; // ICMP type: echo reply

        match classify_trace_reply(&reply, 0x1964) {
            Some(TraceEvent::Destination(5)) => {}
            other => panic!("expected Destination(5), got {:?}", other),
        }
    }

    #[test]
    fn time_exceeded_classifies_as_a_router() {
        // The router sends back: outer IP (from the router) + ICMP type 11
        // + our original IP header + our original ICMP header (8 bytes).
        let original = build_icmp4_echo(
            Ipv4Addr::new(192, 168, 18, 29),
            Ipv4Addr::new(1, 1, 1, 1),
            3, // the TTL that died here
            0x1964,
            3,
            &[0u8; 16],
            0x1971,
            ICMP_ECHO_REQUEST,
        );

        let router_ip = [198, 51, 100, 7];
        let mut datagram = vec![0u8; 20 + 8 + 20 + 8];
        // Outer IP header: from the router, protocol ICMP
        datagram[0] = 0x45;
        datagram[9] = 1;
        datagram[12..16].copy_from_slice(&router_ip);
        // Outer ICMP: Time Exceeded
        let icmp = &mut datagram[20..];
        icmp[0] = 11;
        // Embedded original: full IP header + first 8 bytes of the ICMP
        let embedded = &mut datagram[28..];
        embedded.copy_from_slice(&original[..28]);

        match classify_trace_reply(&datagram, 0x1964) {
            Some(TraceEvent::Router(ip, 3)) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
            }
            other => panic!("expected Router(198.51.100.7, 3), got {:?}", other),
        }
    }

    #[test]
    fn other_peoples_icmp_is_ignored() {
        let original = build_icmp4_echo(
            Ipv4Addr::new(192, 168, 18, 29),
            Ipv4Addr::new(1, 1, 1, 1),
            3,
            0x1964,
            3,
            &[0u8; 16],
            0x1971,
            ICMP_ECHO_REQUEST,
        );
        let mut datagram = vec![0u8; 20 + 8 + 28];
        datagram[0] = 0x45;
        datagram[9] = 1;
        datagram[12..16].copy_from_slice(&[198, 51, 100, 7]);
        datagram[20] = 11;
        datagram[28..].copy_from_slice(&original[..28]);

        // Wrong identifier: none of our business.
        assert!(classify_trace_reply(&datagram, 0xBEEF).is_none());
        // Not ICMP at all: ignored.
        let mut tcpish = datagram.clone();
        tcpish[9] = 6;
        assert!(classify_trace_reply(&tcpish, 0x1964).is_none());
    }

    #[test]
    fn trace_report_serializes_to_json() {
        let report = TraceReport {
            target: "example.test".to_string(),
            resolved_ip: "192.0.2.1".to_string(),
            source_ip: "192.0.2.10".to_string(),
            max_hops: 15,
            reached: true,
            hops: vec![TraceHop {
                ttl: 1,
                ip: Some("192.168.1.1".to_string()),
                rtt_ms: Some(1.42),
                note: "time exceeded".to_string(),
            }],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["reached"], true);
        assert_eq!(value["hops"][0]["ip"], "192.168.1.1");
        assert_eq!(value["hops"][0]["rtt_ms"], 1.42);
    }
}
