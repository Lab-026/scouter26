//! The `trace` command — "where does the path die?"
//!
//! Classic traceroute: echo probes whose IP time-to-live climbs one hop
//! at a time. Every router along the way decrements the TTL, and the one
//! that drops it to zero must answer with ICMP "Time Exceeded" —
//! betraying its address. The destination itself answers with a normal
//! Echo Reply, which ends the trace.
//!
//! The probes are hand-built ICMP echo messages; the kernel wraps them in
//! a proper IP header whose TTL we set per hop through the IP_TTL socket
//! option (the one thing userspace cannot normally touch, which is why
//! this command needs root). Replies arrive on a raw ICMP capture socket
//! with their IP headers intact, and are classified by hand: identifier +
//! sequence still survive inside Time Exceeded messages even though the
//! payload does not.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use colored::*;

use super::ping::build_echo_request;
use super::{RawSocket, local_source_ip, resolve_target};

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

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
        ICMP_ECHO_REPLY => {
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

    // One socket, two duties: it sends the probes (with a per-hop TTL set
    // through IP_TTL) and it hears every ICMP datagram that comes back.
    // Both halves need root, because raw sockets are how userspace touches
    // the TTL knob at all.
    let socket = RawSocket::icmp_capture().map_err(|error| {
        if error.raw_os_error() == Some(libc::EPERM) {
            "Traceroute touches the IP time-to-live knob, which the kernel only \
             allows to root.\n\
             Run it with:  sudo scouter26 trace <target>\n\
             (scouter26's ping, dns, scan, discover, udp, subnet and ports \
             commands never need root.)"
                .to_string()
        } else {
            format!("could not open a raw ICMP socket: {}", error)
        }
    })?;

    let src_ip = local_source_ip(target_ip)?;
    let identifier = 0x1964u16;
    let payload = *b"SCOUTER26-TRACE\x00"; // visible in Wireshark, 16 bytes

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
    let mut sent_times: HashMap<u16, Instant> = HashMap::new();

    for ttl in 1..=max_hops {
        let seq = ttl as u16;
        let echo = build_echo_request(identifier, seq, &payload);
        socket
            .set_ttl(ttl)
            .map_err(|error| format!("could not set TTL {}: {}", ttl, error))?;
        socket
            .send(&echo, target_ip)
            .map_err(|error| format!("could not send probe {}/{}: {}", ttl, max_hops, error))?;
        sent_times.insert(seq, Instant::now());

        // Wait for THIS probe's answer, ignoring everyone else's traffic.
        let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
        let mut outcome: Option<TraceEvent> = None;
        let mut buf = [0u8; 2048];
        while outcome.is_none()
            && let Some(remaining) = deadline.checked_duration_since(Instant::now())
        {
            socket.set_read_timeout(remaining);
            let Some(n) = socket.recv(&mut buf) else {
                break; // timeout slice elapsed: no answer for this hop
            };
            let event = classify_trace_reply(&buf[..n], identifier);
            let ours = event.as_ref().is_some_and(|event| match event {
                TraceEvent::Router(_, s) | TraceEvent::Destination(s) => *s == seq,
            });
            if ours {
                outcome = event;
            }
            // Somebody else's ICMP — ignore it and keep listening.
        }

        let rtt_ms = sent_times
            .get(&seq)
            .map(|sent| sent.elapsed().as_secs_f64() * 1000.0);

        match outcome {
            Some(TraceEvent::Router(router_ip, _)) => {
                let ms = rtt_ms.unwrap_or(0.0);
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
                let ms = rtt_ms.unwrap_or(0.0);
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

    /// Assemble a full ICMP datagram the way the kernel delivers it to a
    /// raw socket: IP header first, then the ICMP message.
    fn datagram(source: [u8; 4], icmp_type: u8, identifier: u16, seq: u16) -> Vec<u8> {
        let mut datagram = vec![0u8; 20 + 8];
        datagram[0] = 0x45; // IPv4, no options
        datagram[9] = 1; // protocol: ICMP
        datagram[12..16].copy_from_slice(&source);
        datagram[20] = icmp_type;
        datagram[24..26].copy_from_slice(&identifier.to_be_bytes());
        datagram[26..28].copy_from_slice(&seq.to_be_bytes());
        datagram
    }

    #[test]
    fn echo_replies_classify_as_the_destination() {
        let datagram = datagram([1, 1, 1, 1], ICMP_ECHO_REPLY, 0x1964, 5);
        match classify_trace_reply(&datagram, 0x1964) {
            Some(TraceEvent::Destination(5)) => {}
            other => panic!("expected Destination(5), got {:?}", other),
        }
    }

    #[test]
    fn time_exceeded_classifies_as_a_router() {
        // A Time Exceeded carries: outer IP (from the router) + ICMP type
        // 11 + the original IP header + the first 8 bytes of our original
        // ICMP header. Only the identifier and sequence survive the trip —
        // that is what we match on.
        let original = build_echo_request(0x1964, 3, &[0u8; 16]);
        let mut datagram = vec![0u8; 20 + 8 + 20 + 8];
        datagram[0] = 0x45;
        datagram[9] = 1;
        datagram[12..16].copy_from_slice(&[198, 51, 100, 7]); // the router
        datagram[20] = 11; // ICMP: Time Exceeded
        // Embedded original IP header (20 bytes) + our ICMP header (8)
        let embedded_ip = &mut datagram[28..48];
        embedded_ip[0] = 0x45;
        embedded_ip[9] = 1; // the original packet was ICMP too
        let embedded_icmp = &mut datagram[48..56];
        embedded_icmp.copy_from_slice(&original[..8]);

        match classify_trace_reply(&datagram, 0x1964) {
            Some(TraceEvent::Router(ip, 3)) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
            }
            other => panic!("expected Router(198.51.100.7, 3), got {:?}", other),
        }
    }

    #[test]
    fn other_peoples_icmp_is_ignored() {
        let wrong_id = datagram([1, 1, 1, 1], ICMP_ECHO_REPLY, 0xBEEF, 5);
        assert!(classify_trace_reply(&wrong_id, 0x1964).is_none());

        let mut not_icmp = datagram([1, 1, 1, 1], ICMP_ECHO_REPLY, 0x1964, 5);
        not_icmp[9] = 6; // protocol: TCP — not our kind of mail
        assert!(classify_trace_reply(&not_icmp, 0x1964).is_none());

        // A Time Exceeded whose embedded packet is not an echo request.
        let mut strange = vec![0u8; 20 + 8 + 20 + 8];
        strange[0] = 0x45;
        strange[9] = 1;
        strange[12..16].copy_from_slice(&[198, 51, 100, 7]);
        strange[20] = 11;
        strange[48] = 13; // embedded type: not an echo request
        assert!(classify_trace_reply(&strange, 0x1964).is_none());
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
