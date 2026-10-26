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
//! with their IP headers intact, and are classified by hand against the
//! probe's FULL identity: identifier, sequence, source and destination
//! addresses, the TTL, and — because Echo Replies carry the payload back
//! verbatim — the probe's embedded process id and per-run token. Time
//! Exceeded messages truncate the payload, but they embed the original IP
//! header, which still carries our source, destination and TTL, and those
//! are checked too. Matching less than the full identity would let
//! unrelated or replayed replies be misattributed. These checks reject
//! mismatched traffic; they do not authenticate the sender.

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

/// The traceroute's identity on the wire is the PAIR (identifier,
/// sequence base), and that pair is a lossless split of the 32-bit
/// process id: the identifier carries the low 16 bits, the sequence base
/// the high 16 bits. Two different processes can therefore never share
/// both fields at once — not "unlikely", impossible, for any pid the OS
/// can assign. (The identifier field alone can still collide — pids 1
/// and 65537 share one — that is the 16-bit ceiling of the ICMP header,
/// and precisely why the sequence base exists.)
fn trace_identity(pid: u32) -> (u16, u16) {
    (0x1964 ^ (pid & 0xFFFF) as u16, 0x5C01 ^ (pid >> 16) as u16)
}

/// The full identity of one probe in flight. Every field here is checked
/// against incoming replies — because the transmitted (identifier,
/// sequence) pair alone can alias across processes and hops.
pub(crate) struct ProbeIdentity {
    /// ICMP identifier: the low 16 bits of the process id, fingerprinted.
    id: u16,
    /// The full process id — carried in the probe payload and verified in
    /// Echo Replies, which return the payload verbatim.
    pid: u32,
    /// The 64-bit per-run token — also carried in the payload and
    /// verified in Echo Replies; this is what rejects replies from an
    /// earlier run even when everything else matches.
    token: u64,
    /// Our address: validated as the embedded source in Time Exceeded.
    source: Ipv4Addr,
    /// The traced destination: validated as the source of Echo Replies
    /// and the embedded destination in Time Exceeded.
    destination: Ipv4Addr,
    /// This probe's TTL: validated against the embedded header in Time
    /// Exceeded and carried in the payload of Echo Replies.
    ttl: u8,
    /// The transmitted sequence number: per-process base + TTL.
    seq: u16,
}

impl ProbeIdentity {
    pub(crate) fn new(
        pid: u32,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        ttl: u8,
        run_nonce: u16,
        token: u64,
    ) -> Self {
        let (id, base) = trace_identity(pid);
        ProbeIdentity {
            id,
            pid,
            token,
            source,
            destination,
            ttl,
            // The run nonce decorrelates sequence numbers across runs: a
            // delayed reply from an earlier trace carries a sequence
            // derived from a different nonce, and is rejected. XOR is a
            // bijection, so per-hop distinctness within one run is
            // preserved.
            seq: base.wrapping_add(ttl as u16) ^ run_nonce,
        }
    }
}

/// The probe payload: magic + full 32-bit pid + ttl. Echo Replies return
/// it verbatim, which lets us verify a reply is truly ours even when the
/// 16-bit identifier and sequence have aliased across processes.
fn trace_payload(pid: u32, ttl: u8, token: u64) -> [u8; 24] {
    let mut payload = [0u8; 24];
    payload[..8].copy_from_slice(b"SC26TRAC");
    payload[8..12].copy_from_slice(&pid.to_be_bytes());
    payload[12..14].copy_from_slice(&(ttl as u16).to_be_bytes());
    payload[14..16].copy_from_slice(&0u16.to_be_bytes()); // reserved
    payload[16..24].copy_from_slice(&token.to_be_bytes());
    payload
}

/// A per-run value mixed into the sequence numbers. Honest limits: it is
/// 16 bits, so two runs can repeat it — this REDUCES accidental cross-run
/// matches, it does not prevent them. The 64-bit run token (see
/// run_token) carried in the payload is what Echo Replies validate for
/// real cross-run replay rejection.
fn run_nonce(pid: u32) -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16;
    nanos ^ (pid as u16) ^ ((pid >> 16) as u16)
}

/// A 64-bit per-run token, carried in the probe payload and verified in
/// every Echo Reply. The base value is drawn from the operating system
/// (std's RandomState is OS-seeded — the strongest randomness the
/// standard library offers without adding a dependency), then mixed with
/// the pid. This makes accidental cross-run token matches astronomically
/// unlikely; it is still not cryptographic authentication. Time Exceeded
/// messages quote only the original IP header and the first eight ICMP
/// bytes, so the token cannot travel in them — cross-run protection there
/// rests on the 16-bit sequence nonce, and the docs say so.
fn run_token(pid: u32) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let os = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    os ^ nanos ^ ((pid as u64) << 32) ^ ((pid as u64).rotate_left(17))
}

/// What an incoming ICMP datagram means for our trace. Every classification
/// requires the reply to carry our full identity — see ProbeIdentity.
#[derive(Debug, PartialEq)]
pub(crate) enum TraceEvent {
    /// A router at this hop dropped our packet and said so.
    Router(IpAddr, u16),
    /// The destination itself answered: the trace is complete.
    Destination(u16),
}

pub(crate) fn classify_trace_reply(datagram: &[u8], probe: &ProbeIdentity) -> Option<TraceEvent> {
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
            // Echo Reply — trusted only when every identity field agrees:
            // it must come from the traced destination, carry our
            // identifier and sequence, and echo back a payload containing
            // our full pid and this probe's TTL.
            if icmp.len() < 8 + 24 {
                return None;
            }
            let id = u16::from_be_bytes([icmp[4], icmp[5]]);
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            if id != probe.id || seq != probe.seq || source != probe.destination {
                return None;
            }
            let payload = &icmp[8..8 + 24];
            if &payload[..8] != b"SC26TRAC"
                || u32::from_be_bytes(payload[8..12].try_into().ok()?) != probe.pid
                || u16::from_be_bytes(payload[12..14].try_into().ok()?) != probe.ttl as u16
                || u64::from_be_bytes(payload[16..24].try_into().ok()?) != probe.token
            {
                return None;
            }
            Some(TraceEvent::Destination(seq))
        }
        11 if icmp[1] == 0 => {
            // Time Exceeded, code 0: TTL exceeded in transit — the
            // traceroute signal. Code 1 (fragment reassembly time) cannot
            // occur for our probes: they carry the Don't Fragment flag and
            // are far smaller than any reassembly threshold, so we ignore
            // anything else rather than guess about it.
            // The message embeds our original IP header + the first 8 bytes
            // of our original ICMP header, which is exactly where our
            // identifier and sequence still live.
            // embeds our original IP header + the first 8 bytes of our
            // original ICMP header, which is exactly where our
            // identifier and sequence still live. Before trusting any of
            // that, the embedded packet must prove it is *ours*: sane IPv4
            // ICMP, sent from our address, to the destination we are
            // tracing, at this hop's TTL. An unrelated Time Exceeded
            // embeds a probe that was never ours and fails here. (These
            // checks separate our traffic from unrelated traffic; they are
            // not cryptographic authentication — the wire format is
            // public.)
            if icmp.len() < 8 + 28 {
                return None;
            }
            if icmp[8] >> 4 != 4 || (icmp[8] & 0x0F) < 5 || icmp[8 + 9] != 1 {
                return None; // embedded packet is not a sane IPv4 ICMP probe
            }
            let inner_src = Ipv4Addr::new(icmp[8 + 12], icmp[8 + 13], icmp[8 + 14], icmp[8 + 15]);
            let inner_dst = Ipv4Addr::new(icmp[8 + 16], icmp[8 + 17], icmp[8 + 18], icmp[8 + 19]);
            let inner_ttl = icmp[8 + 8];
            if inner_src != probe.source || inner_dst != probe.destination || inner_ttl != probe.ttl
            {
                return None; // the embedded probe was not this hop's probe
            }
            let inner_header_words = (icmp[8] & 0x0F) as usize * 4;
            let inner = icmp.get(8 + inner_header_words..)?;
            if inner.len() < 8 || inner[0] != ICMP_ECHO_REQUEST {
                return None;
            }
            let id = u16::from_be_bytes([inner[4], inner[5]]);
            let seq = u16::from_be_bytes([inner[6], inner[7]]);
            if id != probe.id || seq != probe.seq {
                return None; // the embedded probe is not this hop's probe
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
    // A per-process identity: the (identifier, sequence base) pair is a
    // lossless split of this process's id, so two concurrent traces from
    // this machine can never share both fields. (The payload does not
    // survive inside Time Exceeded messages, so this pair is our
    // identity on the wire.)
    let pid = std::process::id();
    let run_nonce = run_nonce(pid);
    let token = run_token(pid);

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
        let probe = ProbeIdentity::new(pid, src_ip, target_ip, ttl, run_nonce, token);
        let echo = build_echo_request(probe.id, probe.seq, &trace_payload(pid, ttl, token));
        socket
            .set_ttl(ttl)
            .map_err(|error| format!("could not set TTL {}: {}", ttl, error))?;
        socket
            .send(&echo, target_ip)
            .map_err(|error| format!("could not send probe {}/{}: {}", ttl, max_hops, error))?;
        sent_times.insert(probe.seq, Instant::now());

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
            let event = classify_trace_reply(&buf[..n], &probe);
            let ours = event.as_ref().is_some_and(|event| match event {
                TraceEvent::Router(_, s) | TraceEvent::Destination(s) => *s == probe.seq,
            });
            if ours {
                outcome = event;
            }
            // Somebody else's ICMP — ignore it and keep listening.
        }

        let rtt_ms = sent_times
            .get(&probe.seq)
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

    /// A complete ProbeIdentity for testing, with the aliasing pair from
    /// the round-7 review: PID 1 at TTL 2 and PID 65537 at TTL 1 transmit
    /// the same (identifier, sequence) pair.
    fn probe_a() -> ProbeIdentity {
        ProbeIdentity {
            id: 0x1965,
            pid: 1,
            token: 0xAAAA_0000_0000_0001,
            source: Ipv4Addr::new(192, 168, 18, 29),
            destination: Ipv4Addr::new(1, 1, 1, 1),
            ttl: 2,
            seq: 0x5C03,
        }
    }

    fn probe_b() -> ProbeIdentity {
        ProbeIdentity {
            id: 0x1965,
            pid: 65_537,
            token: 0xBBBB_0000_0000_0002,
            source: Ipv4Addr::new(192, 168, 18, 29),
            destination: Ipv4Addr::new(1, 1, 1, 1),
            ttl: 1,
            seq: 0x5C03,
        }
    }

    fn probe_a_previous_run() -> ProbeIdentity {
        // The same pid, destination, hop, identifier and sequence as
        // probe_a — but from an earlier run, so the run token differs.
        // This is the replay scenario the 64-bit token exists to reject.
        ProbeIdentity {
            id: 0x1965,
            pid: 1,
            token: 0xAAAA_0000_0000_0000,
            source: Ipv4Addr::new(192, 168, 18, 29),
            destination: Ipv4Addr::new(1, 1, 1, 1),
            ttl: 2,
            seq: 0x5C03,
        }
    }

    /// Assemble an Echo Reply datagram as the destination would send it:
    /// IP header from the destination, then our echo reply with our full
    /// payload echoed back.
    fn echo_reply(from: [u8; 4], probe: &ProbeIdentity) -> Vec<u8> {
        let payload = trace_payload(probe.pid, probe.ttl, probe.token);
        let mut datagram = vec![0u8; 20 + 8 + payload.len()];
        datagram[0] = 0x45;
        datagram[9] = 1; // ICMP
        datagram[12..16].copy_from_slice(&from);
        datagram[20] = ICMP_ECHO_REPLY;
        datagram[24..26].copy_from_slice(&probe.id.to_be_bytes());
        datagram[26..28].copy_from_slice(&probe.seq.to_be_bytes());
        datagram[28..].copy_from_slice(&payload);
        datagram
    }

    /// Assemble a Time Exceeded datagram as a router would send it: outer
    /// IP from the router, ICMP type 11 code 0, then the embedded original
    /// IP header + the first 8 bytes of our original echo request.
    fn time_exceeded(router: [u8; 4], probe: &ProbeIdentity) -> Vec<u8> {
        let mut datagram = vec![0u8; 20 + 8 + 20 + 8];
        datagram[0] = 0x45;
        datagram[9] = 1;
        datagram[12..16].copy_from_slice(&router);
        datagram[20] = 11;
        datagram[21] = 0; // code: TTL exceeded in transit
        let embedded_ip = &mut datagram[28..48];
        embedded_ip[0] = 0x45;
        embedded_ip[8] = probe.ttl; // the TTL that died here
        embedded_ip[9] = 1;
        embedded_ip[12..16].copy_from_slice(&probe.source.octets());
        embedded_ip[16..20].copy_from_slice(&probe.destination.octets());
        let embedded_icmp = &mut datagram[48..56];
        embedded_icmp[0] = ICMP_ECHO_REQUEST;
        embedded_icmp[4..6].copy_from_slice(&probe.id.to_be_bytes());
        embedded_icmp[6..8].copy_from_slice(&probe.seq.to_be_bytes());
        datagram
    }

    #[test]
    fn probe_payloads_carry_the_full_identity() {
        let payload = trace_payload(65_537, 3, 0x1234_5678_9ABC_DEF0);
        assert_eq!(&payload[..8], b"SC26TRAC");
        assert_eq!(
            u32::from_be_bytes(payload[8..12].try_into().unwrap()),
            65_537
        );
        assert_eq!(u16::from_be_bytes(payload[12..14].try_into().unwrap()), 3);
        assert_eq!(
            u64::from_be_bytes(payload[16..24].try_into().unwrap()),
            0x1234_5678_9ABC_DEF0
        );
    }

    #[test]
    fn echo_replies_classify_as_the_destination() {
        let reply = echo_reply([1, 1, 1, 1], &probe_a());
        match classify_trace_reply(&reply, &probe_a()) {
            Some(TraceEvent::Destination(0x5C03)) => {}
            other => panic!("expected Destination, got {:?}", other),
        }
    }

    #[test]
    fn time_exceeded_classifies_as_a_router() {
        let te = time_exceeded([198, 51, 100, 7], &probe_a());
        match classify_trace_reply(&te, &probe_a()) {
            Some(TraceEvent::Router(ip, 0x5C03)) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
            }
            other => panic!("expected Router, got {:?}", other),
        }
    }

    #[test]
    fn aliased_probes_from_different_processes_stay_separated() {
        // The round-7 review scenario: both probes transmit the same
        // (identifier, sequence) pair. The payload pid + ttl (Echo Reply)
        // and the embedded TTL (Time Exceeded) are what separate them.
        let reply_to_a = echo_reply([1, 1, 1, 1], &probe_a());
        let te_about_a = time_exceeded([198, 51, 100, 7], &probe_a());

        // Probe B must not claim either of A's replies...
        assert!(classify_trace_reply(&reply_to_a, &probe_b()).is_none());
        assert!(classify_trace_reply(&te_about_a, &probe_b()).is_none());

        // ...and probe A must.
        assert!(classify_trace_reply(&reply_to_a, &probe_a()).is_some());
        assert!(classify_trace_reply(&te_about_a, &probe_a()).is_some());
    }

    #[test]
    fn other_peoples_icmp_is_ignored() {
        // Wrong identifier.
        let mut reply = echo_reply([1, 1, 1, 1], &probe_a());
        reply[24] ^= 0xFF;
        assert!(classify_trace_reply(&reply, &probe_a()).is_none());

        // Not ICMP at all.
        let mut tcpish = echo_reply([1, 1, 1, 1], &probe_a());
        tcpish[9] = 6;
        assert!(classify_trace_reply(&tcpish, &probe_a()).is_none());

        // A Time Exceeded whose embedded packet is not an echo request.
        let mut strange = time_exceeded([198, 51, 100, 7], &probe_a());
        strange[48] = 13;
        assert!(classify_trace_reply(&strange, &probe_a()).is_none());

        // A Time Exceeded with code 1: impossible for our DF-marked,
        // unfragmented probes, so it is never a hop.
        let mut code1 = time_exceeded([198, 51, 100, 7], &probe_a());
        code1[21] = 1;
        assert!(classify_trace_reply(&code1, &probe_a()).is_none());

        // An Echo Reply whose payload names a different process.
        let mut foreign_payload = echo_reply([1, 1, 1, 1], &probe_a());
        foreign_payload[32] ^= 0xFF; // corrupt the embedded pid
        assert!(classify_trace_reply(&foreign_payload, &probe_a()).is_none());

        // An Echo Reply whose payload carries a different run token.
        let mut stale_payload = echo_reply([1, 1, 1, 1], &probe_a());
        stale_payload[40] ^= 0xFF; // corrupt the embedded run token
        assert!(classify_trace_reply(&stale_payload, &probe_a()).is_none());
    }

    #[test]
    fn an_echo_reply_from_a_previous_run_is_rejected() {
        // Cross-run replay: same pid, destination, hop, identifier and
        // sequence — only the run token differs. The reply from the
        // earlier run must not be accepted as this run's answer.
        let stale = echo_reply([1, 1, 1, 1], &probe_a_previous_run());
        assert!(classify_trace_reply(&stale, &probe_a()).is_none());

        let current = echo_reply([1, 1, 1, 1], &probe_a());
        assert!(classify_trace_reply(&current, &probe_a()).is_some());
    }

    #[test]
    fn identity_pairs_are_unique_across_a_wide_pid_range() {
        // The (identifier, base) pair is a lossless split of the pid, so
        // no two pids in this range — crossing the 16-bit boundary where
        // identifier-only collisions appear — may share a pair.
        let pairs: std::collections::HashSet<(u16, u16)> =
            (1u32..=70_000).map(trace_identity).collect();
        assert_eq!(pairs.len(), 70_000);
    }

    #[test]
    fn the_identifier_ceiling_does_not_spread_to_the_base() {
        // Pids 1 and 65537 share the same low 16 bits, so their
        // identifier fields collide — the honest 16-bit ceiling of the
        // ICMP header. The sequence bases must still differ, which is
        // what makes cross-talk impossible between them.
        let (id_a, base_a) = trace_identity(1);
        let (id_b, base_b) = trace_identity(65_537);
        assert_eq!(id_a, id_b, "the identifier ceiling is real");
        assert_ne!(base_a, base_b, "but the bases keep them distinct");
    }

    #[test]
    fn sequence_numbers_stay_distinct_across_the_hop_range() {
        let base = trace_identity(4194).1;
        let seqs: std::collections::HashSet<u16> = (1u8..=30)
            .map(|ttl| base.wrapping_add(ttl as u16))
            .collect();
        assert_eq!(seqs.len(), 30);
    }

    #[test]
    fn a_time_exceeded_with_the_wrong_embedded_sequence_is_rejected() {
        // Regression: the classifier itself must enforce the full identity,
        // not rely on the caller to filter sequence mismatches afterward.
        // Everything matches here except the embedded sequence.
        let mut wrong_seq = time_exceeded([198, 51, 100, 7], &probe_a());
        wrong_seq[54] ^= 0xFF; // corrupt the embedded sequence number
        assert!(classify_trace_reply(&wrong_seq, &probe_a()).is_none());

        // The intact message still passes, proving the corruption is what
        // made the difference.
        assert!(
            classify_trace_reply(&time_exceeded([198, 51, 100, 7], &probe_a()), &probe_a())
                .is_some()
        );
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
