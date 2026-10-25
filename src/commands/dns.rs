//! The `dns` command — "why can't they reach mail.corp.local?", answered.
//!
//! Queries are built and responses parsed by hand, byte by byte (same
//! spirit as every scanner in this toolbox): header, question, then the
//! answer records — including DNS name compression, where a name can be
//! replaced by a pointer to a previous copy.
//!
//! Default server: whatever /etc/resolv.conf says (the system resolver —
//! exactly what the user's machine actually uses), overridable with
//! --server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use colored::*;

use super::resolve_target;

const DNS_PORT: u16 = 53;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Record type codes (the ones an IT Support shift actually meets).
fn type_code(name: &str) -> Result<u16, String> {
    match name.to_uppercase().as_str() {
        "A" => Ok(1),
        "NS" => Ok(2),
        "CNAME" => Ok(5),
        "SOA" => Ok(6),
        "PTR" => Ok(12),
        "MX" => Ok(15),
        "TXT" => Ok(16),
        "AAAA" => Ok(28),
        other => Err(format!(
            "unknown record type '{}'. Valid: A, AAAA, CNAME, MX, TXT, NS, PTR, SOA",
            other
        )),
    }
}

fn type_name(code: u16) -> &'static str {
    match code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "OTHER",
    }
}

fn rcode_message(rcode: u16) -> String {
    match rcode {
        1 => "FORMERR: the server could not parse the query".to_string(),
        2 => "SERVFAIL: the server failed internally".to_string(),
        3 => "NXDOMAIN: that name does not exist".to_string(),
        4 => "NOTIMP: the server does not implement this record type".to_string(),
        5 => "REFUSED: the server refused the query".to_string(),
        other => format!("DNS error code {}", other),
    }
}

/// The first nameserver the system itself uses, read from /etc/resolv.conf.
/// Falls back to Cloudflare's 1.1.1.1 when nothing sensible is found.
fn first_system_nameserver() -> IpAddr {
    if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in resolv.lines() {
            if let Some(server) = line.strip_prefix("nameserver")
                && let Ok(ip) = server.trim().parse::<IpAddr>()
            {
                return ip;
            }
        }
    }
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
}

// ============================================================
// Query building.
// ============================================================

/// Encode a domain name as DNS labels: "\x07github\x03com\x00".
fn encode_name(name: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let trimmed = name.trim().trim_end_matches('.');
    for label in trimmed.split('.') {
        if label.is_empty() {
            continue; // tolerate doubled dots
        }
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return Err(format!("label '{}' is too long (max 63 bytes)", label));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0); // the root label terminates the name
    if out.len() > 255 {
        return Err(format!("name '{}' exceeds 255 bytes", name));
    }
    Ok(out)
}

/// Build a standard recursive query: header + question + type + class IN.
fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: recursion desired
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    query.extend(encode_name(name)?);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(query)
}

// ============================================================
// Response parsing.
// ============================================================

/// Parse a possibly-compressed domain name starting at `offset`.
/// Returns (name, offset-after-the-name-in-the-outer-message) — the
/// second value matters because compressed names are two bytes long but
/// spell out many.
fn parse_name(message: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut hops = 0;

    loop {
        let length = *message.get(offset)?;
        match length & 0xC0 {
            0x00 => {
                if length == 0 {
                    offset += 1;
                    if !jumped {
                        next_offset = offset;
                    }
                    break;
                }
                let end = offset + 1 + length as usize;
                if end > message.len() {
                    return None;
                }
                labels.push(String::from_utf8_lossy(&message[offset + 1..end]).to_string());
                offset = end;
                if !jumped {
                    next_offset = offset;
                }
            }
            0xC0 => {
                // Compression pointer: the name continues elsewhere in the
                // message. 14 bits of offset, hidden in this byte's lower
                // 6 bits plus the whole next byte.
                let high = (length & 0x3F) as usize;
                let low = *message.get(offset + 1)? as usize;
                if !jumped {
                    next_offset = offset + 2;
                    jumped = true;
                }
                offset = (high << 8) | low;
                hops += 1;
                if hops > 32 {
                    return None; // a compression loop is a malformed message
                }
            }
            _ => return None, // 0x40/0x80 are reserved, never seen in the wild
        }
    }

    Some((labels.join("."), next_offset))
}

/// One rendered answer record.
#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub name: String,
    pub kind: String,
    pub value: String,
    pub ttl: u32,
}

/// Render the RDATA of one record. Unknown types fall back to a byte
/// count — the tool reports what it knows, not what it guesses.
fn render_rdata(message: &[u8], rtype: u16, start: usize, end: usize) -> Option<String> {
    match rtype {
        1 => {
            if end - start != 4 {
                return None;
            }
            Some(
                Ipv4Addr::new(
                    message[start],
                    message[start + 1],
                    message[start + 2],
                    message[start + 3],
                )
                .to_string(),
            )
        }
        28 => {
            if end - start != 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&message[start..end]);
            Some(Ipv6Addr::from(octets).to_string())
        }
        2 | 5 | 12 => parse_name(message, start).map(|(name, _)| name),
        15 => {
            // MX: a 16-bit preference, then a mail server name.
            let preference = u16::from_be_bytes([message[start], message[start + 1]]);
            parse_name(message, start + 2).map(|(name, _)| format!("{} {}", preference, name))
        }
        16 => {
            // TXT: one or more length-prefixed character strings.
            let mut text = String::new();
            let mut p = start;
            while p < end {
                let len = *message.get(p)? as usize;
                let piece_end = p + 1 + len;
                if piece_end > end {
                    return None;
                }
                text.push_str(&String::from_utf8_lossy(&message[p + 1..piece_end]));
                p = piece_end;
            }
            Some(text)
        }
        6 => {
            // SOA: two names, then five 32-bit counters.
            let (mname, after_mname) = parse_name(message, start)?;
            let (rname, after_rname) = parse_name(message, after_mname)?;
            if after_rname + 20 > end {
                return None;
            }
            let serial = u32::from_be_bytes(
                message[after_rname..after_rname + 4]
                    .try_into()
                    .expect("20 bytes guarded above"),
            );
            Some(format!("{} {} (serial {})", mname, rname, serial))
        }
        _ => Some(format!("<{} bytes of data>", end - start)),
    }
}

#[derive(Debug)]
struct DnsAnswer {
    records: Vec<DnsRecord>,
    truncated: bool,
}

fn parse_response(message: &[u8], expected_id: u16) -> Result<DnsAnswer, String> {
    if message.len() < 12 {
        return Err("response is too short to be DNS".to_string());
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != expected_id {
        return Err(format!(
            "response ID mismatch (got {}, wanted {})",
            id, expected_id
        ));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let rcode = flags & 0x000F;
    let truncated = flags & 0x0200 != 0;
    if rcode != 0 {
        return Err(rcode_message(rcode));
    }

    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    let ancount = u16::from_be_bytes([message[6], message[7]]);

    // Skip the echoed question section.
    let mut offset = 12;
    for _ in 0..qdcount {
        let (_, after_name) = parse_name(message, offset).ok_or("malformed question section")?;
        offset = after_name + 4; // QTYPE (2) + QCLASS (2)
    }

    let mut records = Vec::new();
    for _ in 0..ancount {
        let (name, after_name) = parse_name(message, offset).ok_or("malformed answer name")?;
        if after_name + 10 > message.len() {
            return Err("truncated answer record".to_string());
        }
        let rtype = u16::from_be_bytes([message[after_name], message[after_name + 1]]);
        let ttl = u32::from_be_bytes([
            message[after_name + 4],
            message[after_name + 5],
            message[after_name + 6],
            message[after_name + 7],
        ]);
        let rdlength =
            u16::from_be_bytes([message[after_name + 8], message[after_name + 9]]) as usize;
        let start = after_name + 10;
        let end = start + rdlength;
        if end > message.len() {
            return Err("record data runs past the end of the response".to_string());
        }

        let kind = type_name(rtype).to_string();
        let value = render_rdata(message, rtype, start, end)
            .unwrap_or_else(|| format!("<{} bytes of data>", rdlength));
        records.push(DnsRecord {
            name,
            kind,
            value,
            ttl,
        });
        offset = end;
    }

    Ok(DnsAnswer { records, truncated })
}

// ============================================================
// The JSON report (--json / --output).
// ============================================================

#[derive(serde::Serialize)]
struct DnsReportRecord {
    name: String,
    kind: String,
    value: String,
    ttl: u32,
}

#[derive(serde::Serialize)]
struct DnsReport {
    name: String,
    record_type: String,
    server: String,
    duration_ms: f64,
    answer_count: usize,
    records: Vec<DnsReportRecord>,
}

/// Entry point for `scouter26 dns <name>`.
pub fn execute(
    name: &str,
    record_type: &Option<String>,
    server_arg: &Option<String>,
    json: bool,
    output: &Option<PathBuf>,
) -> Result<(), String> {
    let started_at = Instant::now();

    let type_str = record_type.clone().unwrap_or_else(|| "A".to_string());
    let qtype = type_code(&type_str)?;
    let server: IpAddr = match server_arg {
        Some(explicit) => resolve_target(explicit, false)?,
        None => first_system_nameserver(),
    };

    // A fresh transaction ID per run, mixed from two clocks so two
    // lookups started together never share one.
    let id = (std::process::id() as u16) ^ (now_micros() as u16);
    let query = build_query(name, qtype, id)?;

    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|error| format!("could not open a UDP socket: {}", error))?;
    socket
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .map_err(|error| format!("could not set the reply timeout: {}", error))?;

    socket
        .send_to(&query, (server, DNS_PORT))
        .map_err(|error| format!("could not send the query to {}: {}", server, error))?;

    let mut buffer = [0u8; 4096];
    let (received, _from) = socket
        .recv_from(&mut buffer)
        .map_err(|error| format!("no reply from {} within 3s ({})", server, error))?;
    let duration_ms = started_at.elapsed().as_secs_f64() * 1000.0;

    let answer = parse_response(&buffer[..received], id)?;

    if answer.truncated {
        eprintln!(
            "{}",
            " note: the response was truncated — some records may be missing".yellow()
        );
    }

    if json || output.is_some() {
        let report = DnsReport {
            name: name.to_string(),
            record_type: type_str.to_uppercase(),
            server: server.to_string(),
            duration_ms,
            answer_count: answer.records.len(),
            records: answer
                .records
                .iter()
                .map(|r| DnsReportRecord {
                    name: r.name.clone(),
                    kind: r.kind.clone(),
                    value: r.value.clone(),
                    ttl: r.ttl,
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
                serde_json::to_string_pretty(&report).expect("DnsReport always serializes")
            );
            return Ok(());
        }
    }

    println!("{}", "========================================".cyan());
    println!("{}", " Scouter26 - DNS Lookup".cyan().bold());
    println!(
        " {}{} ({})",
        "Query:  ".cyan(),
        name.cyan(),
        type_str.to_uppercase()
    );
    println!(
        " {}{}",
        "Server: ".cyan(),
        format!("{}:{}", server, DNS_PORT).cyan()
    );
    println!(" {}{:.1} ms", "Time:   ".cyan(), duration_ms);
    println!("{}", "----------------------------------------".cyan());

    if answer.records.is_empty() {
        println!(
            "{}",
            format!(
                " no {} records exist for '{}'",
                type_str.to_uppercase(),
                name
            )
            .yellow()
        );
    } else {
        for record in &answer.records {
            println!(
                " {:<7} {:<50} TTL {}",
                record.kind,
                record.value.dimmed(),
                record.ttl
            );
        }
        println!("{}", "----------------------------------------".cyan());
        println!(
            " {} record(s) in {:.1} ms.",
            answer.records.len(),
            duration_ms
        );
    }

    Ok(())
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_encode_as_labels() {
        assert_eq!(
            encode_name("github.com").unwrap(),
            vec![
                6, b'g', b'i', b't', b'h', b'u', b'b', 3, b'c', b'o', b'm', 0
            ]
        );
        // Trailing dots and doubled dots are tolerated.
        assert_eq!(
            encode_name("github.com.").unwrap(),
            encode_name("github.com").unwrap()
        );
        // A label over 63 bytes is rejected with a clear message.
        let long = "a".repeat(64);
        assert!(encode_name(&long).unwrap_err().contains("too long"));
    }

    #[test]
    fn queries_have_header_question_and_class() {
        let query = build_query("example.com", 1, 0xBEEF).unwrap();
        assert_eq!(&query[0..2], &[0xBE, 0xEF], "transaction id");
        assert_eq!(&query[2..4], &[0x01, 0x00], "recursion desired");
        assert_eq!(&query[4..6], &[0, 1], "one question");
        assert_eq!(
            &query[query.len() - 4..],
            &[0, 1, 0, 1],
            "QTYPE=A, QCLASS=IN"
        );
    }

    #[test]
    fn compressed_names_follow_pointers() {
        // A message where the answer's name is a pointer back to the
        // question's name at offset 12.
        let question_name = encode_name("example.com").unwrap();
        let mut message = vec![0u8; 12];
        message.extend_from_slice(&question_name);
        message.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
        let answer_name_offset = message.len();
        message.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12

        let (name, after) = parse_name(&message, answer_name_offset).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(
            after,
            answer_name_offset + 2,
            "a pointer costs exactly 2 bytes"
        );
    }

    /// Build a synthetic DNS response with the given answer records.
    fn synth_response(answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&0x1964u16.to_be_bytes()); // id
        message.extend_from_slice(&0x8180u16.to_be_bytes()); // QR+RD+RA, rcode 0
        message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        message.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        // Question: example.com A IN
        message.extend(encode_name("example.com").unwrap());
        message.extend_from_slice(&[0, 1, 0, 1]);
        // Answers: name by pointer to offset 12, type, class, TTL, rdata
        for (rtype, rdata) in answers {
            message.extend_from_slice(&[0xC0, 0x0C]);
            message.extend_from_slice(&rtype.to_be_bytes());
            message.extend_from_slice(&1u16.to_be_bytes()); // class IN
            message.extend_from_slice(&300u32.to_be_bytes()); // TTL
            message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            message.extend_from_slice(rdata);
        }
        message
    }

    #[test]
    fn an_a_record_renders_an_ip() {
        let response = synth_response(&[(1, vec![140, 82, 121, 3])]);
        let answer = parse_response(&response, 0x1964).unwrap();
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].name, "example.com");
        assert_eq!(answer.records[0].kind, "A");
        assert_eq!(answer.records[0].value, "140.82.121.3");
        assert_eq!(answer.records[0].ttl, 300);
    }

    #[test]
    fn mx_and_txt_render_their_payloads() {
        let mut mx_rdata = vec![0, 10]; // preference 10
        mx_rdata.extend(encode_name("mail.example.com").unwrap());
        let response = synth_response(&[(15, mx_rdata)]);
        let answer = parse_response(&response, 0x1964).unwrap();
        assert_eq!(answer.records[0].kind, "MX");
        assert_eq!(answer.records[0].value, "10 mail.example.com");

        let txt_rdata = vec![5, b'h', b'e', b'l', b'l', b'o'];
        let response = synth_response(&[(16, txt_rdata)]);
        let answer = parse_response(&response, 0x1964).unwrap();
        assert_eq!(answer.records[0].value, "hello");
    }

    #[test]
    fn nxdomain_becomes_a_clear_error() {
        let mut message = synth_response(&[]);
        message[3] = (message[3] & 0xF0) | 0x03; // RCODE = 3
        let error = parse_response(&message, 0x1964).unwrap_err();
        assert!(error.contains("NXDOMAIN"), "message was: {}", error);
    }

    #[test]
    fn wrong_ids_are_rejected() {
        let response = synth_response(&[]);
        assert!(parse_response(&response, 0x1234).is_err());
    }

    #[test]
    fn dns_report_serializes_to_json() {
        let report = DnsReport {
            name: "example.com".to_string(),
            record_type: "A".to_string(),
            server: "127.0.0.53".to_string(),
            duration_ms: 12.3,
            answer_count: 1,
            records: vec![DnsReportRecord {
                name: "example.com".to_string(),
                kind: "A".to_string(),
                value: "93.184.216.34".to_string(),
                ttl: 3600,
            }],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["server"], "127.0.0.53");
        assert_eq!(value["records"][0]["value"], "93.184.216.34");
    }
}
