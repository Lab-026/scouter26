//! Shared helpers used by more than one scouter26 command.

pub mod discover;
pub mod dns;
pub mod ping;
pub mod ports;
pub mod scan;
pub mod subnet;
pub mod syn;
pub mod trace;
pub mod udp;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

/// The hard ceiling for --workers in the scanning commands. Beyond a few
/// thousand, the threads cost more than they save and local
/// file-descriptor limits start to bite.
pub(crate) const MAX_WORKERS: usize = 2000;

/// Live progress lines are only worth their screen noise on long jobs.
pub(crate) const PROGRESS_THRESHOLD: usize = 100;

/// Turn a hostname or IP string into one IP address (either family).
///
/// A bare IP skips DNS entirely. A hostname that resolves to both
/// families gets its IPv4 address first — the same default nmap uses —
/// unless the user asked for IPv6 with --ipv6. Single-family names
/// simply get whatever they have, so IPv6-only hosts work normally.
pub(crate) fn resolve_target(target: &str, prefer_ipv6: bool) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addrs = match (target, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(_) => return Err(format!("could not resolve '{}' to an IP address", target)),
    };

    let pick = |want_v6: bool| {
        addrs.iter().find_map(|addr| match addr.ip() {
            IpAddr::V6(v6) if want_v6 => Some(IpAddr::V6(v6)),
            IpAddr::V4(v4) if !want_v6 => Some(IpAddr::V4(v4)),
            _ => None,
        })
    };

    pick(prefer_ipv6)
        .or_else(|| pick(!prefer_ipv6))
        .ok_or_else(|| format!("'{}' did not resolve to any usable IP address", target))
}

/// Write a report as pretty JSON to a file (--output).
///
/// Used by every scanning command so the saved format is identical
/// everywhere: what lands on disk is byte-for-byte what --json would
/// have printed.
pub(crate) fn write_report(
    path: &std::path::Path,
    report: &impl serde::Serialize,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|error| format!("could not serialize the report: {}", error))?;
    std::fs::write(path, json + "\n")
        .map_err(|error| format!("could not write '{}': {}", path.display(), error))
}

/// The Internet checksum (RFC 1071): sum every 16-bit word, fold the
/// carries back in until nothing overflows, then invert. Every IP, TCP
/// and ICMP header carries one; a receiver that sums the whole header
/// with the checksum included must arrive at all-ones. (Used by the SYN
/// scanner's TCP headers and ping's ICMP headers alike.)
pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    // as_chunks hands us the data as &[u8; 2] words plus the odd tail.
    let (words, remainder) = data.as_chunks::<2>();
    for word in words {
        sum += u16::from_be_bytes(*word) as u32;
    }
    // An odd trailing byte counts as a high-order byte (padded with zero).
    if let [odd] = remainder {
        sum += (*odd as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// What a worker-pool sweep can report about its own completeness: how
/// many jobs were actually dispatched, and how many workers died before
/// finishing. A sweep is complete only when every job was dispatched and
/// no worker failed.
pub(crate) struct SweepStatus {
    pub(crate) dispatched: usize,
    pub(crate) failed_joins: usize,
}

impl SweepStatus {
    pub(crate) fn is_complete(&self, total: usize) -> bool {
        self.failed_joins == 0 && self.dispatched >= total
    }
}

/// A finished flag shared with a progress thread, so the line can be
/// released the moment the workers are done even if a panic left the
/// counters short of the total.
pub(crate) fn atomic_bool() -> Arc<std::sync::atomic::AtomicBool> {
    Arc::new(std::sync::atomic::AtomicBool::new(false))
}

/// A lock() only fails when a thread panicked while holding it
/// ("poisoned"). The data itself is still fine, so recover it instead of
/// silently dropping results. Generic so every mutex in this crate can use it.
pub(crate) fn unlock<T>(
    poisoned: std::sync::PoisonError<std::sync::MutexGuard<'_, T>>,
) -> std::sync::MutexGuard<'_, T> {
    poisoned.into_inner()
}

/// Validate the tunables shared by the scanning commands (--timeout in
/// seconds, --workers in threads).
pub(crate) fn validate_tunables(timeout_secs: f64, workers: usize) -> Result<(), String> {
    if !(0.05..=60.0).contains(&timeout_secs) {
        return Err("timeout must be between 0.05 and 60 seconds".to_string());
    }
    if workers == 0 || workers > MAX_WORKERS {
        return Err(format!("workers must be between 1 and {}", MAX_WORKERS));
    }
    Ok(())
}

/// Parse a port specification: "80", "22,80,443", or "1-1024".
/// Returns a sorted list with no duplicates.
/// (Shared by `scan` and `discover`.)
pub(crate) fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
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

/// A SOCK_RAW / IPPROTO_TCP socket with IP_HDRINCL: we supply the whole
/// IPv4 header ourselves. Creating one needs root (CAP_NET_RAW) — that
/// is not a bug, it is the kernel defending everyone else from packet
/// forgery.
pub(crate) struct RawSocket {
    fd: libc::c_int,
}

impl RawSocket {
    pub(crate) fn new() -> Result<Self, io::Error> {
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

    pub(crate) fn send(&self, packet: &[u8], dst: Ipv4Addr) -> Result<(), io::Error> {
        // Zeroed first — see ping.rs for why (Darwin's extra sin_len).
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 0; // ignored: the port lives in the header we built
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(dst.octets()),
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

    pub(crate) fn set_read_timeout(&self, timeout: Duration) {
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
    pub(crate) fn recv(&self, buf: &mut [u8]) -> Option<usize> {
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
    /// An ICMP *listening* socket: SOCK_RAW + IPPROTO_ICMP, without
    /// IP_HDRINCL. This one is for receiving — every ICMP datagram that
    /// arrives at this machine (echo replies, Time Exceeded, ...) is
    /// delivered here with its IP header intact, which is exactly what
    /// traceroute needs to hear.
    pub(crate) fn icmp_capture() -> Result<Self, io::Error> {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(RawSocket { fd })
        }
    }

    /// Set the time-to-live for future sends on this socket — the knob
    /// traceroute turns once per hop. (Kernel-managed IP headers only;
    /// a hand-forged header carries its own TTL.)
    pub(crate) fn set_ttl(&self, ttl: u8) -> Result<(), io::Error> {
        let ttl = ttl as libc::c_int;
        unsafe {
            if libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &ttl as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub(crate) fn dup_for_reading(&self) -> RawSocket {
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
pub(crate) fn local_source_ip(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_land_on_disk_as_valid_json() {
        let mut path = std::env::temp_dir();
        path.push(format!("scouter26-test-report-{}.json", std::process::id()));
        #[derive(serde::Serialize)]
        struct Sample {
            tool: String,
            version: u32,
        }
        write_report(
            &path,
            &Sample {
                tool: "scouter26".into(),
                version: 1,
            },
        )
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(value["tool"], "scouter26");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn sweep_status_completeness_rules() {
        use super::SweepStatus;
        // All tasks dispatched, no failed joins: complete.
        assert!(
            SweepStatus {
                dispatched: 50,
                failed_joins: 0
            }
            .is_complete(50)
        );
        // Fewer tasks dispatched than planned: incomplete, whatever the
        // failed-join count is.
        assert!(
            !SweepStatus {
                dispatched: 10,
                failed_joins: 0
            }
            .is_complete(50)
        );
        // Any failed join makes the sweep incomplete, even at full dispatch.
        assert!(
            !SweepStatus {
                dispatched: 50,
                failed_joins: 2
            }
            .is_complete(50)
        );
    }

    #[test]
    fn unwritable_paths_fail_with_a_clear_message() {
        let result = write_report(
            std::path::Path::new("/nonexistent-dir-1964/report.json"),
            &"x",
        );
        assert!(result.is_err());
        let message = result.unwrap_err();
        assert!(
            message.contains("could not write"),
            "message was: {}",
            message
        );
    }
}
