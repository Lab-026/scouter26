use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Scouter26: a modular network toolbox for IT support and junior admins
#[derive(Parser)]
#[command(name = "scouter26")]
// No more hardcoded "1.0" - this reads the version straight from Cargo.toml,
// so the version lives in exactly ONE place.
#[command(version)]
#[command(about = "A modular network toolbox", long_about = None)]
// A few worked examples at the bottom of --help, so a new user can see
// what the tool does without ever opening the README.
#[command(after_help = "Examples:
  scouter26 subnet 192.168.1.0/24
  scouter26 ports 443
  scouter26 scan scanme.nmap.org --ports 22,80,443
  scouter26 discover 192.168.1.0/24
  scouter26 udp 192.168.1.1
  sudo scouter26 syn 192.168.1.1 --ports 22,80,443")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Calculate subnet details from CIDR notation (IPv4 or IPv6)
    Subnet {
        /// An IPv4 or IPv6 address in CIDR notation
        /// (e.g., 192.168.1.10/24 or 2001:db8::/32)
        cidr: String,
    },
    /// Look up common network ports and protocols
    Ports {
        /// The port number (e.g., 80) or protocol name (e.g., http)
        query: String,
    },
    /// Is this host up? ICMP echo, with a TCP fallback (no root needed)
    Ping {
        /// The IP address or hostname to ping (e.g., 192.168.1.1)
        target: String,
        /// How many probes to send (1-100). Default: 4.
        #[arg(short, long, default_value_t = 4)]
        count: usize,
        /// Seconds between probes
        #[arg(short, long, default_value_t = 1.0)]
        interval: f64,
        /// Seconds to wait for each reply
        #[arg(long, default_value_t = 2.0)]
        timeout: f64,
        /// TCP fallback port when ICMP is unavailable
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Print results as JSON (stdout) instead of a human report
        #[arg(long)]
        json: bool,
        /// Also save the JSON report to this file
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// DNS lookups: A, AAAA, MX, TXT, NS, PTR, CNAME or SOA
    Dns {
        /// The name to look up (e.g., github.com)
        name: String,
        /// Record type: A, AAAA, CNAME, MX, TXT, NS, PTR or SOA. Default: A.
        #[arg(short = 't', long = "type")]
        record_type: Option<String>,
        /// DNS server to ask (default: your system's own resolver)
        #[arg(long)]
        server: Option<String>,
        /// Print results as JSON (stdout) instead of a human report
        #[arg(long)]
        json: bool,
        /// Also save the JSON report to this file
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Scan a target host for open TCP ports
    Scan {
        /// The IP address or hostname to scan (e.g., 192.168.1.1)
        target: String,
        /// Ports to scan: one (80), a list (22,80,443), or a range (1-1024).
        /// Default: the 10 most common ports.
        #[arg(short, long)]
        ports: Option<String>,
        /// Seconds to wait for each port before calling it closed
        #[arg(long, default_value_t = 1.0)]
        timeout: f64,
        /// How many ports to probe at the same time (1-2000)
        #[arg(long, default_value_t = 200)]
        workers: usize,
        /// Prefer the IPv6 address when a hostname has both A and AAAA records
        #[arg(long)]
        ipv6: bool,
        /// Print results as JSON (stdout) instead of a human report
        #[arg(long)]
        json: bool,
        /// Also save the JSON report to this file
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Find live hosts in a subnet by probing common ports on every address
    Discover {
        /// The network to sweep, in CIDR notation (e.g., 192.168.1.0/24)
        cidr: String,
        /// Ports to probe on each host: one, a list, or a range.
        /// Default: 22, 80, 443, 445, 3389.
        #[arg(short, long)]
        ports: Option<String>,
        /// Seconds to wait for each probe before calling the host absent
        #[arg(long, default_value_t = 1.0)]
        timeout: f64,
        /// How many probes to send at the same time (1-2000)
        #[arg(long, default_value_t = 200)]
        workers: usize,
        /// Print results as JSON (stdout) instead of a human report
        #[arg(long)]
        json: bool,
        /// Also save the JSON report to this file
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Probe UDP services on a host (DNS, NTP, SNMP, ...)
    Udp {
        /// The IP address or hostname to probe (e.g., 192.168.1.1)
        target: String,
        /// Ports to probe: one, a list, or a range.
        /// Default: 53, 69, 123, 137, 161, 514.
        #[arg(short, long)]
        ports: Option<String>,
        /// Seconds to wait per attempt; silent ports are probed twice,
        /// so one can consume up to twice this value
        #[arg(long, default_value_t = 1.0)]
        timeout: f64,
        /// How many probes to send at the same time (1-2000)
        #[arg(long, default_value_t = 200)]
        workers: usize,
        /// Prefer the IPv6 address when a hostname has both A and AAAA records
        #[arg(long)]
        ipv6: bool,
        /// Print results as JSON (stdout) instead of a human report
        #[arg(long)]
        json: bool,
        /// Also save the JSON report to this file
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Half-open SYN scan: forges raw packets, needs root (IPv4 only)
    Syn {
        /// The IPv4 address or hostname to scan (e.g., 192.168.1.1)
        target: String,
        /// Ports to scan: one (80), a list (22,80,443), or a range (1-1024).
        /// Default: the 10 most common ports.
        #[arg(short, long)]
        ports: Option<String>,
        /// Seconds to wait for replies; silent ports are probed twice
        #[arg(long, default_value_t = 1.0)]
        timeout: f64,
        /// Print results as JSON (stdout) instead of a human report
        #[arg(long)]
        json: bool,
        /// Also save the JSON report to this file
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Map the path to a host, hop by hop (needs root, IPv4 only)
    Trace {
        /// The IPv4 address or hostname to trace (e.g., 1.1.1.1)
        target: String,
        /// Maximum hops to try. Default: 15.
        #[arg(short = 'm', long, default_value_t = 15)]
        hops: u8,
        /// Seconds to wait for each hop to answer
        #[arg(long, default_value_t = 2.0)]
        timeout: f64,
        /// Print results as JSON (stdout) instead of a human report
        #[arg(long)]
        json: bool,
        /// Also save the JSON report to this file
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Generate shell completions (hidden helper: scouter26 completions bash)
    #[command(hide = true)]
    Completions {
        /// Which shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::shells::Shell,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn completions_generate_for_every_shell() {
        // If any shell's generation panics or comes back empty, Tab-completion
        // is silently broken for those users — so test them all.
        for shell in [
            clap_complete::shells::Shell::Bash,
            clap_complete::shells::Shell::Zsh,
            clap_complete::shells::Shell::Fish,
            clap_complete::shells::Shell::PowerShell,
        ] {
            let mut buffer = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "scouter26", &mut buffer);
            assert!(!buffer.is_empty(), "{} produced no completions", shell);
        }
    }

    #[test]
    fn help_contains_worked_examples() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("Examples:"));
        assert!(help.contains("scouter26 discover 192.168.1.0/24"));
    }
}
