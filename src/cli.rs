use clap::{Parser, Subcommand};

/// Scouter26: a modular network toolbox for IT support and junior admins
#[derive(Parser)]
#[command(name = "scouter26")]
// No more hardcoded "1.0" - this reads the version straight from Cargo.toml,
// so the version lives in exactly ONE place.
#[command(version)]
#[command(about = "A modular network toolbox", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Calculate subnet details from CIDR notation
    Subnet {
        /// The IPv4 address in CIDR notation (e.g., 192.168.1.10/24)
        cidr: String,
    },
    /// Look up common network ports and protocols
    Ports {
        /// The port number (e.g., 80) or protocol name (e.g., http)
        query: String,
    },
    /// Scan a target host for open TCP ports
    Scan {
        /// The IP address or hostname to scan (e.g., 192.168.1.1)
        target: String,
        /// Ports to scan: one (80), a list (22,80,443), or a range (1-1024).
        /// Default: the 10 most common ports.
        #[arg(short, long)]
        ports: Option<String>,
    },
}