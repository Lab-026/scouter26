use clap::{Parser, Subcommand};

/// Scouter26: A modular network toolbox for IT Support and Admins
#[derive(Parser)]
#[command(name = "scouter26")]
#[command(version = "1.0")]
#[command(about = "A modular network toolbox", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Calculate subnet details from CIDR notation
    Subnet {
        /// The IP address in CIDR notation (e.g., 192.168.1.10/24)
        cidr: String,
    },
    /// Look up common network ports and protocols
    Ports {
        /// The port number (e.g., 80) or protocol name (e.g., http)
        query: String,
    },
    /// Scan common ports on a target host to see if they are open
    Scan {
        /// The IP address or hostname to scan (e.g., 192.168.1.1)
        target: String,
    },
}