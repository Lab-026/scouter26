use clap::{Parser, Subcommand};

/// Scouter26: A modular network toolbox for A+ and Network+ prep
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
}