mod cli;
mod commands;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;

fn main() {
    let cli = Cli::parse();

    // Each command does its own work and reports failures as Err instead
    // of calling exit() deep inside the code — the single exit point
    // below is the only place that decides the process's fate.
    let result = match &cli.command {
        Commands::Subnet { cidr } => commands::subnet::execute(cidr),
        Commands::Ports { query } => commands::ports::execute(query),
        Commands::Scan {
            target,
            ports,
            timeout,
            workers,
            ipv6,
        } => commands::scan::execute(target, ports, *timeout, *workers, *ipv6),
        Commands::Discover {
            cidr,
            ports,
            timeout,
            workers,
        } => commands::discover::execute(cidr, ports, *timeout, *workers),
    };

    if let Err(message) = result {
        eprintln!("{}", format!("Error: {}", message).red().bold());
        // Exit with code 1 so shell scripts can detect the failure
        // (e.g. `scouter26 subnet $ip || echo "failed"`)
        std::process::exit(1);
    }
}
