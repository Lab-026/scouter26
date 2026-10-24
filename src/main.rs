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
    let (result, json_mode) = match &cli.command {
        Commands::Subnet { cidr } => (commands::subnet::execute(cidr), false),
        Commands::Ports { query } => (commands::ports::execute(query), false),
        Commands::Scan {
            target,
            ports,
            timeout,
            workers,
            ipv6,
            json,
        } => (
            commands::scan::execute(target, ports, *timeout, *workers, *ipv6, *json),
            *json,
        ),
        Commands::Discover {
            cidr,
            ports,
            timeout,
            workers,
            json,
        } => (
            commands::discover::execute(cidr, ports, *timeout, *workers, *json),
            *json,
        ),
    };

    if let Err(message) = result {
        if json_mode {
            // Machines reading --json output should get machine errors,
            // on stderr so stdout stays clean for successful reports.
            let payload = serde_json::json!({ "error": message });
            eprintln!("{}", payload);
        } else {
            eprintln!("{}", format!("Error: {}", message).red().bold());
        }
        // Exit with code 1 so shell scripts can detect the failure
        // (e.g. `scouter26 subnet $ip || echo "failed"`)
        std::process::exit(1);
    }
}
