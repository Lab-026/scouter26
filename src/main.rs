mod cli;
mod commands;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use colored::Colorize;

fn main() {
    // Unix CLI convention: when whoever reads our stdout goes away
    // (e.g. `scouter26 subnet ... | head`), die quietly on SIGPIPE like
    // every classic tool. Rust ignores SIGPIPE by default, which makes
    // println! panic with "Broken pipe" instead — restore the default.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    // Shell completions are a service, not a scan: print them and leave.
    if let Commands::Completions { shell } = &cli.command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "scouter26",
            &mut std::io::stdout(),
        );
        return;
    }

    // Each command does its own work and reports failures as Err instead
    // of calling exit() deep inside the code — the single exit point
    // below is the only place that decides the process's fate.
    let (result, json_mode) = match &cli.command {
        Commands::Subnet { cidr } => (commands::subnet::execute(cidr), false),
        Commands::Ports { query } => (commands::ports::execute(query), false),
        Commands::Ping {
            target,
            count,
            interval,
            timeout,
            port,
            json,
            output,
        } => (
            commands::ping::execute(target, *count, *interval, *timeout, *port, *json, output),
            *json,
        ),
        Commands::Scan {
            target,
            ports,
            timeout,
            workers,
            ipv6,
            json,
            output,
        } => (
            commands::scan::execute(target, ports, *timeout, *workers, *ipv6, *json, output),
            *json,
        ),
        Commands::Discover {
            cidr,
            ports,
            timeout,
            workers,
            json,
            output,
        } => (
            commands::discover::execute(cidr, ports, *timeout, *workers, *json, output),
            *json,
        ),
        Commands::Udp {
            target,
            ports,
            timeout,
            workers,
            ipv6,
            json,
            output,
        } => (
            commands::udp::execute(target, ports, *timeout, *workers, *ipv6, *json, output),
            *json,
        ),
        Commands::Syn {
            target,
            ports,
            timeout,
            json,
            output,
        } => (
            commands::syn::execute(target, ports, *timeout, *json, output),
            *json,
        ),
        Commands::Completions { .. } => unreachable!("handled above"),
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
