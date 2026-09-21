mod cli;
mod commands;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Subnet { cidr } => {
            commands::subnet::execute(cidr);
        }
        Commands::Ports { query } => {
            commands::ports::execute(query);
        }
    }
}