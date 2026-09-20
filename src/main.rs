mod cli;
mod commands;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    // 1. Clap reads the terminal arguments automatically
    let cli = Cli::parse();

    // 2. We match the command the user typed and route it
    match &cli.command {
        Commands::Subnet { cidr } => {
            commands::subnet::execute(cidr);
        }
    }
}