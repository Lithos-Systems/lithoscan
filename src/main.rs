mod scanner;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run ARP scan on a given interface and CIDR
    ArpScan {
        #[arg(short, long)]
        iface: String,
        #[arg(short, long)]
        cidr: String,
    },
    /// List all available interfaces
    IfaceList,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::ArpScan { iface, cidr } => {
            match scanner::arp::run_arp_scan(iface, cidr).await {
                Ok(_) => (),
                Err(e) => eprintln!("Scan failed: {e}"),
            }
        }
        Commands::IfaceList => {
            match scanner::arp::list_interfaces() {
                Ok(_) => (),
                Err(e) => eprintln!("Could not list interfaces: {e}"),
            }
        }
    }
}
