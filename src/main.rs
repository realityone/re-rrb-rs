//! rerrb: relay UniFi 802.11r RRB frames from the switch-facing ports to
//! hostapd on the bridge, without touching the source ports' data path.
//!
//! Linux-only: AF_PACKET, TAP and tc are Linux facilities.

// Only the Linux build wires every module into the binary; on other hosts
// they exist solely so their unit tests can run.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
mod app;
mod config;
mod hostapd;
#[cfg(target_os = "linux")]
mod packet;
pub mod proto;
mod relay;
#[cfg(target_os = "linux")]
mod tap;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rerrb",
    about = "Relay UniFi 802.11r RRB frames into the bridge via a TAP + tc mirred"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture RRB on the source ports, validate, untag, and relay into the
    /// target bridge. Runs until interrupted.
    Run {
        /// Path to the YAML config file.
        #[arg(long)]
        config: String,
    },
    /// Remove leftovers of a previous run identified by TAP name.
    Destroy {
        /// TAP device name.
        #[arg(long, default_value = "rrb0")]
        tap: String,
        /// TC filter priority used at install time.
        #[arg(long, default_value_t = config::DEFAULT_PREF)]
        pref: u16,
    },
    /// Print the kernel-side mirred action counters (tc -s) for the TAP.
    Stats {
        /// TAP device name.
        #[arg(long, default_value = "rrb0")]
        tap: String,
    },
}

#[cfg(target_os = "linux")]
// current_thread: every task is I/O-driven and counters are the only shared
// state; one thread keeps the daemon as light as the workload is.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Default level is info; RUST_LOG overrides, e.g. RUST_LOG=rerrb=debug
    // to see every matched frame, or rerrb=trace for rejections too.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("rerrb=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();
    match Cli::parse().command {
        Command::Run { config } => app::run(&config).await,
        Command::Destroy { tap, pref } => tap::destroy(&tap, pref).await,
        Command::Stats { tap } => {
            print!("{}", tap::action_stats(&tap).await?);
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rerrb runs on Linux only (AF_PACKET, TAP, tc)");
    std::process::exit(1);
}
