mod parsers;
mod capture;
mod stats;
mod ddos;
mod baseline;
mod streams;
mod sourceengine;

use clap::Parser;

#[derive(Parser)]
#[command(name = "capture-packets", about = "Fast packet capture with native protocol parsing")]
pub struct Cli {
    /// Network interface
    #[arg(short, long, default_value = "wlo1")]
    pub interface: String,
    /// Capture duration in seconds
    #[arg(short, long, default_value_t = 5)]
    pub duration: u64,
    /// Mode: basic, full, stats, conversations, ddos, baseline, anomaly, streams, source-engine
    #[arg(short, long, default_value = "basic")]
    pub mode: String,
    /// Read from pcap file instead of live capture
    #[arg(short = 'r', long)]
    pub file: Option<String>,
    /// Max output chars (0 = unlimited)
    #[arg(long, default_value_t = 720000)]
    pub max_chars: usize,
}

fn main() {
    let cli = Cli::parse();

    if !cli.interface.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
        eprintln!("Error: Invalid interface name: {}", cli.interface);
        std::process::exit(1);
    }

    match cli.mode.as_str() {
        "basic" => capture::run_basic(&cli),
        "full" => capture::run_full(&cli),
        "stats" => stats::run_stats(&cli),
        "conversations" => stats::run_conversations(&cli),
        "ddos" => ddos::run_ddos(&cli),
        "baseline" => baseline::run_baseline(&cli),
        "anomaly" => baseline::run_anomaly(&cli),
        "streams" => streams::run_streams(&cli),
        "source-engine" => sourceengine::run_source_engine(&cli),
        other => {
            eprintln!("Error: Unknown mode '{}'. Use basic, full, stats, conversations, ddos, baseline, anomaly, streams, or source-engine.", other);
            std::process::exit(1);
        }
    }
}
