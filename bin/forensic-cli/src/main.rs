use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Analyze {
        #[arg(long)]
        leaked: PathBuf,
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    VerifyLedger {
        #[arg(long)]
        ledger: PathBuf,
    },
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Analyze {
            leaked,
            ledger,
            out,
        } => {
            let ledger = ledger::Ledger::open(ledger)?;
            let report = forensics::analyze(&fs::read(leaked)?, &ledger)?;
            fs::write(out, serde_json::to_vec_pretty(&report)?)?;
        }
        Command::VerifyLedger { ledger } => ledger::Ledger::open(ledger)?.verify_chain()?,
    }
    Ok(())
}
