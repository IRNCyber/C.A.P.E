use anyhow::{Context, Result};
use attribution_record::{MlDsaPublicKey, MlKemPublicKey, RecipientId};
use clap::{Parser, Subcommand};
use crypt_engine::encrypt;
use pqc_core::{generate_kem_keypair, generate_signing_keypair, seal_private_key};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        passphrase: String,
    },
    Encrypt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        recipients: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
struct RecipientPublic {
    recipient_id: RecipientId,
    kem_public: MlKemPublicKey,
    signing_public: MlDsaPublicKey,
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            recipient,
            out,
            passphrase,
        } => {
            fs::create_dir_all(&out)?;
            let kem = generate_kem_keypair()?;
            let sign = generate_signing_keypair()?;
            seal_private_key(
                &out.join("kem.private"),
                &kem.private,
                passphrase.as_bytes(),
            )?;
            seal_private_key(
                &out.join("sign.private"),
                &sign.private,
                passphrase.as_bytes(),
            )?;
            let public = RecipientPublic {
                recipient_id: RecipientId(recipient),
                kem_public: kem.public,
                signing_public: sign.public,
            };
            fs::write(
                out.join("recipient.json"),
                serde_json::to_vec_pretty(&public)?,
            )?;
            println!("identity generated; distribute only recipient.json");
        }
        Command::Encrypt {
            input,
            recipients,
            out,
        } => {
            let input = fs::read(input)?;
            let recipients: Vec<RecipientPublic> =
                serde_json::from_slice(&fs::read(recipients).context("read recipients JSON")?)?;
            let keys = recipients
                .into_iter()
                .map(|r| (r.recipient_id, r.kem_public))
                .collect::<Vec<_>>();
            fs::write(out, bincode::serialize(&encrypt(&input, &keys)?)?)?;
        }
    }
    Ok(())
}
