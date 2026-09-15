use anyhow::Result;
use attribution_record::{
    canonical_bytes, DecryptionRecord, MlDsaPublicKey, RecipientId, SignedDecryptionRecord,
    WatermarkPayload,
};
use clap::Parser;
use crypt_engine::{decrypt, EncryptedPackage};
use ledger::Ledger;
use pqc_core::{open_private_key, sign};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Parser)]
struct Cli {
    #[arg(long)]
    package: PathBuf,
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    passphrase: String,
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    out: PathBuf,
}
#[derive(Deserialize)]
struct Public {
    recipient_id: RecipientId,
    signing_public: MlDsaPublicKey,
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let public: Public = serde_json::from_slice(&fs::read(cli.identity.join("recipient.json"))?)?;
    let package: EncryptedPackage = bincode::deserialize(&fs::read(&cli.package)?)?;
    let kem = open_private_key(&cli.identity.join("kem.private"), cli.passphrase.as_bytes())?;
    let plain = decrypt(&package, &public.recipient_id, &kem)?;
    let mut session = [0; 16];
    OsRng.fill_bytes(&mut session);
    let mut material = Vec::new();
    material.extend_from_slice(&blake3::hash(&package.ciphertext).as_bytes()[..]);
    material.extend_from_slice(public.recipient_id.0.as_bytes());
    material.extend_from_slice(&session);
    let watermark = WatermarkPayload(*blake3::hash(&material).as_bytes());
    let marked = watermark::embed(&plain, watermark)?;
    let record = DecryptionRecord {
        document_id: *blake3::hash(&package.ciphertext).as_bytes(),
        recipient_id: public.recipient_id,
        watermark,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        session_nonce: session,
    };
    let signing = open_private_key(
        &cli.identity.join("sign.private"),
        cli.passphrase.as_bytes(),
    )?;
    let entry = SignedDecryptionRecord {
        signature: sign(&signing, &canonical_bytes(&record)?)?,
        record,
        signer_pubkey: public.signing_public,
    };
    Ledger::open(cli.ledger)?.append(entry)?;
    fs::write(cli.out, marked)?;
    Ok(())
}
