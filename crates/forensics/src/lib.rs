use attribution_record::{LedgerBlock, MlDsaPublicKey, RecipientId, WatermarkPayload};
use ledger::Ledger;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub block_index: u64,
    pub chain_hashes: Vec<[u8; 32]>,
    pub signature: Vec<u8>,
    pub signer_pubkey: MlDsaPublicKey,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttributionReport {
    pub recipient_id: RecipientId,
    pub timestamp: u64,
    pub watermark: WatermarkPayload,
    pub proof: ProofBundle,
}
pub fn analyze(leaked_file: &[u8], ledger: &Ledger) -> Result<AttributionReport, ForensicError> {
    let watermark = watermark::extract(leaked_file).ok_or(ForensicError::WatermarkNotFound)?;
    let block = ledger
        .get_by_watermark(watermark)?
        .ok_or(ForensicError::NotRecorded)?;
    verify_block(ledger, &block)?;
    Ok(AttributionReport {
        recipient_id: block.entry.record.recipient_id.clone(),
        timestamp: block.entry.record.timestamp,
        watermark,
        proof: ProofBundle {
            block_index: block.index,
            chain_hashes: ledger.hash_path_to(block.index)?,
            signature: block.entry.signature.clone(),
            signer_pubkey: block.entry.signer_pubkey.clone(),
        },
    })
}
fn verify_block(ledger: &Ledger, block: &LedgerBlock) -> Result<(), ForensicError> {
    ledger.verify_chain()?;
    if ledger.get(block.index)?.as_ref() != Some(block) {
        return Err(ForensicError::BlockChanged);
    }
    Ok(())
}
#[derive(Debug, thiserror::Error)]
pub enum ForensicError {
    #[error("no supported watermark exists in this file")]
    WatermarkNotFound,
    #[error("watermark is not present in the ledger")]
    NotRecorded,
    #[error("ledger block changed while being verified")]
    BlockChanged,
    #[error(transparent)]
    Ledger(#[from] ledger::LedgerError),
}
