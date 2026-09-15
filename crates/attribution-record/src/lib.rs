//! Shared, canonical on-disk types. Never change field ordering without a format version bump.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecipientId(pub String);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKemPublicKey(pub Vec<u8>);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsaPublicKey(pub Vec<u8>);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WatermarkPayload(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionRecord {
    pub document_id: [u8; 32],
    pub recipient_id: RecipientId,
    pub watermark: WatermarkPayload,
    pub timestamp: u64,
    pub session_nonce: [u8; 16],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDecryptionRecord {
    pub record: DecryptionRecord,
    pub signature: Vec<u8>,
    pub signer_pubkey: MlDsaPublicKey,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub index: u64,
    pub prev_hash: [u8; 32],
    pub entry: SignedDecryptionRecord,
    pub entry_hash: [u8; 32],
}
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("record serialization failed: {0}")]
    Encode(#[from] Box<bincode::ErrorKind>),
}
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, RecordError> {
    Ok(bincode::serialize(value)?)
}
