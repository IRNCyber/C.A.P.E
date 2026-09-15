//! Local append-only, hash-chained evidence ledger. `sync` is deliberately offline-only.
use attribution_record::{canonical_bytes, LedgerBlock, SignedDecryptionRecord, WatermarkPayload};
use pqc_core::verify;
use std::path::Path;
const ZERO: [u8; 32] = [0; 32];
const COUNT: &[u8] = b"count";
pub struct Ledger {
    blocks: sled::Tree,
    watermarks: sled::Tree,
    meta: sled::Tree,
}
impl Ledger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let db = sled::open(path)?;
        Ok(Self {
            blocks: db.open_tree("blocks")?,
            watermarks: db.open_tree("watermarks")?,
            meta: db.open_tree("meta")?,
        })
    }
    fn count(&self) -> Result<u64, LedgerError> {
        match self.meta.get(COUNT)? {
            Some(v) => {
                let b: [u8; 8] = v.as_ref().try_into().map_err(|_| LedgerError::Corrupt)?;
                Ok(u64::from_be_bytes(b))
            }
            None => Ok(0),
        }
    }
    fn key(i: u64) -> [u8; 8] {
        i.to_be_bytes()
    }
    pub fn append(&self, entry: SignedDecryptionRecord) -> Result<LedgerBlock, LedgerError> {
        let msg = canonical_bytes(&entry.record)?;
        if !verify(&entry.signer_pubkey, &msg, &entry.signature)? {
            return Err(LedgerError::InvalidSignature);
        }
        let index = self.count()?;
        if self.watermarks.get(entry.record.watermark.0)?.is_some() {
            return Err(LedgerError::DuplicateWatermark);
        }
        let prev_hash = if index == 0 {
            ZERO
        } else {
            self.get(index - 1)?.ok_or(LedgerError::Corrupt)?.entry_hash
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&prev_hash);
        hasher.update(&canonical_bytes(&entry)?);
        let block = LedgerBlock {
            index,
            prev_hash,
            entry,
            entry_hash: *hasher.finalize().as_bytes(),
        };
        let encoded = canonical_bytes(&block)?;
        let mut batch = sled::Batch::default();
        batch.insert(Self::key(index).to_vec(), encoded);
        self.blocks.apply_batch(batch)?;
        self.watermarks
            .insert(block.entry.record.watermark.0, Self::key(index).to_vec())?;
        self.meta
            .insert(COUNT, (index + 1).to_be_bytes().to_vec())?;
        self.meta.flush()?;
        Ok(block)
    }
    pub fn get(&self, index: u64) -> Result<Option<LedgerBlock>, LedgerError> {
        self.blocks
            .get(Self::key(index))?
            .map(|v| bincode::deserialize(&v).map_err(LedgerError::from))
            .transpose()
    }
    pub fn get_by_watermark(
        &self,
        watermark: WatermarkPayload,
    ) -> Result<Option<LedgerBlock>, LedgerError> {
        let Some(index) = self.watermarks.get(watermark.0)? else {
            return Ok(None);
        };
        let bytes: [u8; 8] = index
            .as_ref()
            .try_into()
            .map_err(|_| LedgerError::Corrupt)?;
        self.get(u64::from_be_bytes(bytes))
    }
    pub fn iterate(&self) -> Result<Vec<LedgerBlock>, LedgerError> {
        self.blocks
            .iter()
            .map(|r| {
                let (_, v) = r?;
                Ok(bincode::deserialize(&v)?)
            })
            .collect()
    }
    pub fn verify_chain(&self) -> Result<(), LedgerError> {
        let mut prev = ZERO;
        for (expected, block) in self.iterate()?.into_iter().enumerate() {
            if block.index != expected as u64 || block.prev_hash != prev {
                return Err(LedgerError::BrokenChain(block.index));
            }
            let msg = canonical_bytes(&block.entry.record)?;
            if !verify(&block.entry.signer_pubkey, &msg, &block.entry.signature)? {
                return Err(LedgerError::InvalidSignature);
            }
            let mut h = blake3::Hasher::new();
            h.update(&block.prev_hash);
            h.update(&canonical_bytes(&block.entry)?);
            if *h.finalize().as_bytes() != block.entry_hash {
                return Err(LedgerError::BrokenChain(block.index));
            }
            prev = block.entry_hash
        }
        Ok(())
    }
    pub fn hash_path_to(&self, index: u64) -> Result<Vec<[u8; 32]>, LedgerError> {
        let blocks = self.iterate()?;
        if index as usize >= blocks.len() {
            return Err(LedgerError::MissingBlock);
        }
        Ok(blocks
            .into_iter()
            .take(index as usize + 1)
            .map(|b| b.entry_hash)
            .collect())
    }
}
/// Future extension point: import a separately signed, offline-carried segment after proof validation.
pub mod sync {
    use super::*;
    pub fn import_remote_segment(_ledger: &Ledger, _segment: &[u8]) -> Result<(), LedgerError> {
        Err(LedgerError::SyncNotImplemented)
    }
}
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("sled: {0}")]
    Sled(#[from] sled::Error),
    #[error("serialization: {0}")]
    Codec(#[from] Box<bincode::ErrorKind>),
    #[error(transparent)]
    Record(#[from] attribution_record::RecordError),
    #[error(transparent)]
    Pqc(#[from] pqc_core::PqcError),
    #[error("the signed record is invalid")]
    InvalidSignature,
    #[error("watermark already exists")]
    DuplicateWatermark,
    #[error("ledger storage is corrupt")]
    Corrupt,
    #[error("hash chain failed at block {0}")]
    BrokenChain(u64),
    #[error("block does not exist")]
    MissingBlock,
    #[error("offline segment import is not implemented")]
    SyncNotImplemented,
}
#[cfg(test)]
mod tests {
    use super::*;
    use attribution_record::{
        DecryptionRecord, MlDsaPublicKey, RecipientId, SignedDecryptionRecord, WatermarkPayload,
    };
    use pqc_core::{generate_signing_keypair, sign};
    #[test]
    fn detects_tampered_block() {
        let temp = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(temp.path()).unwrap();
        let pair = generate_signing_keypair().unwrap();
        let record = DecryptionRecord {
            document_id: [1; 32],
            recipient_id: RecipientId("r".into()),
            watermark: WatermarkPayload([2; 32]),
            timestamp: 1,
            session_nonce: [3; 16],
        };
        let signature = sign(&pair.private, &canonical_bytes(&record).unwrap()).unwrap();
        ledger
            .append(SignedDecryptionRecord {
                record,
                signature,
                signer_pubkey: MlDsaPublicKey(pair.public.0),
            })
            .unwrap();
        let block = ledger.blocks.get(Ledger::key(0)).unwrap().unwrap();
        let mut bytes = block.to_vec();
        bytes[0] ^= 1;
        ledger.blocks.insert(Ledger::key(0), bytes).unwrap();
        assert!(ledger.verify_chain().is_err());
    }
}
