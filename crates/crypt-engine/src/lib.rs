//! Broadcast package encryption. Plaintext is returned only to the caller after AEAD verification.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use attribution_record::{MlKemPublicKey, RecipientId};
use pqc_core::{decapsulate, derive_key, encapsulate};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientEnvelope {
    pub recipient_id: RecipientId,
    pub kem_ciphertext: Vec<u8>,
    pub key_nonce: [u8; 12],
    pub encrypted_document_key: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPackage {
    pub version: u8,
    pub document_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub recipients: Vec<RecipientEnvelope>,
}
pub fn encrypt(
    plaintext: &[u8],
    recipients: &[(RecipientId, MlKemPublicKey)],
) -> Result<EncryptedPackage, CryptError> {
    if recipients.is_empty() {
        return Err(CryptError::NoRecipients);
    }
    let mut doc_key = [0; 32];
    let mut document_nonce = [0; 12];
    OsRng.fill_bytes(&mut doc_key);
    OsRng.fill_bytes(&mut document_nonce);
    let ciphertext = Aes256Gcm::new_from_slice(&doc_key)
        .map_err(|_| CryptError::Aead)?
        .encrypt(Nonce::from_slice(&document_nonce), plaintext)
        .map_err(|_| CryptError::Aead)?;
    let mut envelopes = Vec::with_capacity(recipients.len());
    for (id, pk) in recipients {
        let (kem_ciphertext, shared) = encapsulate(pk)?;
        let wrapping = derive_key(&shared, b"cape document-key wrap v1")?;
        let mut key_nonce = [0; 12];
        OsRng.fill_bytes(&mut key_nonce);
        let encrypted_document_key = Aes256Gcm::new_from_slice(&wrapping)
            .map_err(|_| CryptError::Aead)?
            .encrypt(Nonce::from_slice(&key_nonce), doc_key.as_ref())
            .map_err(|_| CryptError::Aead)?;
        envelopes.push(RecipientEnvelope {
            recipient_id: id.clone(),
            kem_ciphertext,
            key_nonce,
            encrypted_document_key,
        });
    }
    doc_key.zeroize();
    Ok(EncryptedPackage {
        version: 1,
        document_nonce,
        ciphertext,
        recipients: envelopes,
    })
}
pub fn decrypt(
    package: &EncryptedPackage,
    recipient: &RecipientId,
    kem_private: &[u8],
) -> Result<Vec<u8>, CryptError> {
    if package.version != 1 {
        return Err(CryptError::UnsupportedVersion);
    }
    let e = package
        .recipients
        .iter()
        .find(|e| &e.recipient_id == recipient)
        .ok_or(CryptError::RecipientNotFound)?;
    let shared = decapsulate(kem_private, &e.kem_ciphertext)?;
    let wrapping = derive_key(&shared, b"cape document-key wrap v1")?;
    let mut document_key = Aes256Gcm::new_from_slice(&wrapping)
        .map_err(|_| CryptError::Aead)?
        .decrypt(
            Nonce::from_slice(&e.key_nonce),
            e.encrypted_document_key.as_ref(),
        )
        .map_err(|_| CryptError::Aead)?;
    let result = Aes256Gcm::new_from_slice(&document_key)
        .map_err(|_| CryptError::Aead)?
        .decrypt(
            Nonce::from_slice(&package.document_nonce),
            package.ciphertext.as_ref(),
        )
        .map_err(|_| CryptError::Aead);
    document_key.zeroize();
    result
}
#[derive(Debug, thiserror::Error)]
pub enum CryptError {
    #[error("at least one recipient is required")]
    NoRecipients,
    #[error("recipient does not have an envelope")]
    RecipientNotFound,
    #[error("unsupported package version")]
    UnsupportedVersion,
    #[error("authenticated encryption failed")]
    Aead,
    #[error(transparent)]
    Pqc(#[from] pqc_core::PqcError),
}
#[cfg(test)]
mod tests {
    use super::*;
    use pqc_core::generate_kem_keypair;
    #[test]
    fn round_trip() {
        let k = generate_kem_keypair().unwrap();
        let id = RecipientId("a".into());
        let p = encrypt(b"secret", &[(id.clone(), k.public)]).unwrap();
        assert_eq!(decrypt(&p, &id, &k.private).unwrap(), b"secret");
    }
}
