//! NIST PQC façade: ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204), via liboqs.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use attribution_record::{MlDsaPublicKey, MlKemPublicKey};
use hkdf::Hkdf;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::{
    kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _},
    sign::{DetachedSignature as _, PublicKey as SignPublicKey, SecretKey as SignSecretKey},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::{fs, path::Path};
use zeroize::Zeroize;

pub struct KemKeyPair {
    pub public: MlKemPublicKey,
    pub private: Vec<u8>,
}
pub struct SigningKeyPair {
    pub public: MlDsaPublicKey,
    pub private: Vec<u8>,
}
pub fn generate_kem_keypair() -> Result<KemKeyPair, PqcError> {
    let (p, s) = mlkem768::keypair();
    Ok(KemKeyPair {
        public: MlKemPublicKey(p.as_bytes().to_vec()),
        private: s.as_bytes().to_vec(),
    })
}
pub fn generate_signing_keypair() -> Result<SigningKeyPair, PqcError> {
    let (p, k) = mldsa65::keypair();
    Ok(SigningKeyPair {
        public: MlDsaPublicKey(p.as_bytes().to_vec()),
        private: k.as_bytes().to_vec(),
    })
}
pub fn encapsulate(public: &MlKemPublicKey) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
    let p = mlkem768::PublicKey::from_bytes(&public.0).map_err(|_| PqcError::MalformedKey)?;
    let (s, c) = mlkem768::encapsulate(&p);
    Ok((c.as_bytes().to_vec(), s.as_bytes().to_vec()))
}
pub fn decapsulate(private: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PqcError> {
    let s = mlkem768::SecretKey::from_bytes(private).map_err(|_| PqcError::MalformedKey)?;
    let c = mlkem768::Ciphertext::from_bytes(ciphertext).map_err(|_| PqcError::MalformedKey)?;
    Ok(mlkem768::decapsulate(&c, &s).as_bytes().to_vec())
}
pub fn sign(private: &[u8], message: &[u8]) -> Result<Vec<u8>, PqcError> {
    let k = mldsa65::SecretKey::from_bytes(private).map_err(|_| PqcError::MalformedKey)?;
    Ok(mldsa65::detached_sign(message, &k).as_bytes().to_vec())
}
pub fn verify(public: &MlDsaPublicKey, message: &[u8], signature: &[u8]) -> Result<bool, PqcError> {
    let p = mldsa65::PublicKey::from_bytes(&public.0).map_err(|_| PqcError::MalformedKey)?;
    let sig =
        mldsa65::DetachedSignature::from_bytes(signature).map_err(|_| PqcError::MalformedKey)?;
    Ok(mldsa65::verify_detached_signature(&sig, message, &p).is_ok())
}
pub fn derive_key(shared_secret: &[u8], context: &[u8]) -> Result<[u8; 32], PqcError> {
    let hk = Hkdf::<Sha3_256>::new(None, shared_secret);
    let mut out = [0; 32];
    hk.expand(context, &mut out).map_err(|_| PqcError::Kdf)?;
    Ok(out)
}
#[derive(Serialize, Deserialize)]
struct SealedKey {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
pub fn seal_private_key(path: &Path, private: &[u8], passphrase: &[u8]) -> Result<(), PqcError> {
    let mut salt = [0; 16];
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut key = [0; 32];
    Argon2::default()
        .hash_password_into(passphrase, &salt, &mut key)
        .map_err(|_| PqcError::KeyStorage)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| PqcError::KeyStorage)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), private)
        .map_err(|_| PqcError::KeyStorage)?;
    key.zeroize();
    fs::write(
        path,
        bincode::serialize(&SealedKey {
            salt,
            nonce,
            ciphertext,
        })?,
    )
    .map_err(PqcError::Io)
}
pub fn open_private_key(path: &Path, passphrase: &[u8]) -> Result<Vec<u8>, PqcError> {
    let blob: SealedKey = bincode::deserialize(&fs::read(path).map_err(PqcError::Io)?)?;
    let mut key = [0; 32];
    Argon2::default()
        .hash_password_into(passphrase, &blob.salt, &mut key)
        .map_err(|_| PqcError::KeyStorage)?;
    let result = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| PqcError::KeyStorage)?
        .decrypt(Nonce::from_slice(&blob.nonce), blob.ciphertext.as_ref())
        .map_err(|_| PqcError::KeyStorage);
    key.zeroize();
    result
}
#[derive(Debug, thiserror::Error)]
pub enum PqcError {
    #[error("malformed PQC key, ciphertext, or signature")]
    MalformedKey,
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),
    #[error("serialization error: {0}")]
    Codec(#[from] Box<bincode::ErrorKind>),
    #[error("key derivation failed")]
    Kdf,
    #[error("private-key storage operation failed")]
    KeyStorage,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kem_and_signature_round_trip() {
        let k = generate_kem_keypair().unwrap();
        let (c, s) = encapsulate(&k.public).unwrap();
        assert_eq!(s, decapsulate(&k.private, &c).unwrap());
        let k = generate_signing_keypair().unwrap();
        let sig = sign(&k.private, b"record").unwrap();
        assert!(verify(&k.public, b"record", &sig).unwrap());
    }
}
