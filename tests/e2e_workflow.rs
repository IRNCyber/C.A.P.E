use attribution_record::{
    canonical_bytes, DecryptionRecord, RecipientId, SignedDecryptionRecord, WatermarkPayload,
};
use crypt_engine::{decrypt, encrypt};
use ledger::Ledger;
use pqc_core::{generate_kem_keypair, generate_signing_keypair, sign};
use rand::{rngs::OsRng, RngCore};
#[test]
fn broadcast_decrypt_and_attribute_recipient_two() {
    let recipients = (0..3)
        .map(|n| {
            (
                RecipientId(format!("recipient-{n}")),
                generate_kem_keypair().unwrap(),
                generate_signing_keypair().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let public = recipients
        .iter()
        .map(|(id, k, _)| (id.clone(), k.public.clone()))
        .collect::<Vec<_>>();
    let package = encrypt(b"classified plain text", &public).unwrap();
    let (id, kem, signing) = &recipients[1];
    let plaintext = decrypt(&package, id, &kem.private).unwrap();
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    let watermark = WatermarkPayload(*blake3::hash(&[id.0.as_bytes(), &nonce].concat()).as_bytes());
    let leaked = watermark::embed(&plaintext, watermark).unwrap();
    let record = DecryptionRecord {
        document_id: *blake3::hash(&package.ciphertext).as_bytes(),
        recipient_id: id.clone(),
        watermark,
        timestamp: 42,
        session_nonce: nonce,
    };
    let entry = SignedDecryptionRecord {
        signature: sign(&signing.private, &canonical_bytes(&record).unwrap()).unwrap(),
        record,
        signer_pubkey: signing.public.clone(),
    };
    let temp = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(temp.path()).unwrap();
    ledger.append(entry).unwrap();
    let report = forensics::analyze(&leaked, &ledger).unwrap();
    assert_eq!(report.recipient_id, *id);
}
