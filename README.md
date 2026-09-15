# C.A.P.E. — Cryptographic Attribution & Provenance Evidence

An offline Rust proof-of-concept for broadcast-encrypt / individually-decrypt document distribution. A recipient decrypts into memory, receives a per-session invisible watermark, signs a record using ML-DSA-65, and commits it to a local hash-chained `sled` ledger. No runtime networking code or cloud service is included.

The implemented watermark target is UTF-8 plain text. Do not label arbitrary PDF or DOCX input as supported.

## Build

`cargo test --workspace`

The first build compiles vendored liboqs locally; it does not perform any runtime network activity.

## Desktop evidence workspace

Launch the native, offline interface with:

`cargo run -p cape-ui`

The interface provides separate Sender, Recipient, and Auditor workspaces. It keeps file paths explicit for air-gapped use and supports the same UTF-8 text workflow as the CLIs. The Recipient workspace intentionally has no unrecorded-decryption option: it watermarks the output and commits the signed record before writing the file.

## Local demo

Create three identities, then combine their generated `recipient.json` files into a JSON array named `recipients.json`.

```text
sender-cli keygen --recipient recipient-1 --out demo/r1 --passphrase demo-passphrase
sender-cli keygen --recipient recipient-2 --out demo/r2 --passphrase demo-passphrase
sender-cli keygen --recipient recipient-3 --out demo/r3 --passphrase demo-passphrase
sender-cli encrypt --input memo.txt --recipients recipients.json --out package.bin
recipient-cli --package package.bin --identity demo/r2 --passphrase demo-passphrase --ledger demo/ledger --out leaked.txt
forensic-cli analyze --leaked leaked.txt --ledger demo/ledger --out report.json
forensic-cli verify-ledger --ledger demo/ledger
```

Only public `recipient.json` files are shared with the sender. Private keys are Argon2-derived AES-256-GCM sealed files stored in each identity directory.
