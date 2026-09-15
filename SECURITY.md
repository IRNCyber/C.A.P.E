# Security posture

This system is intended for air-gapped operation. It contains no telemetry, analytics, update checking, cloud KMS, network client, or networked database. Keep package exchange and any future ledger segment exchange on controlled removable media.

ML-KEM-768 and ML-DSA-65 are selected through liboqs. The authenticity evidence is only as trustworthy as the recipient endpoint, passphrase protection, local clock, and physical custody of its ledger files. An attacker who controls a recipient machine before decryption may steal keys or alter the output environment.
