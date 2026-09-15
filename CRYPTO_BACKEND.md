# Cryptographic backend

This build uses the pure-Rust `pqcrypto-mlkem` and `pqcrypto-mldsa` crates because the `oqs` binding requires a local libclang installation that is not present in this build environment. It selects ML-KEM-768 and ML-DSA-65 only: the FIPS 203 and FIPS 204 algorithms respectively. No classical public-key cryptosystem is used as a primary scheme.
