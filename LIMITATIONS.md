# Limitations

- Watermarking currently supports **UTF-8 plain text only**. It uses a trailing zero-width-character frame, which is visually invisible but is not robust against retyping, Unicode normalization, copy/paste sanitizers, conversion to PDF, screenshots, printing, or photography.
- The ledger is tamper-evident, not magical deletion prevention: a party with filesystem access can remove the entire ledger. Preserve signed exports across independently controlled air-gapped sites to detect rollback/deletion.
- Multi-site offline synchronization is documented as an extension point only; `sync::import_remote_segment` intentionally rejects input until proof and authorization policy are implemented.
- Time is the local system clock; it is not independently trusted and does not use NTP.
- This proof-of-concept needs a threat-model and security review before deployment in a production or evidentiary setting.
