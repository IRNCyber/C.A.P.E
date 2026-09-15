//! UTF-8 plain-text watermarking. It appends a zero-width sentinel frame and is not resistant
//! to retyping, normalization that strips format characters, screenshots, or printing.
use attribution_record::WatermarkPayload;
const START: &str = "\u{2063}\u{2063}\u{2063}";
const END: &str = "\u{2064}\u{2064}\u{2064}";
const ZERO: char = '\u{200b}';
const ONE: char = '\u{200c}';

pub fn embed(plaintext: &[u8], payload: WatermarkPayload) -> Result<Vec<u8>, WatermarkError> {
    let text = std::str::from_utf8(plaintext).map_err(|_| WatermarkError::NonUtf8)?;
    let mut marked = String::with_capacity(text.len() + 3 + 256 + 3);
    marked.push_str(text);
    marked.push_str(START);
    for byte in payload.0 {
        for shift in (0..8).rev() {
            marked.push(if byte & (1 << shift) == 0 { ZERO } else { ONE });
        }
    }
    marked.push_str(END);
    Ok(marked.into_bytes())
}
pub fn extract(document: &[u8]) -> Option<WatermarkPayload> {
    let text = std::str::from_utf8(document).ok()?;
    let start = text.rfind(START)? + START.len();
    let rest = &text[start..];
    let end = rest.find(END)?;
    let bits: Vec<char> = rest[..end].chars().collect();
    if bits.len() != 256 || bits.iter().any(|c| *c != ZERO && *c != ONE) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, bit) in bits.iter().enumerate() {
        if *bit == ONE {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    Some(WatermarkPayload(out))
}
#[derive(Debug, thiserror::Error)]
pub enum WatermarkError {
    #[error("only UTF-8 plain-text input is supported")]
    NonUtf8,
}
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn round_trip() {
        let p = WatermarkPayload([7; 32]);
        assert_eq!(extract(&embed(b"memo", p).unwrap()), Some(p));
    }
    proptest! { #[test] fn round_trip_property(s in "[a-zA-Z0-9 \\n]{0,1000}", p in prop::array::uniform32(any::<u8>())) { let marked=embed(s.as_bytes(),WatermarkPayload(p)).unwrap(); prop_assert_eq!(extract(&marked),Some(WatermarkPayload(p))); } }
}
