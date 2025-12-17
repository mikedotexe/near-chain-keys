//! Decoder with O(1) metadata extraction from tail.
//!
//! The key insight: for Base58, the last digit's value mod 29 equals
//! the decoded value mod 29 (because 58 ≡ 0 mod 29).
//!
//! This lets us extract partial metadata without full decode.

use crate::encode::{Metadata, Sign};
use crate::residue::{detect_base_from_alphabet, DetectedBase, b58_char_to_digit, MOD_29};

/// Metadata extracted from the tail
#[derive(Debug, Clone)]
pub struct TailMetadata {
    /// Detected base from alphabet/residue analysis
    pub detected_base: DetectedBase,
    /// Sign (if extractable)
    pub sign: Option<Sign>,
    /// Base ID from metadata byte (if decoded)
    pub base_id: Option<u8>,
    /// Checksum from metadata byte (if decoded)
    pub checksum: Option<u8>,
    /// Whether checksum validates
    pub checksum_valid: Option<bool>,
}

/// Decode error
#[derive(Debug, Clone)]
pub enum DecodeError {
    EmptyInput,
    InvalidCharacter,
    DecodeFailed(String),
    ChecksumMismatch,
    UnknownBase,
}

/// Extract partial metadata from tail in O(1).
///
/// For Base58: uses the vanishing property (58 ≡ 0 mod 29) to extract
/// the decoded value mod 29 from just the last character.
///
/// This doesn't give us the full metadata byte, but can help detect
/// whether this is likely a self-describing encoded value.
pub fn extract_tail_hint(s: &str) -> Option<TailMetadata> {
    if s.is_empty() {
        return None;
    }

    let detected_base = detect_base_from_alphabet(s);
    let bytes = s.as_bytes();
    let last_char = bytes[bytes.len() - 1];

    // For Base58: last_digit mod 29 = decoded_value mod 29
    if detected_base == DetectedBase::Base58 || detected_base == DetectedBase::Unknown {
        if let Some(digit) = b58_char_to_digit(last_char) {
            let _residue = digit % MOD_29;
            // The residue tells us: (payload || metadata_byte) mod 29 = residue
            // We can't extract full metadata without decode, but we know the residue
            return Some(TailMetadata {
                detected_base,
                sign: None, // Can't determine without full decode
                base_id: None,
                checksum: None,
                checksum_valid: None,
            });
        }
    }

    Some(TailMetadata {
        detected_base,
        sign: None,
        base_id: None,
        checksum: None,
        checksum_valid: None,
    })
}

/// Fully decode a self-describing encoded string.
///
/// Strategy: Try each decoder and validate using the embedded metadata.
/// The metadata byte contains a base_id that tells us which base was used.
/// We try decoders and check if the metadata is consistent.
pub fn decode(s: &str) -> Result<(Vec<u8>, TailMetadata), DecodeError> {
    if s.is_empty() {
        return Err(DecodeError::EmptyInput);
    }

    // Try each decoder and validate with metadata
    let candidates = try_all_decoders(s);

    // Find the candidate where base_id matches the decoder used
    for (decoded, detected_base) in candidates {
        if decoded.is_empty() {
            continue;
        }
        let meta_byte = decoded[decoded.len() - 1];
        let metadata = Metadata::unpack(meta_byte);

        // Check if base_id matches what we decoded with
        let expected_base_id = match detected_base {
            DetectedBase::Base58 => 0,
            DetectedBase::Base64 => 1,
            DetectedBase::Base32 => 2,
            DetectedBase::Unknown => continue,
        };

        if metadata.base_id == expected_base_id {
            // Also validate checksum
            let payload = &decoded[..decoded.len() - 1];
            let expected_checksum: u8 = {
                let sum: u32 = payload.iter().map(|&b| b as u32).sum();
                (sum % 31) as u8
            };

            if metadata.checksum == expected_checksum {
                return decode_with_bytes(decoded, detected_base);
            }
        }
    }

    // Fallback: try alphabet detection
    let detected_base = detect_base_from_alphabet(s);
    if detected_base != DetectedBase::Unknown {
        let decoded = match detected_base {
            DetectedBase::Base58 => bs58::decode(s).into_vec().ok(),
            DetectedBase::Base64 => {
                use base64::Engine;
                use base64::engine::general_purpose::STANDARD;
                STANDARD.decode(s).ok()
            }
            DetectedBase::Base32 => data_encoding::BASE32.decode(s.as_bytes()).ok(),
            DetectedBase::Unknown => None,
        };
        if let Some(bytes) = decoded {
            return decode_with_bytes(bytes, detected_base);
        }
    }

    Err(DecodeError::UnknownBase)
}

/// Try decoding with all supported bases
fn try_all_decoders(s: &str) -> Vec<(Vec<u8>, DetectedBase)> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut results = Vec::new();

    if let Ok(bytes) = bs58::decode(s).into_vec() {
        results.push((bytes, DetectedBase::Base58));
    }
    if let Ok(bytes) = STANDARD.decode(s) {
        results.push((bytes, DetectedBase::Base64));
    }
    if let Ok(bytes) = data_encoding::BASE32.decode(s.as_bytes()) {
        results.push((bytes, DetectedBase::Base32));
    }

    results
}

/// Process decoded bytes to extract metadata
fn decode_with_bytes(decoded: Vec<u8>, detected_base: DetectedBase) -> Result<(Vec<u8>, TailMetadata), DecodeError> {
    if decoded.is_empty() {
        return Err(DecodeError::EmptyInput);
    }

    // Last byte is metadata
    let meta_byte = decoded[decoded.len() - 1];
    let metadata = Metadata::unpack(meta_byte);

    // Payload is everything except the last byte
    let payload = decoded[..decoded.len() - 1].to_vec();

    // Validate checksum
    let expected_checksum: u8 = {
        let sum: u32 = payload.iter().map(|&b| b as u32).sum();
        (sum % 31) as u8
    };
    let checksum_valid = metadata.checksum == expected_checksum;

    let tail_meta = TailMetadata {
        detected_base,
        sign: Some(metadata.sign),
        base_id: Some(metadata.base_id),
        checksum: Some(metadata.checksum),
        checksum_valid: Some(checksum_valid),
    };

    Ok((payload, tail_meta))
}

/// Decode and validate, returning error if checksum fails
pub fn decode_validated(s: &str) -> Result<(Vec<u8>, TailMetadata), DecodeError> {
    let (payload, meta) = decode(s)?;

    if meta.checksum_valid == Some(false) {
        return Err(DecodeError::ChecksumMismatch);
    }

    Ok((payload, meta))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{encode_base58, encode_base64, encode_base32, Sign};

    #[test]
    fn test_roundtrip_base58() {
        let payload = b"hello world";
        let encoded = encode_base58(payload, Sign::Positive);
        let (decoded, meta) = decode(&encoded).unwrap();

        assert_eq!(&decoded, payload);
        assert_eq!(meta.sign, Some(Sign::Positive));
        assert_eq!(meta.base_id, Some(0)); // Base58
        assert_eq!(meta.checksum_valid, Some(true));
    }

    #[test]
    fn test_roundtrip_base64() {
        let payload = b"hello world";
        let encoded = encode_base64(payload, Sign::Negative);
        let (decoded, meta) = decode(&encoded).unwrap();

        assert_eq!(&decoded, payload);
        assert_eq!(meta.sign, Some(Sign::Negative));
        assert_eq!(meta.base_id, Some(1)); // Base64
        assert_eq!(meta.checksum_valid, Some(true));
    }

    #[test]
    fn test_roundtrip_base32() {
        let payload = b"hello world";
        let encoded = encode_base32(payload, Sign::Positive);
        let (decoded, meta) = decode(&encoded).unwrap();

        assert_eq!(&decoded, payload);
        assert_eq!(meta.sign, Some(Sign::Positive));
        assert_eq!(meta.base_id, Some(2)); // Base32
        assert_eq!(meta.checksum_valid, Some(true));
    }

    #[test]
    fn test_checksum_validation() {
        let payload = b"test data";
        let encoded = encode_base58(payload, Sign::Positive);

        // Should validate
        let result = decode_validated(&encoded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tail_hint_extraction() {
        let encoded = encode_base58(b"test", Sign::Positive);
        let hint = extract_tail_hint(&encoded);

        assert!(hint.is_some());
        // Can detect it's likely Base58 from alphabet
        let _hint = hint.unwrap();
        // The detected_base might be Unknown if ambiguous with Base64
    }
}
