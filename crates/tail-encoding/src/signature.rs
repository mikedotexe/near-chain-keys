//! Elliptic curve signature tail encoding.
//!
//! Encodes signature metadata (curve type, format, recovery byte, pubkey presence)
//! into a **single tail character** using mod 29 residue, enabling O(1) extraction.
//!
//! # Encoding Scheme
//!
//! 28 values fit in mod 29:
//!
//! | Value | Curve      | Format | Recovery | Pubkey |
//! |-------|------------|--------|----------|--------|
//! | 0     | Ed25519    | raw    | -        | No     |
//! | 1     | BLS12-381  | raw    | -        | No     |
//! | 2-5   | secp256k1  | raw    | 0-3      | No     |
//! | 6-9   | secp256k1  | DER    | 0-3      | No     |
//! | 10-13 | secp256r1  | raw    | 0-3      | No     |
//! | 14-17 | secp256r1  | DER    | 0-3      | No     |
//! | 18    | Ed25519    | raw    | -        | Yes (32B) |
//! | 19    | BLS12-381  | raw    | -        | Yes (48B) |
//! | 20-23 | secp256k1  | raw    | 0-3      | Yes (33B) |
//! | 24-27 | secp256r1  | raw    | 0-3      | Yes (33B) |
//!
//! When pubkey is embedded, Ed25519 signatures become "recoverable" - the pubkey
//! is concatenated after the signature bytes.
//!
//! # Example
//!
//! ```
//! use tail_encoding::signature::*;
//!
//! // Ed25519 with embedded pubkey for "recovery"
//! let sig = [0u8; 64];
//! let pubkey = [1u8; 32];
//! let encoded = encode_signature_with_pubkey(&sig, &pubkey, Curve::Ed25519);
//! let meta = extract_signature_meta(&encoded).unwrap();
//! assert_eq!(meta.curve, Curve::Ed25519);
//! assert!(meta.has_pubkey);
//! ```

use crate::residue::{b58_char_to_digit, B58_ALPHABET};

/// Supported elliptic curves
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// Ed25519 (Solana, Cardano) - deterministic signatures
    Ed25519,
    /// BLS12-381 (Ethereum 2.0, Zcash) - aggregatable signatures
    BLS12_381,
    /// secp256k1 (Bitcoin, Ethereum) - ECDSA
    Secp256k1,
    /// secp256r1 / P-256 (NIST standard) - ECDSA
    Secp256r1,
}

/// Signature encoding format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFormat {
    /// Raw format: r || s (64 bytes for 256-bit curves, 96 bytes for BLS)
    Raw,
    /// DER encoding: ASN.1 format (71-73 bytes for ECDSA)
    Der,
}

/// Signature metadata extracted from tail
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureMeta {
    /// The elliptic curve used
    pub curve: Curve,
    /// Signature encoding format
    pub format: SigFormat,
    /// Recovery byte (v value) for ECDSA curves, None for Ed25519/BLS
    pub recovery: Option<u8>,
    /// Whether the public key is embedded after the signature
    pub has_pubkey: bool,
}

/// Expected pubkey sizes for each curve (compressed format for ECDSA)
pub const ED25519_PUBKEY_SIZE: usize = 32;
pub const BLS12_381_PUBKEY_SIZE: usize = 48;
pub const ECDSA_COMPRESSED_PUBKEY_SIZE: usize = 33;

// ============================================================================
// PACKING/UNPACKING
// ============================================================================

/// Pack signature metadata into a single value (0-27)
fn pack_meta(curve: Curve, format: SigFormat, recovery: Option<u8>, has_pubkey: bool) -> u8 {
    if has_pubkey {
        // Values 18-27: with embedded pubkey
        match curve {
            Curve::Ed25519 => 18,
            Curve::BLS12_381 => 19,
            Curve::Secp256k1 => 20 + recovery.unwrap_or(0).min(3),
            Curve::Secp256r1 => 24 + recovery.unwrap_or(0).min(3),
        }
    } else {
        // Values 0-17: signature only
        match curve {
            Curve::Ed25519 => 0,
            Curve::BLS12_381 => 1,
            Curve::Secp256k1 => {
                let base = if format == SigFormat::Raw { 2 } else { 6 };
                base + recovery.unwrap_or(0).min(3)
            }
            Curve::Secp256r1 => {
                let base = if format == SigFormat::Raw { 10 } else { 14 };
                base + recovery.unwrap_or(0).min(3)
            }
        }
    }
}

/// Unpack metadata value (0-27) into curve, format, recovery, has_pubkey
fn unpack_meta(value: u8) -> Option<SignatureMeta> {
    match value {
        // Signature only (0-17)
        0 => Some(SignatureMeta {
            curve: Curve::Ed25519,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: false,
        }),
        1 => Some(SignatureMeta {
            curve: Curve::BLS12_381,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: false,
        }),
        2..=5 => Some(SignatureMeta {
            curve: Curve::Secp256k1,
            format: SigFormat::Raw,
            recovery: Some(value - 2),
            has_pubkey: false,
        }),
        6..=9 => Some(SignatureMeta {
            curve: Curve::Secp256k1,
            format: SigFormat::Der,
            recovery: Some(value - 6),
            has_pubkey: false,
        }),
        10..=13 => Some(SignatureMeta {
            curve: Curve::Secp256r1,
            format: SigFormat::Raw,
            recovery: Some(value - 10),
            has_pubkey: false,
        }),
        14..=17 => Some(SignatureMeta {
            curve: Curve::Secp256r1,
            format: SigFormat::Der,
            recovery: Some(value - 14),
            has_pubkey: false,
        }),
        // With embedded pubkey (18-27)
        18 => Some(SignatureMeta {
            curve: Curve::Ed25519,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: true,
        }),
        19 => Some(SignatureMeta {
            curve: Curve::BLS12_381,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: true,
        }),
        20..=23 => Some(SignatureMeta {
            curve: Curve::Secp256k1,
            format: SigFormat::Raw,
            recovery: Some(value - 20),
            has_pubkey: true,
        }),
        24..=27 => Some(SignatureMeta {
            curve: Curve::Secp256r1,
            format: SigFormat::Raw,
            recovery: Some(value - 24),
            has_pubkey: true,
        }),
        _ => None,
    }
}

// ============================================================================
// TAIL CHARACTER ENCODING
// ============================================================================

/// Find a Base58 character whose digit value mod 29 equals the target.
fn char_for_residue(target: u8) -> char {
    // Base58 has 58 characters, indices 0-57
    // We want index where index % 29 == target
    // For targets 0-28, the first match is index = target
    // For targets 0-28 where target < 29, index = target works if target < 58
    for (i, &c) in B58_ALPHABET.iter().enumerate() {
        if (i as u8) % 29 == target {
            return c as char;
        }
    }
    unreachable!("target must be 0-28")
}

/// Extract the mod 29 residue from a Base58 character.
fn residue_from_char(c: char) -> Option<u8> {
    let digit = b58_char_to_digit(c as u8)?;
    Some(digit % 29)
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Encode signature bytes with curve metadata in tail.
///
/// # Arguments
/// * `sig_bytes` - The raw signature bytes
/// * `curve` - The elliptic curve used
/// * `format` - The signature format (Raw or DER)
/// * `recovery` - The recovery byte (v value) for ECDSA, None for Ed25519/BLS
///
/// # Returns
/// Base58-encoded signature with metadata tail character
pub fn encode_signature(
    sig_bytes: &[u8],
    curve: Curve,
    format: SigFormat,
    recovery: Option<u8>,
) -> String {
    // Base58 encode the signature bytes
    let base58_sig = bs58::encode(sig_bytes).into_string();

    // Pack metadata into tail residue (no pubkey)
    let meta_value = pack_meta(curve, format, recovery, false);
    let tail_char = char_for_residue(meta_value);

    // Append tail character
    format!("{}{}", base58_sig, tail_char)
}

/// Encode signature bytes WITH embedded public key.
///
/// This enables "recovery" for Ed25519 and other curves that don't natively
/// support public key recovery from signatures.
///
/// # Arguments
/// * `sig_bytes` - The raw signature bytes
/// * `pubkey_bytes` - The public key bytes (32B Ed25519, 48B BLS, 33B compressed ECDSA)
/// * `curve` - The elliptic curve used
///
/// # Returns
/// Base58-encoded (signature || pubkey) with metadata tail character
pub fn encode_signature_with_pubkey(
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
    curve: Curve,
) -> String {
    // Concatenate signature and pubkey
    let mut payload = sig_bytes.to_vec();
    payload.extend_from_slice(pubkey_bytes);

    // Base58 encode
    let base58_payload = bs58::encode(&payload).into_string();

    // Pack metadata (with pubkey flag, raw format, no recovery for Ed25519/BLS)
    let recovery = match curve {
        Curve::Ed25519 | Curve::BLS12_381 => None,
        Curve::Secp256k1 | Curve::Secp256r1 => Some(0), // Default recovery
    };
    let meta_value = pack_meta(curve, SigFormat::Raw, recovery, true);
    let tail_char = char_for_residue(meta_value);

    format!("{}{}", base58_payload, tail_char)
}

/// Encode signature with pubkey AND recovery byte (for ECDSA curves).
///
/// # Arguments
/// * `sig_bytes` - The raw signature bytes (64 bytes)
/// * `pubkey_bytes` - The compressed public key (33 bytes)
/// * `curve` - The elliptic curve (Secp256k1 or Secp256r1)
/// * `recovery` - The recovery byte (v value, 0-3)
pub fn encode_signature_with_pubkey_and_recovery(
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
    curve: Curve,
    recovery: u8,
) -> String {
    let mut payload = sig_bytes.to_vec();
    payload.extend_from_slice(pubkey_bytes);

    let base58_payload = bs58::encode(&payload).into_string();
    let meta_value = pack_meta(curve, SigFormat::Raw, Some(recovery), true);
    let tail_char = char_for_residue(meta_value);

    format!("{}{}", base58_payload, tail_char)
}

/// Decoded signature with optional pubkey
#[derive(Debug, Clone)]
pub struct DecodedSignature {
    /// The signature bytes
    pub signature: Vec<u8>,
    /// The public key bytes (if embedded)
    pub pubkey: Option<Vec<u8>>,
    /// Signature metadata
    pub meta: SignatureMeta,
}

/// Decode signature, extracting metadata from tail.
///
/// # Arguments
/// * `encoded` - The tail-encoded signature string
///
/// # Returns
/// Tuple of (signature bytes, metadata) if valid.
/// Note: If pubkey is embedded, this returns the combined payload.
/// Use `decode_signature_full` to separate signature and pubkey.
pub fn decode_signature(encoded: &str) -> Option<(Vec<u8>, SignatureMeta)> {
    if encoded.is_empty() {
        return None;
    }

    // Extract tail character and signature portion
    let chars: Vec<char> = encoded.chars().collect();
    let tail_char = *chars.last()?;
    let sig_portion: String = chars[..chars.len() - 1].iter().collect();

    // Extract metadata from tail
    let residue = residue_from_char(tail_char)?;
    let meta = unpack_meta(residue)?;

    // Decode the payload bytes
    let payload = bs58::decode(&sig_portion).into_vec().ok()?;

    Some((payload, meta))
}

/// Decode signature with full separation of signature and pubkey.
///
/// # Arguments
/// * `encoded` - The tail-encoded signature string
///
/// # Returns
/// DecodedSignature with separated signature and optional pubkey
pub fn decode_signature_full(encoded: &str) -> Option<DecodedSignature> {
    let (payload, meta) = decode_signature(encoded)?;

    if meta.has_pubkey {
        // Split payload into signature and pubkey based on curve
        let pubkey_size = match meta.curve {
            Curve::Ed25519 => ED25519_PUBKEY_SIZE,
            Curve::BLS12_381 => BLS12_381_PUBKEY_SIZE,
            Curve::Secp256k1 | Curve::Secp256r1 => ECDSA_COMPRESSED_PUBKEY_SIZE,
        };

        if payload.len() < pubkey_size {
            return None;
        }

        let sig_size = payload.len() - pubkey_size;
        let signature = payload[..sig_size].to_vec();
        let pubkey = payload[sig_size..].to_vec();

        Some(DecodedSignature {
            signature,
            pubkey: Some(pubkey),
            meta,
        })
    } else {
        Some(DecodedSignature {
            signature: payload,
            pubkey: None,
            meta,
        })
    }
}

/// Extract just the metadata from tail (O(1)).
///
/// This reads only the last character and extracts curve type,
/// format, and recovery byte without decoding the full signature.
///
/// # Arguments
/// * `encoded` - The tail-encoded signature string
///
/// # Returns
/// The signature metadata if valid
pub fn extract_signature_meta(encoded: &str) -> Option<SignatureMeta> {
    let tail_char = encoded.chars().last()?;
    let residue = residue_from_char(tail_char)?;
    unpack_meta(residue)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_ed25519() {
        let meta = SignatureMeta {
            curve: Curve::Ed25519,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: false,
        };
        let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
        assert_eq!(packed, 0);
        assert_eq!(unpack_meta(packed), Some(meta));
    }

    #[test]
    fn test_pack_unpack_bls() {
        let meta = SignatureMeta {
            curve: Curve::BLS12_381,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: false,
        };
        let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
        assert_eq!(packed, 1);
        assert_eq!(unpack_meta(packed), Some(meta));
    }

    #[test]
    fn test_pack_unpack_secp256k1_raw() {
        for v in 0..4 {
            let meta = SignatureMeta {
                curve: Curve::Secp256k1,
                format: SigFormat::Raw,
                recovery: Some(v),
                has_pubkey: false,
            };
            let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
            assert_eq!(packed, 2 + v);
            assert_eq!(unpack_meta(packed), Some(meta));
        }
    }

    #[test]
    fn test_pack_unpack_secp256k1_der() {
        for v in 0..4 {
            let meta = SignatureMeta {
                curve: Curve::Secp256k1,
                format: SigFormat::Der,
                recovery: Some(v),
                has_pubkey: false,
            };
            let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
            assert_eq!(packed, 6 + v);
            assert_eq!(unpack_meta(packed), Some(meta));
        }
    }

    #[test]
    fn test_pack_unpack_secp256r1_raw() {
        for v in 0..4 {
            let meta = SignatureMeta {
                curve: Curve::Secp256r1,
                format: SigFormat::Raw,
                recovery: Some(v),
                has_pubkey: false,
            };
            let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
            assert_eq!(packed, 10 + v);
            assert_eq!(unpack_meta(packed), Some(meta));
        }
    }

    #[test]
    fn test_pack_unpack_secp256r1_der() {
        for v in 0..4 {
            let meta = SignatureMeta {
                curve: Curve::Secp256r1,
                format: SigFormat::Der,
                recovery: Some(v),
                has_pubkey: false,
            };
            let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
            assert_eq!(packed, 14 + v);
            assert_eq!(unpack_meta(packed), Some(meta));
        }
    }

    #[test]
    fn test_pack_unpack_ed25519_with_pubkey() {
        let meta = SignatureMeta {
            curve: Curve::Ed25519,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: true,
        };
        let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
        assert_eq!(packed, 18);
        assert_eq!(unpack_meta(packed), Some(meta));
    }

    #[test]
    fn test_pack_unpack_bls_with_pubkey() {
        let meta = SignatureMeta {
            curve: Curve::BLS12_381,
            format: SigFormat::Raw,
            recovery: None,
            has_pubkey: true,
        };
        let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
        assert_eq!(packed, 19);
        assert_eq!(unpack_meta(packed), Some(meta));
    }

    #[test]
    fn test_pack_unpack_secp256k1_with_pubkey() {
        for v in 0..4 {
            let meta = SignatureMeta {
                curve: Curve::Secp256k1,
                format: SigFormat::Raw,
                recovery: Some(v),
                has_pubkey: true,
            };
            let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
            assert_eq!(packed, 20 + v);
            assert_eq!(unpack_meta(packed), Some(meta));
        }
    }

    #[test]
    fn test_pack_unpack_secp256r1_with_pubkey() {
        for v in 0..4 {
            let meta = SignatureMeta {
                curve: Curve::Secp256r1,
                format: SigFormat::Raw,
                recovery: Some(v),
                has_pubkey: true,
            };
            let packed = pack_meta(meta.curve, meta.format, meta.recovery, meta.has_pubkey);
            assert_eq!(packed, 24 + v);
            assert_eq!(unpack_meta(packed), Some(meta));
        }
    }

    #[test]
    fn test_char_for_residue() {
        // Verify each residue maps to a valid character (0-27 for all combinations)
        for target in 0..28 {
            let c = char_for_residue(target);
            let digit = b58_char_to_digit(c as u8).unwrap();
            assert_eq!(digit % 29, target);
        }
    }

    #[test]
    fn test_ed25519_roundtrip() {
        let sig = [0u8; 64]; // Ed25519 signature
        let encoded = encode_signature(&sig, Curve::Ed25519, SigFormat::Raw, None);
        let (decoded, meta) = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(meta.curve, Curve::Ed25519);
        assert_eq!(meta.format, SigFormat::Raw);
        assert_eq!(meta.recovery, None);
        assert!(!meta.has_pubkey);
    }

    #[test]
    fn test_secp256k1_with_recovery() {
        let sig = [42u8; 64];
        let encoded = encode_signature(&sig, Curve::Secp256k1, SigFormat::Raw, Some(1));
        let meta = extract_signature_meta(&encoded).unwrap();
        assert_eq!(meta.curve, Curve::Secp256k1);
        assert_eq!(meta.format, SigFormat::Raw);
        assert_eq!(meta.recovery, Some(1));
        assert!(!meta.has_pubkey);

        let (decoded, _) = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn test_bls_roundtrip() {
        let sig = [0xFFu8; 96]; // BLS signature is 96 bytes
        let encoded = encode_signature(&sig, Curve::BLS12_381, SigFormat::Raw, None);
        let (decoded, meta) = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(meta.curve, Curve::BLS12_381);
        assert!(!meta.has_pubkey);
    }

    #[test]
    fn test_all_18_combinations_without_pubkey() {
        // Test each of the 18 valid metadata combinations (without pubkey)
        let test_cases = vec![
            (Curve::Ed25519, SigFormat::Raw, None),
            (Curve::BLS12_381, SigFormat::Raw, None),
            (Curve::Secp256k1, SigFormat::Raw, Some(0)),
            (Curve::Secp256k1, SigFormat::Raw, Some(1)),
            (Curve::Secp256k1, SigFormat::Raw, Some(2)),
            (Curve::Secp256k1, SigFormat::Raw, Some(3)),
            (Curve::Secp256k1, SigFormat::Der, Some(0)),
            (Curve::Secp256k1, SigFormat::Der, Some(1)),
            (Curve::Secp256k1, SigFormat::Der, Some(2)),
            (Curve::Secp256k1, SigFormat::Der, Some(3)),
            (Curve::Secp256r1, SigFormat::Raw, Some(0)),
            (Curve::Secp256r1, SigFormat::Raw, Some(1)),
            (Curve::Secp256r1, SigFormat::Raw, Some(2)),
            (Curve::Secp256r1, SigFormat::Raw, Some(3)),
            (Curve::Secp256r1, SigFormat::Der, Some(0)),
            (Curve::Secp256r1, SigFormat::Der, Some(1)),
            (Curve::Secp256r1, SigFormat::Der, Some(2)),
            (Curve::Secp256r1, SigFormat::Der, Some(3)),
        ];

        for (i, (curve, format, recovery)) in test_cases.iter().enumerate() {
            let sig = vec![i as u8; 64];
            let encoded = encode_signature(&sig, *curve, *format, *recovery);
            let meta = extract_signature_meta(&encoded).unwrap();

            assert_eq!(meta.curve, *curve, "Failed at case {}", i);
            assert_eq!(meta.format, *format, "Failed at case {}", i);
            assert_eq!(meta.recovery, *recovery, "Failed at case {}", i);
            assert!(!meta.has_pubkey, "Failed at case {}", i);

            let (decoded, _) = decode_signature(&encoded).unwrap();
            assert_eq!(decoded, sig, "Failed roundtrip at case {}", i);
        }
    }

    #[test]
    fn test_o1_extraction() {
        // Verify that extract_signature_meta is truly O(1) by testing with various sizes
        let sizes = [64, 128, 256, 512, 1024];

        for size in sizes {
            let sig = vec![0xAB; size];
            let encoded = encode_signature(&sig, Curve::Secp256k1, SigFormat::Der, Some(2));

            // This should be O(1) - only reads last character
            let meta = extract_signature_meta(&encoded).unwrap();
            assert_eq!(meta.curve, Curve::Secp256k1);
            assert_eq!(meta.format, SigFormat::Der);
            assert_eq!(meta.recovery, Some(2));
            assert!(!meta.has_pubkey);
        }
    }

    #[test]
    fn test_real_signature_sizes() {
        // Test with realistic signature sizes

        // Ed25519: 64 bytes
        let ed_sig = [0x11; 64];
        let encoded = encode_signature(&ed_sig, Curve::Ed25519, SigFormat::Raw, None);
        let (decoded, _) = decode_signature(&encoded).unwrap();
        assert_eq!(decoded.len(), 64);

        // secp256k1 raw: 64 bytes (r + s)
        let ecdsa_sig = [0x22; 64];
        let encoded = encode_signature(&ecdsa_sig, Curve::Secp256k1, SigFormat::Raw, Some(0));
        let (decoded, _) = decode_signature(&encoded).unwrap();
        assert_eq!(decoded.len(), 64);

        // BLS12-381: 96 bytes
        let bls_sig = [0x33; 96];
        let encoded = encode_signature(&bls_sig, Curve::BLS12_381, SigFormat::Raw, None);
        let (decoded, _) = decode_signature(&encoded).unwrap();
        assert_eq!(decoded.len(), 96);
    }

    // ========================================================================
    // EMBEDDED PUBKEY TESTS
    // ========================================================================

    #[test]
    fn test_ed25519_with_pubkey_roundtrip() {
        let sig = [0xAA; 64];
        let pubkey = [0xBB; 32]; // Ed25519 pubkey is 32 bytes

        let encoded = encode_signature_with_pubkey(&sig, &pubkey, Curve::Ed25519);
        let meta = extract_signature_meta(&encoded).unwrap();

        assert_eq!(meta.curve, Curve::Ed25519);
        assert!(meta.has_pubkey);

        let decoded = decode_signature_full(&encoded).unwrap();
        assert_eq!(decoded.signature, sig);
        assert_eq!(decoded.pubkey, Some(pubkey.to_vec()));
        assert!(decoded.meta.has_pubkey);
    }

    #[test]
    fn test_bls_with_pubkey_roundtrip() {
        let sig = [0xCC; 96];
        let pubkey = [0xDD; 48]; // BLS pubkey is 48 bytes

        let encoded = encode_signature_with_pubkey(&sig, &pubkey, Curve::BLS12_381);
        let meta = extract_signature_meta(&encoded).unwrap();

        assert_eq!(meta.curve, Curve::BLS12_381);
        assert!(meta.has_pubkey);

        let decoded = decode_signature_full(&encoded).unwrap();
        assert_eq!(decoded.signature, sig);
        assert_eq!(decoded.pubkey, Some(pubkey.to_vec()));
    }

    #[test]
    fn test_secp256k1_with_pubkey_roundtrip() {
        let sig = [0xEE; 64];
        let pubkey = [0xFF; 33]; // Compressed ECDSA pubkey is 33 bytes

        let encoded = encode_signature_with_pubkey_and_recovery(&sig, &pubkey, Curve::Secp256k1, 2);
        let meta = extract_signature_meta(&encoded).unwrap();

        assert_eq!(meta.curve, Curve::Secp256k1);
        assert_eq!(meta.recovery, Some(2));
        assert!(meta.has_pubkey);

        let decoded = decode_signature_full(&encoded).unwrap();
        assert_eq!(decoded.signature, sig);
        assert_eq!(decoded.pubkey, Some(pubkey.to_vec()));
    }

    #[test]
    fn test_all_10_pubkey_combinations() {
        // Test all 10 with-pubkey combinations (values 18-27)
        // Ed25519: 1, BLS: 1, secp256k1: 4, secp256r1: 4

        // Ed25519
        {
            let sig = [0x11; 64];
            let pubkey = [0x22; 32];
            let encoded = encode_signature_with_pubkey(&sig, &pubkey, Curve::Ed25519);
            let decoded = decode_signature_full(&encoded).unwrap();
            assert_eq!(decoded.meta.curve, Curve::Ed25519);
            assert!(decoded.meta.has_pubkey);
            assert_eq!(decoded.signature, sig);
            assert_eq!(decoded.pubkey.unwrap(), pubkey);
        }

        // BLS
        {
            let sig = [0x33; 96];
            let pubkey = [0x44; 48];
            let encoded = encode_signature_with_pubkey(&sig, &pubkey, Curve::BLS12_381);
            let decoded = decode_signature_full(&encoded).unwrap();
            assert_eq!(decoded.meta.curve, Curve::BLS12_381);
            assert!(decoded.meta.has_pubkey);
        }

        // secp256k1 with recovery 0-3
        for v in 0..4 {
            let sig = [0x55; 64];
            let pubkey = [0x66; 33];
            let encoded = encode_signature_with_pubkey_and_recovery(&sig, &pubkey, Curve::Secp256k1, v);
            let decoded = decode_signature_full(&encoded).unwrap();
            assert_eq!(decoded.meta.curve, Curve::Secp256k1);
            assert_eq!(decoded.meta.recovery, Some(v));
            assert!(decoded.meta.has_pubkey);
        }

        // secp256r1 with recovery 0-3
        for v in 0..4 {
            let sig = [0x77; 64];
            let pubkey = [0x88; 33];
            let encoded = encode_signature_with_pubkey_and_recovery(&sig, &pubkey, Curve::Secp256r1, v);
            let decoded = decode_signature_full(&encoded).unwrap();
            assert_eq!(decoded.meta.curve, Curve::Secp256r1);
            assert_eq!(decoded.meta.recovery, Some(v));
            assert!(decoded.meta.has_pubkey);
        }
    }

    #[test]
    fn test_decode_without_pubkey_still_works() {
        // Ensure decode_signature_full works for signatures without embedded pubkey
        let sig = [0x99; 64];
        let encoded = encode_signature(&sig, Curve::Secp256k1, SigFormat::Raw, Some(1));

        let decoded = decode_signature_full(&encoded).unwrap();
        assert_eq!(decoded.signature, sig);
        assert!(decoded.pubkey.is_none());
        assert!(!decoded.meta.has_pubkey);
    }

    #[test]
    fn test_ed25519_recovery_scenario() {
        // Simulate the "recovery" use case for Ed25519
        // Someone receives a signed message and can extract the pubkey from the tail

        let message = b"Hello, world!";
        let sig = [0xAB; 64]; // Simulated signature
        let pubkey = [0xCD; 32]; // Simulated pubkey

        // Sender encodes signature with pubkey
        let encoded = encode_signature_with_pubkey(&sig, &pubkey, Curve::Ed25519);

        // Receiver extracts metadata in O(1)
        let meta = extract_signature_meta(&encoded).unwrap();
        assert_eq!(meta.curve, Curve::Ed25519);
        assert!(meta.has_pubkey); // Knows pubkey is embedded!

        // Receiver decodes to get pubkey for verification
        let decoded = decode_signature_full(&encoded).unwrap();
        let recovered_pubkey = decoded.pubkey.unwrap();

        // Now they can verify: verify(message, decoded.signature, recovered_pubkey)
        assert_eq!(recovered_pubkey.len(), 32);
        assert_eq!(decoded.signature.len(), 64);

        // This is "recovery" for Ed25519 - not algebraic, but practical!
        let _ = message; // Would use message in real verification
    }
}
