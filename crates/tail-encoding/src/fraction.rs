//! Fraction encoding: numerator/denominator with self-describing tail.
//!
//! # Format
//!
//! ```text
//! [numerator: variable][denominator: 4 bytes, big-endian][metadata: 1 byte]
//! ```
//!
//! - numerator: variable length (total - 5 bytes)
//! - denominator: fixed 4 bytes (u32, max ~4 billion)
//! - metadata: 1 byte encoding base_id + sign via mod 29 residue
//!
//! # O(1) Tail Properties
//!
//! From the encoded string's tail, we can extract:
//! - Base system (mod 29 vanishing) - O(1), last char only
//! - Sign of fraction (mod 29) - O(1), last char only
//! - Position-sensitive checksum (mod 41) - O(n), computed separately
//!
//! Fixed denominator size means deterministic parsing with no search.

use crate::encode::Sign;
use crate::layered::{pack_mod_29, unpack_mod_29, extract_mod_29, compute_mod_41, LayeredMeta};

/// A fraction with numerator and denominator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fraction {
    /// Numerator bytes (big-endian)
    pub numerator: Vec<u8>,
    /// Denominator bytes (big-endian)
    pub denominator: Vec<u8>,
    /// Sign of the fraction
    pub sign: Sign,
}

impl Fraction {
    /// Create a new fraction from byte slices.
    pub fn new(numerator: &[u8], denominator: &[u8], sign: Sign) -> Self {
        Self {
            numerator: numerator.to_vec(),
            denominator: denominator.to_vec(),
            sign,
        }
    }

    /// Create from u64 values.
    pub fn from_u64(num: u64, denom: u64, sign: Sign) -> Self {
        Self {
            numerator: u64_to_bytes(num),
            denominator: u64_to_bytes(denom),
            sign,
        }
    }

    /// Convert to f64 (lossy).
    pub fn to_f64(&self) -> f64 {
        let num = bytes_to_u64(&self.numerator);
        let denom = bytes_to_u64(&self.denominator);
        let value = if denom == 0 {
            f64::INFINITY
        } else {
            num as f64 / denom as f64
        };
        if self.sign == Sign::Negative { -value } else { value }
    }
}

/// Encode a fraction to Base58 with self-describing tail.
pub fn encode_fraction(frac: &Fraction) -> String {
    encode_fraction_base58(frac)
}

/// Encode fraction to Base58.
pub fn encode_fraction_base58(frac: &Fraction) -> String {
    let bytes = pack_fraction_bytes(frac, 0); // base_id = 0 for Base58
    bs58::encode(&bytes).into_string()
}

/// Encode fraction to Base64.
pub fn encode_fraction_base64(frac: &Fraction) -> String {
    use base64::Engine;
    let bytes = pack_fraction_bytes(frac, 1); // base_id = 1 for Base64
    base64::engine::general_purpose::STANDARD.encode(&bytes)
}

/// Fixed denominator size in bytes
const DENOM_SIZE: usize = 4;

/// Pack fraction into bytes with metadata.
fn pack_fraction_bytes(frac: &Fraction, base_id: u8) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Numerator (variable length)
    bytes.extend_from_slice(&frac.numerator);

    // Denominator (fixed 4 bytes, big-endian, zero-padded)
    let denom_u32 = bytes_to_u32(&frac.denominator);
    bytes.extend_from_slice(&denom_u32.to_be_bytes());

    // Find metadata byte that produces correct mod 29 residue in encoded string
    let target_29 = pack_mod_29(base_id, frac.sign);
    let metadata = find_metadata_byte(&bytes, target_29);
    bytes.push(metadata);

    bytes
}

/// Find a metadata byte such that the Base58-encoded string has the target mod 29 residue.
///
/// The mod 29 residue of a Base58 string equals (value mod 58) mod 29 = value mod 29.
/// So we need: (content_as_integer * 256 + metadata) mod 29 = target_29.
fn find_metadata_byte(content: &[u8], target_29: u8) -> u8 {
    // Compute content's value mod 29 using Horner's method
    // 256 mod 29 = 24
    let content_mod_29: u16 = {
        let mut acc: u16 = 0;
        for &b in content {
            acc = (acc * 24 + b as u16) % 29;
        }
        acc
    };

    // We need: (content_mod_29 * 24 + metadata) mod 29 = target_29
    // metadata = (target_29 - content_mod_29 * 24) mod 29
    let contrib = (content_mod_29 * 24) % 29;
    let base_metadata = ((target_29 as u16 + 29 - contrib) % 29) as u8;

    // base_metadata is in range 0-28, but we can add multiples of 29
    // to get different byte values. Pick one that's valid.
    // Any of: base_metadata, base_metadata + 29, base_metadata + 58, ... up to 255
    base_metadata
}

/// Decoded fraction with metadata.
#[derive(Debug)]
pub struct DecodedFraction {
    pub fraction: Fraction,
    pub meta: LayeredMeta,
}

/// Decode a Base58 fraction string.
pub fn decode_fraction(s: &str) -> Option<DecodedFraction> {
    // O(1) extraction: base_id and sign from last character
    let residue_29 = extract_mod_29(s)?;
    let (base_id, sign) = unpack_mod_29(residue_29);

    // O(n) extraction: position-sensitive checksum
    let residue_41 = compute_mod_41(s)?;

    let meta = LayeredMeta {
        base_id,
        sign,
        checksum_41: residue_41,
        residue_29,
        residue_41,
    };

    // Full decode
    let bytes = bs58::decode(s).into_vec().ok()?;

    // Format: [numerator: N bytes][denominator: 4 bytes][metadata: 1 byte]
    // Minimum: 0 + 4 + 1 = 5 bytes
    if bytes.len() < DENOM_SIZE + 1 {
        return None;
    }

    // Split: last byte is metadata, preceding 4 bytes are denominator, rest is numerator
    let content = &bytes[..bytes.len() - 1]; // Remove metadata
    let num_len = content.len() - DENOM_SIZE;

    let numerator = &content[..num_len];
    let denom_bytes: [u8; 4] = content[num_len..].try_into().ok()?;
    let denom_u32 = u32::from_be_bytes(denom_bytes);

    Some(DecodedFraction {
        fraction: Fraction {
            numerator: numerator.to_vec(),
            denominator: u32_to_bytes(denom_u32),
            sign,
        },
        meta,
    })
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn u64_to_bytes(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let mut bytes = n.to_be_bytes().to_vec();
    // Strip leading zeros
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    bytes
}

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for &b in bytes {
        result = result.wrapping_mul(256).wrapping_add(b as u64);
    }
    result
}

fn u32_to_bytes(n: u32) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let mut bytes = n.to_be_bytes().to_vec();
    // Strip leading zeros
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    bytes
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for &b in bytes {
        result = result.wrapping_mul(256).wrapping_add(b as u32);
    }
    result
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fraction_roundtrip_simple() {
        let frac = Fraction::from_u64(1, 3, Sign::Positive);
        let encoded = encode_fraction(&frac);

        println!("1/3 encoded: {}", encoded);

        let decoded = decode_fraction(&encoded).unwrap();
        assert_eq!(decoded.fraction.numerator, frac.numerator);
        assert_eq!(decoded.fraction.denominator, frac.denominator);
        assert_eq!(decoded.fraction.sign, Sign::Positive);
    }

    #[test]
    fn test_fraction_roundtrip_negative() {
        let frac = Fraction::from_u64(7, 8, Sign::Negative);
        let encoded = encode_fraction(&frac);

        println!("-7/8 encoded: {}", encoded);

        let decoded = decode_fraction(&encoded).unwrap();
        assert_eq!(decoded.fraction.sign, Sign::Negative);
        assert_eq!(bytes_to_u64(&decoded.fraction.numerator), 7);
        assert_eq!(bytes_to_u64(&decoded.fraction.denominator), 8);
    }

    #[test]
    fn test_fraction_large_values() {
        let frac = Fraction::from_u64(123456789, 987654321, Sign::Positive);
        let encoded = encode_fraction(&frac);

        println!("123456789/987654321 encoded: {} (len={})", encoded, encoded.len());

        let decoded = decode_fraction(&encoded).unwrap();
        assert_eq!(bytes_to_u64(&decoded.fraction.numerator), 123456789);
        assert_eq!(bytes_to_u64(&decoded.fraction.denominator), 987654321);
    }

    #[test]
    fn test_fraction_metadata_extraction() {
        let frac = Fraction::from_u64(22, 7, Sign::Positive); // ~pi
        let encoded = encode_fraction(&frac);

        // O(1) base detection should work (via decode_fraction which uses extract_mod_29)
        let decoded = decode_fraction(&encoded).unwrap();
        assert_eq!(decoded.meta.base_id, 0); // Base58
        assert_eq!(decoded.meta.sign, Sign::Positive);

        println!("22/7 metadata: base_id={}, sign={:?}, checksum_41={}",
                 decoded.meta.base_id, decoded.meta.sign, decoded.meta.checksum_41);
    }

    #[test]
    fn test_fraction_to_f64() {
        let frac = Fraction::from_u64(1, 3, Sign::Negative);
        let f = frac.to_f64();
        assert!((f - (-1.0/3.0)).abs() < 0.0001);
    }

    #[test]
    fn test_fraction_zero_denominator() {
        // Edge case: zero denominator (infinity)
        let frac = Fraction::from_u64(5, 0, Sign::Positive);
        let encoded = encode_fraction(&frac);

        let decoded = decode_fraction(&encoded).unwrap();
        assert_eq!(bytes_to_u64(&decoded.fraction.denominator), 0);
        assert!(decoded.fraction.to_f64().is_infinite());
    }

    #[test]
    fn test_fraction_whole_number() {
        // Whole number: n/1
        let frac = Fraction::from_u64(42, 1, Sign::Positive);
        let encoded = encode_fraction(&frac);

        let decoded = decode_fraction(&encoded).unwrap();
        assert_eq!(decoded.fraction.to_f64(), 42.0);
    }
}
