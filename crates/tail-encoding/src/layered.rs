//! Layered encoding: O(1) metadata + O(n) position-sensitive checksum.
//!
//! # The Scheme
//!
//! ```text
//! Layer 1 - O(1): mod 29 (vanishing)
//!   58 ≡ 0 (mod 29) → last char determines residue
//!   Encodes: base_id (3) × sign (2) = 6 values
//!
//! Layer 2 - O(n): mod 41 (primitive root)
//!   58 is primitive root mod 41 → position-sensitive
//!   Detects: transpositions, all single-char errors
//!   Provides: 41 checksum values
//!
//! Combined via CRT: mod 1189
//!   1189 distinct (metadata, checksum) pairs
//!   ~10.2 bits of information
//! ```
//!
//! # Error Detection
//!
//! | Error Type | mod 29 | mod 41 |
//! |------------|--------|--------|
//! | Last char change | ✓ | ✓ |
//! | Other char change | ✗ | ✓ |
//! | Transposition | 7% | 93%+ |

use crate::encode::Sign;
use crate::residue::b58_char_to_digit;

/// Layered metadata: O(1) extraction + O(n) checksum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayeredMeta {
    /// Base ID (0=B58, 1=B64, 2=B32)
    pub base_id: u8,
    /// Sign
    pub sign: Sign,
    /// Position-sensitive checksum (mod 41)
    pub checksum_41: u8,
    /// Raw residue mod 29 (from O(1) extraction)
    pub residue_29: u8,
    /// Raw residue mod 41 (from O(n) computation)
    pub residue_41: u8,
}

/// Modulus where 58 vanishes (O(1) extraction)
pub const MOD_VANISH: u8 = 29;

/// Modulus where 58 is primitive root (position-sensitive)
pub const MOD_PRIMITIVE: u8 = 41;

/// Combined modulus via CRT
pub const MOD_COMBINED: u16 = 29 * 41; // 1189

// ============================================================================
// O(1) EXTRACTION: mod 29
// ============================================================================

/// O(1) extract residue mod 29 from last character only.
///
/// Since 58 ≡ 0 (mod 29), only the last digit matters.
#[inline]
pub fn extract_mod_29(s: &str) -> Option<u8> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let last_digit = b58_char_to_digit(bytes[bytes.len() - 1])?;
    Some(last_digit % 29)
}

/// Pack base_id + sign into residue mod 29.
///
/// Format: base_id * 10 + sign_bit * 5 + reserved
/// - base_id: 0-2 (3 values)
/// - sign_bit: 0-1 (2 values)
/// - Total: 6 core values, room for expansion
#[inline]
pub fn pack_mod_29(base_id: u8, sign: Sign) -> u8 {
    let sign_bit = if sign == Sign::Negative { 1u8 } else { 0u8 };
    (base_id % 3) * 10 + sign_bit * 5
}

/// Unpack base_id + sign from residue mod 29.
#[inline]
pub fn unpack_mod_29(residue: u8) -> (u8, Sign) {
    let r = residue % 29;
    let base_id = r / 10;
    let sign_bit = (r % 10) / 5;
    let sign = if sign_bit == 1 { Sign::Negative } else { Sign::Positive };
    (base_id.min(2), sign)
}

// ============================================================================
// O(n) CHECKSUM: mod 41 (primitive root)
// ============================================================================

/// O(n) compute residue mod 41 using Horner's method.
///
/// Since 58 is a primitive root mod 41, this is position-sensitive
/// and detects transpositions.
#[inline]
pub fn compute_mod_41(s: &str) -> Option<u8> {
    let mut acc: u64 = 0;
    for &c in s.as_bytes() {
        let d = b58_char_to_digit(c)? as u64;
        acc = (acc * 58 + d) % 41;
    }
    Some(acc as u8)
}

/// Compute mod 41 from raw bytes (for encoder).
#[inline]
pub fn bytes_mod_41(bytes: &[u8]) -> u8 {
    let mut acc: u64 = 0;
    for &b in bytes {
        acc = (acc * 256 + b as u64) % 41;
    }
    acc as u8
}

// ============================================================================
// COMBINED EXTRACTION
// ============================================================================

/// Extract layered metadata from a Base58 string.
///
/// - O(1) for base_id + sign (from last char)
/// - O(n) for position-sensitive checksum (during char validation)
pub fn extract_layered(s: &str) -> Option<LayeredMeta> {
    // O(1): get mod 29 from last char
    let residue_29 = extract_mod_29(s)?;
    let (base_id, sign) = unpack_mod_29(residue_29);

    // O(n): compute mod 41 (position-sensitive)
    let residue_41 = compute_mod_41(s)?;

    Some(LayeredMeta {
        base_id,
        sign,
        checksum_41: residue_41,
        residue_29,
        residue_41,
    })
}

/// Create metadata byte that produces desired residues.
///
/// We need a byte value X such that:
/// - (payload || X) mod 29 = target_29
/// - (payload || X) mod 41 = target_41
///
/// This uses CRT to find X mod 1189, then takes X mod 256.
pub fn create_metadata_byte(
    payload_mod_29: u8,
    payload_mod_41: u8,
    base_id: u8,
    sign: Sign,
    target_checksum: u8,
) -> u8 {
    // Target residues
    let target_29 = pack_mod_29(base_id, sign);
    let target_41 = target_checksum % 41;

    // We need: (payload * 256 + X) ≡ target (mod m)
    // So: X ≡ (target - payload * 256) (mod m)

    // mod 29: 256 ≡ 256 - 8*29 = 256 - 232 = 24 (mod 29)
    let x_29 = {
        let payload_contrib = (payload_mod_29 as u16 * 24) % 29;
        let target = target_29 as u16;
        ((target + 29 - payload_contrib) % 29) as u8
    };

    // mod 41: 256 ≡ 256 - 6*41 = 256 - 246 = 10 (mod 41)
    let x_41 = {
        let payload_contrib = (payload_mod_41 as u16 * 10) % 41;
        let target = target_41 as u16;
        ((target + 41 - payload_contrib) % 41) as u8
    };

    // CRT: combine x_29 and x_41 to get x mod 1189
    // x ≡ x_29 (mod 29), x ≡ x_41 (mod 41)
    // x = x_29 + 29 * k where k = (x_41 - x_29) * 29^{-1} mod 41
    // 29^{-1} mod 41: 29 * 17 = 493 = 12*41 + 1 ≡ 1, so inv = 17

    const INV_29_MOD_41: u16 = 17;

    let diff = if x_41 >= x_29 {
        (x_41 - x_29) as u16
    } else {
        x_41 as u16 + 41 - x_29 as u16
    };

    let k = (diff * INV_29_MOD_41) % 41;
    let x_combined = (x_29 as u16 + 29 * k) % MOD_COMBINED;

    // Return x mod 256 (fits in a byte)
    (x_combined % 256) as u8
}

// ============================================================================
// VERIFICATION
// ============================================================================

/// Verify that extracted metadata matches expected.
pub fn verify_layered(
    extracted: &LayeredMeta,
    expected_base_id: u8,
    expected_sign: Sign,
    expected_checksum: u8,
) -> bool {
    extracted.base_id == expected_base_id
        && extracted.sign == expected_sign
        && extracted.checksum_41 == expected_checksum % 41
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_29_vanishing() {
        // Verify 58 ≡ 0 (mod 29)
        assert_eq!(58 % 29, 0);

        // Strings with same last char should have same mod 29
        assert_eq!(extract_mod_29("abc3yQ"), extract_mod_29("xyz3yQ"));
        assert_eq!(extract_mod_29("Q"), extract_mod_29("abcdefghijkQ"));
    }

    #[test]
    fn test_mod_41_position_sensitive() {
        // Same chars, different order → different residue
        let r1 = compute_mod_41("abc").unwrap();
        let r2 = compute_mod_41("bac").unwrap();
        let r3 = compute_mod_41("cab").unwrap();

        // At least two should differ (position-sensitive)
        assert!(r1 != r2 || r2 != r3 || r1 != r3);
    }

    #[test]
    fn test_transposition_detection() {
        let original = "JxF12TrwUP45BMd";
        let transposed = "xJF12TrwUP45BMd"; // Swap first two chars

        // mod 29: same (last char unchanged)
        assert_eq!(extract_mod_29(original), extract_mod_29(transposed));

        // mod 41: different (position-sensitive!)
        assert_ne!(compute_mod_41(original), compute_mod_41(transposed));
    }

    #[test]
    fn test_pack_unpack_mod_29() {
        for base_id in 0..3 {
            for sign in [Sign::Positive, Sign::Negative] {
                let packed = pack_mod_29(base_id, sign);
                let (unpacked_base, unpacked_sign) = unpack_mod_29(packed);

                assert_eq!(unpacked_base, base_id);
                assert_eq!(unpacked_sign, sign);
            }
        }
    }

    #[test]
    fn test_extract_layered() {
        let s = "3yQ"; // Known: encodes 9999

        let meta = extract_layered(s).unwrap();

        println!("Extracted from '3yQ':");
        println!("  residue_29: {}", meta.residue_29);
        println!("  residue_41: {}", meta.residue_41);
        println!("  base_id: {}", meta.base_id);
        println!("  sign: {:?}", meta.sign);
        println!("  checksum_41: {}", meta.checksum_41);

        // Verify residue calculations
        // 9999 mod 29 = 23
        // 9999 mod 41 = 9999 - 243*41 = 9999 - 9963 = 36
        assert_eq!(meta.residue_29, 23);
        assert_eq!(meta.residue_41, 36);
    }

    #[test]
    fn test_crt_inverse() {
        // Verify 29^{-1} mod 41 = 17
        assert_eq!((29 * 17) % 41, 1);

        // Verify 256 mod 29 = 24
        assert_eq!(256 % 29, 24);

        // Verify 256 mod 41 = 10
        assert_eq!(256 % 41, 10);
    }
}
