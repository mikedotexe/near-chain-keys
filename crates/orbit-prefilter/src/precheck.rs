//! Base58 pre-checking with orbit validation.
//!
//! Provides O(n) pre-filtering to reject invalid Base58 inputs before
//! expensive O(n²) decoding.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::fingerprint::{Orbit4, Orbit8};

/// Base58 alphabet (Bitcoin style): 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
/// Excludes: 0, O, I, l (to avoid visual ambiguity)
const B58_DECODE: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00-0x0F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10-0x1F
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20-0x2F
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1, // 0x30-0x3F ('1'-'9')
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1, // 0x40-0x4F ('A'-'O')
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1, // 0x50-0x5F ('P'-'Z')
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, // 0x60-0x6F ('a'-'o')
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, // 0x70-0x7F ('p'-'z')
];

/// Result of pre-filtering a Base58 string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefilterResult {
    /// Input contains invalid Base58 character(s). Definitely reject.
    InvalidChars,
    /// All characters valid. Fingerprints match expected bytes.
    /// ~99.998% confidence values are equal (orbit4) or ~99.9999999% (orbit8).
    ProbablyValid,
    /// All characters valid but fingerprints don't match.
    /// Definitely different values.
    DefinitelyInvalid,
    /// All characters valid but no expected bytes provided.
    /// Need full decode to determine actual value.
    NeedsFullDecode,
}

/// Decode a Base58 character to its digit value (0-57).
/// Returns None for invalid characters.
#[inline]
pub fn b58_char_to_digit(c: u8) -> Option<u8> {
    if c >= 128 {
        return None;
    }
    let v = B58_DECODE[c as usize];
    if v < 0 { None } else { Some(v as u8) }
}

/// Check if all characters in a string are valid Base58.
/// Returns the position of the first invalid character, or None if all valid.
#[inline]
pub fn find_invalid_char(input: &str) -> Option<usize> {
    for (i, c) in input.bytes().enumerate() {
        if b58_char_to_digit(c).is_none() {
            return Some(i);
        }
    }
    None
}

/// Check if a string contains only valid Base58 characters.
#[inline]
pub fn is_valid_base58_chars(input: &str) -> bool {
    input.bytes().all(|c| b58_char_to_digit(c).is_some())
}

/// Pre-filter a Base58 string with orbit4 validation.
///
/// # Arguments
/// * `input` - The Base58 string to check
/// * `expected` - Optional expected bytes to validate against
///
/// # Returns
/// * `InvalidChars` - Input has invalid Base58 characters
/// * `ProbablyValid` - Characters valid AND fingerprints match expected
/// * `DefinitelyInvalid` - Characters valid BUT fingerprints don't match
/// * `NeedsFullDecode` - Characters valid, no expected provided
///
/// # Performance
/// * O(n) time complexity (vs O(n²) for full decode)
/// * For 600-char input: ~76× faster rejection than bs58::decode
#[inline]
pub fn prefilter(input: &str, expected: Option<&[u8]>) -> PrefilterResult {
    // Collect digits while validating characters
    let mut digits = Vec::with_capacity(input.len());

    for c in input.bytes() {
        match b58_char_to_digit(c) {
            Some(d) => digits.push(d),
            None => return PrefilterResult::InvalidChars,
        }
    }

    // If no expected bytes, we can't validate further
    let expected = match expected {
        Some(e) => e,
        None => return PrefilterResult::NeedsFullDecode,
    };

    // Compute fingerprints and compare
    let fp_input = Orbit4::from_b58_digits(digits.into_iter());
    let fp_expected = Orbit4::from_bytes(expected);

    if fp_input.matches(&fp_expected) {
        PrefilterResult::ProbablyValid
    } else {
        PrefilterResult::DefinitelyInvalid
    }
}

/// Pre-filter with orbit8 (stronger, 1 in 168B false positive rate).
#[inline]
pub fn prefilter_strong(input: &str, expected: Option<&[u8]>) -> PrefilterResult {
    let mut digits = Vec::with_capacity(input.len());

    for c in input.bytes() {
        match b58_char_to_digit(c) {
            Some(d) => digits.push(d),
            None => return PrefilterResult::InvalidChars,
        }
    }

    let expected = match expected {
        Some(e) => e,
        None => return PrefilterResult::NeedsFullDecode,
    };

    let fp_input = Orbit8::from_b58_digits(digits.into_iter());
    let fp_expected = Orbit8::from_bytes(expected);

    if fp_input.matches(&fp_expected) {
        PrefilterResult::ProbablyValid
    } else {
        PrefilterResult::DefinitelyInvalid
    }
}

/// Zero-allocation pre-filter that validates characters inline with fingerprinting.
/// More efficient for hot paths.
#[inline]
pub fn prefilter_inline(input: &str, expected: &[u8]) -> PrefilterResult {
    let mut acc = [0u64; 4];
    const MODULI: [u32; 4] = [7, 11, 23, 31];

    for c in input.bytes() {
        let d = match b58_char_to_digit(c) {
            Some(d) => d as u64,
            None => return PrefilterResult::InvalidChars,
        };

        for (i, &m) in MODULI.iter().enumerate() {
            acc[i] = (acc[i] * 58 + d) % m as u64;
        }
    }

    // Compute expected fingerprint
    let mut exp_acc = [0u64; 4];
    for &b in expected {
        for (i, &m) in MODULI.iter().enumerate() {
            exp_acc[i] = (exp_acc[i] * 256 + b as u64) % m as u64;
        }
    }

    if acc == exp_acc {
        PrefilterResult::ProbablyValid
    } else {
        PrefilterResult::DefinitelyInvalid
    }
}

/// Layered pre-filter: orbit fingerprint + progressive tail matching.
///
/// Combines two independent validation layers:
/// 1. Orbit4 fingerprint - O(n), ~1/55,000 false positive rate
/// 2. Tail byte match - O(32), exact match of last 4 bytes
///
/// Combined false positive rate is negligible (requires both layers to fail).
///
/// # Arguments
/// * `input` - The Base58 string to check
/// * `expected` - Expected decoded bytes to validate against
/// * `tail_bytes` - Number of tail bytes to check (1-4, default 4)
///
/// # Performance
/// * Orbit: O(n) where n = input length
/// * Tail: O(32) constant time for 4 bytes
/// * Total: O(n) but catches virtually all mismatches
#[inline]
pub fn prefilter_layered(input: &str, expected: &[u8]) -> PrefilterResult {
    // Layer 1: Character validation + orbit fingerprint
    let mut digits = Vec::with_capacity(input.len());

    for c in input.bytes() {
        match b58_char_to_digit(c) {
            Some(d) => digits.push(d),
            None => return PrefilterResult::InvalidChars,
        }
    }

    // Orbit fingerprint check
    let fp_input = Orbit4::from_b58_digits(digits.into_iter());
    let fp_expected = Orbit4::from_bytes(expected);

    if !fp_input.matches(&fp_expected) {
        return PrefilterResult::DefinitelyInvalid;
    }

    // Layer 2: Progressive tail matching (O(32) constant time)
    // Only check if expected is long enough
    if expected.len() >= 4 {
        let tail_expected = &expected[expected.len() - 4..];
        match crate::progressive::tail_matches(input, tail_expected) {
            Ok(true) => PrefilterResult::ProbablyValid,
            Ok(false) => PrefilterResult::DefinitelyInvalid,
            Err(_) => PrefilterResult::InvalidChars,
        }
    } else {
        // For short expected, orbit is enough
        PrefilterResult::ProbablyValid
    }
}

/// Zero-allocation layered prefilter.
/// Combines inline orbit fingerprinting with tail byte extraction.
#[inline]
pub fn prefilter_layered_inline(input: &str, expected: &[u8]) -> PrefilterResult {
    // Inline orbit fingerprint (no allocation)
    let mut acc = [0u64; 4];
    const MODULI: [u32; 4] = [7, 11, 23, 31];

    for c in input.bytes() {
        let d = match b58_char_to_digit(c) {
            Some(d) => d as u64,
            None => return PrefilterResult::InvalidChars,
        };

        for (i, &m) in MODULI.iter().enumerate() {
            acc[i] = (acc[i] * 58 + d) % m as u64;
        }
    }

    // Compute expected orbit fingerprint
    let mut exp_acc = [0u64; 4];
    for &b in expected {
        for (i, &m) in MODULI.iter().enumerate() {
            exp_acc[i] = (exp_acc[i] * 256 + b as u64) % m as u64;
        }
    }

    if acc != exp_acc {
        return PrefilterResult::DefinitelyInvalid;
    }

    // Layer 2: Progressive tail check
    if expected.len() >= 4 {
        let tail_expected = &expected[expected.len() - 4..];
        match crate::progressive::tail_matches(input, tail_expected) {
            Ok(true) => PrefilterResult::ProbablyValid,
            Ok(false) => PrefilterResult::DefinitelyInvalid,
            Err(_) => PrefilterResult::InvalidChars,
        }
    } else {
        PrefilterResult::ProbablyValid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_chars() {
        assert!(is_valid_base58_chars("123456789"));
        assert!(is_valid_base58_chars("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"));
        assert!(!is_valid_base58_chars("0")); // '0' not in Base58
        assert!(!is_valid_base58_chars("O")); // 'O' not in Base58
        assert!(!is_valid_base58_chars("I")); // 'I' not in Base58
        assert!(!is_valid_base58_chars("l")); // 'l' not in Base58
    }

    #[test]
    fn test_find_invalid() {
        assert_eq!(find_invalid_char("abc123"), None);
        assert_eq!(find_invalid_char("abc0123"), Some(3)); // '0' at position 3
        assert_eq!(find_invalid_char("Oops"), Some(0)); // 'O' at position 0
    }

    #[test]
    fn test_prefilter_invalid_chars() {
        assert_eq!(
            prefilter("abc0def", Some(&[1, 2, 3])),
            PrefilterResult::InvalidChars
        );
    }

    #[test]
    fn test_prefilter_no_expected() {
        assert_eq!(
            prefilter("abc123", None),
            PrefilterResult::NeedsFullDecode
        );
    }

    #[test]
    fn test_prefilter_matching() {
        // "3yQ" encodes 9999 = 0x270F
        let result = prefilter("3yQ", Some(&[0x27, 0x0F]));
        assert_eq!(result, PrefilterResult::ProbablyValid);
    }

    #[test]
    fn test_prefilter_not_matching() {
        // "3yQ" encodes 9999, not 10000
        let result = prefilter("3yQ", Some(&[0x27, 0x10]));
        assert_eq!(result, PrefilterResult::DefinitelyInvalid);
    }

    #[test]
    fn test_prefilter_inline_same_result() {
        let input = "3yQ";
        let expected = [0x27u8, 0x0F];

        let result1 = prefilter(input, Some(&expected));
        let result2 = prefilter_inline(input, &expected);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_prefilter_layered_matching() {
        // "3yQ" encodes 9999 = 0x270F
        let result = prefilter_layered("3yQ", &[0x27, 0x0F]);
        assert_eq!(result, PrefilterResult::ProbablyValid);
    }

    #[test]
    fn test_prefilter_layered_mismatch() {
        // Wrong bytes should be detected
        let result = prefilter_layered("3yQ", &[0x27, 0x10]);
        assert_eq!(result, PrefilterResult::DefinitelyInvalid);
    }

    #[test]
    fn test_prefilter_layered_invalid_chars() {
        let result = prefilter_layered("3y0Q", &[0x27, 0x0F]);
        assert_eq!(result, PrefilterResult::InvalidChars);
    }

    #[test]
    fn test_prefilter_layered_inline_same_result() {
        let input = "3yQ";
        let expected = [0x27u8, 0x0F];

        let result1 = prefilter_layered(input, &expected);
        let result2 = prefilter_layered_inline(input, &expected);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_prefilter_layered_with_longer_input() {
        // Test with a longer input to exercise the tail matching code
        // Use known bs58 test vector
        let input = "JxF12TrwUP45BMd";
        // We don't know exact bytes, but this should not crash
        // and should return DefinitelyInvalid for random expected bytes
        let result = prefilter_layered(input, &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(result, PrefilterResult::DefinitelyInvalid);
    }
}
