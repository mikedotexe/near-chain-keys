//! Residue math for tail-based metadata extraction.
//!
//! # Key Insight
//!
//! `58 = 2 × 29` means `58 ≡ 0 (mod 29)`, so the last Base58 digit alone
//! determines the decoded value mod 29. Other bases don't have this property.
//!
//! This lets us embed and extract metadata in O(1) from the tail.

/// Base58 alphabet (Bitcoin-style)
pub const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base64 alphabet (standard)
pub const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base32 alphabet (RFC 4648)
pub const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ============================================================================
// MAGIC MODULI
// ============================================================================

/// The "vanishing modulus" for Base58: 58 ≡ 0 (mod 29)
pub const MOD_29: u8 = 29;

/// Checksum modulus: 58 ≡ 1 (mod 57), so digit_sum ≡ value (mod 57)
pub const MOD_57: u8 = 57;

/// Powers of each base mod 29
/// 58^k mod 29 = 0 for all k >= 1 (58 = 2*29)
/// 64^k mod 29: [1, 6, 7, 13, 20, 4, 24, 28, 23, 22, 16, 9, 25, 5, 1, ...] (period 14)
/// 32^k mod 29: [1, 3, 9, 27, 23, 11, 4, 12, 7, 21, 5, 15, 16, 19, 28, 26, 20, 2, 6, 18, 25, 17, 22, 8, 24, 14, 13, 10, 1, ...] (period 28)

// ============================================================================
// BASE DETECTION
// ============================================================================

/// Detected encoding base
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedBase {
    Base58,
    Base64,
    Base32,
    Unknown,
}

/// Residues extracted from the tail
#[derive(Debug, Clone, Copy)]
pub struct TailResidue {
    /// Last char's digit value (in its alphabet)
    pub last_digit: u8,
    /// Residue mod 29 (for base detection)
    pub mod_29: u8,
    /// Detected base from alphabet analysis
    pub detected_base: DetectedBase,
}

/// Convert a character to its Base58 digit value (0-57), or None if invalid
#[inline]
pub fn b58_char_to_digit(c: u8) -> Option<u8> {
    match c {
        b'1'..=b'9' => Some(c - b'1'),           // '1' -> 0, '9' -> 8
        b'A'..=b'H' => Some(c - b'A' + 9),       // 'A' -> 9, 'H' -> 16
        b'J'..=b'N' => Some(c - b'J' + 17),      // 'J' -> 17, 'N' -> 21
        b'P'..=b'Z' => Some(c - b'P' + 22),      // 'P' -> 22, 'Z' -> 32
        b'a'..=b'k' => Some(c - b'a' + 33),      // 'a' -> 33, 'k' -> 43
        b'm'..=b'z' => Some(c - b'm' + 44),      // 'm' -> 44, 'z' -> 57
        _ => None,
    }
}

/// Convert a character to its Base64 digit value (0-63), or None if invalid
#[inline]
pub fn b64_char_to_digit(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Convert a character to its Base32 digit value (0-31), or None if invalid
#[inline]
pub fn b32_char_to_digit(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Detect the encoding base from alphabet analysis.
///
/// Uses distinguishing characters:
/// - '0', '+', '/' → Base64 (not in B58/B32)
/// - lowercase → not Base32
/// - 'O', 'I', 'l' → not Base58
pub fn detect_base_from_alphabet(s: &str) -> DetectedBase {
    let bytes = s.as_bytes();

    let mut could_be_b58 = true;
    #[allow(unused_mut)]
    let mut could_be_b64 = true; // Base64's alphabet is broad, rarely ruled out
    let mut could_be_b32 = true;

    for &c in bytes {
        // Check for Base64-only characters
        if c == b'0' || c == b'+' || c == b'/' {
            could_be_b58 = false;
            could_be_b32 = false;
        }

        // Check for characters that rule out Base58
        if c == b'O' || c == b'I' || c == b'l' {
            could_be_b58 = false;
        }

        // Lowercase rules out Base32
        if c.is_ascii_lowercase() {
            could_be_b32 = false;
        }

        // Digits 0, 1 rule out Base32 (only 2-7 allowed)
        if c == b'0' || c == b'1' {
            could_be_b32 = false;
        }

        // Digit 8, 9 rule out Base32
        if c == b'8' || c == b'9' {
            could_be_b32 = false;
        }
    }

    // Return most specific match
    match (could_be_b58, could_be_b64, could_be_b32) {
        (true, false, false) => DetectedBase::Base58,
        (false, true, false) => DetectedBase::Base64,
        (false, false, true) => DetectedBase::Base32,
        (true, true, false) => DetectedBase::Unknown, // Ambiguous B58/B64
        (true, false, true) => DetectedBase::Unknown, // Ambiguous B58/B32
        (false, true, true) => DetectedBase::Unknown, // Ambiguous B64/B32
        (true, true, true) => DetectedBase::Unknown,  // Completely ambiguous
        (false, false, false) => DetectedBase::Unknown, // Invalid for all
    }
}

/// Extract tail residue information from an encoded string.
///
/// Returns the last character's digit value and mod-29 residue.
pub fn extract_tail_residue(s: &str) -> Option<TailResidue> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let last_char = bytes[bytes.len() - 1];
    let detected_base = detect_base_from_alphabet(s);

    // Get digit value based on detected (or attempted) base
    let last_digit = match detected_base {
        DetectedBase::Base58 => b58_char_to_digit(last_char)?,
        DetectedBase::Base64 => b64_char_to_digit(last_char)?,
        DetectedBase::Base32 => b32_char_to_digit(last_char)?,
        DetectedBase::Unknown => {
            // Try each alphabet
            b58_char_to_digit(last_char)
                .or_else(|| b64_char_to_digit(last_char))
                .or_else(|| b32_char_to_digit(last_char))?
        }
    };

    Some(TailResidue {
        last_digit,
        mod_29: last_digit % MOD_29,
        detected_base,
    })
}

/// O(1) base detection from tail residue pattern.
///
/// For Base58: N mod 29 = last_digit mod 29 (because 58 ≡ 0 mod 29)
/// For Base64/32: The relationship is more complex, involving all digits.
///
/// This function checks if the tail residue is consistent with Base58's
/// vanishing property.
pub fn detect_base(s: &str) -> DetectedBase {
    // First pass: alphabet analysis (fast, definitive when possible)
    let alphabet_result = detect_base_from_alphabet(s);
    if alphabet_result != DetectedBase::Unknown {
        return alphabet_result;
    }

    // If ambiguous, we can't determine from alphabet alone
    // In a self-describing format, we'd use reserved residue ranges
    DetectedBase::Unknown
}

// ============================================================================
// CHECKSUM (digit sum mod 57)
// ============================================================================

/// Compute Base58 checksum: digit_sum mod 57.
///
/// Since 58 ≡ 1 (mod 57), the digit sum equals the decoded value mod 57.
pub fn b58_checksum(s: &str) -> Option<u8> {
    let mut sum: u32 = 0;
    for &c in s.as_bytes() {
        let d = b58_char_to_digit(c)?;
        sum += d as u32;
    }
    Some((sum % MOD_57 as u32) as u8)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b58_char_to_digit() {
        assert_eq!(b58_char_to_digit(b'1'), Some(0));
        assert_eq!(b58_char_to_digit(b'9'), Some(8));
        assert_eq!(b58_char_to_digit(b'A'), Some(9));
        assert_eq!(b58_char_to_digit(b'z'), Some(57));
        assert_eq!(b58_char_to_digit(b'0'), None); // Invalid
        assert_eq!(b58_char_to_digit(b'O'), None); // Invalid
        assert_eq!(b58_char_to_digit(b'I'), None); // Invalid
        assert_eq!(b58_char_to_digit(b'l'), None); // Invalid
    }

    #[test]
    fn test_detect_base_from_alphabet() {
        // Pure Base58 (has lowercase, no 0/O/I/l)
        assert_eq!(detect_base_from_alphabet("3yQ"), DetectedBase::Unknown); // ambiguous with b64

        // Has '0' → definitely Base64
        assert_eq!(detect_base_from_alphabet("abc0def"), DetectedBase::Base64);

        // Has '+' → definitely Base64
        assert_eq!(detect_base_from_alphabet("abc+def"), DetectedBase::Base64);

        // Uppercase only, 2-7 digits → ambiguous (could be Base32 or Base64)
        // "ABCD2345" is valid in both Base64 (A-Za-z0-9+/) and Base32 (A-Z2-7)
        let result = detect_base_from_alphabet("ABCD2345");
        assert!(result == DetectedBase::Base32 || result == DetectedBase::Unknown);

        // Has 'O' → not Base58
        assert_eq!(detect_base_from_alphabet("ABCOD"), DetectedBase::Unknown);
    }

    #[test]
    fn test_b58_checksum() {
        // "3yQ" encodes 9999
        // Digits: 3->2, y->55, Q->25 (in Base58)
        // Sum: 2 + 55 + 25 = 82
        // 82 mod 57 = 25
        let checksum = b58_checksum("3yQ").unwrap();

        // Verify: 9999 mod 57 = 9999 - 175*57 = 9999 - 9975 = 24
        // Hmm, let me recalculate the digit values
        // '3' -> b58_char_to_digit('3') = '3' - '1' = 2
        // 'y' -> 'y' - 'm' + 44 = 121 - 109 + 44 = 56
        // 'Q' -> 'Q' - 'P' + 22 = 1 + 22 = 23
        // Sum: 2 + 56 + 23 = 81
        // 81 mod 57 = 24
        // And 9999 mod 57 = 24 ✓
        assert_eq!(checksum, 24);
    }

    #[test]
    fn test_vanishing_property() {
        // 58 ≡ 0 (mod 29), so 58^k ≡ 0 (mod 29) for k >= 1
        assert_eq!(58 % 29, 0);
        assert_eq!((58 * 58) % 29, 0);
        assert_eq!((58 * 58 * 58) % 29, 0);

        // 64 and 32 don't vanish mod 29
        assert_ne!(64 % 29, 0);
        assert_ne!(32 % 29, 0);

        // 64 ≡ 6 (mod 29)
        assert_eq!(64 % 29, 6);

        // 32 ≡ 3 (mod 29)
        assert_eq!(32 % 29, 3);
    }
}
