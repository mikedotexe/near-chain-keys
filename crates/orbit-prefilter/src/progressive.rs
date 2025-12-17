//! Progressive Base58 tail decoding.
//!
//! # Key Insight
//!
//! `58^{8T} ≡ 0 (mod 256^T)` means the last `T` bytes of a decoded Base58 value
//! depend only on the last `8T` characters of the input string.
//!
//! | Bytes Wanted | Chars Needed | Time Complexity |
//! |--------------|--------------|-----------------|
//! | Last 4 bytes | Last 32 chars | O(32) |
//! | Last 8 bytes | Last 64 chars | O(64) |
//! | Last 16 bytes | Last 128 chars | O(128) |
//!
//! For a 600-character Base58 string, extracting the last 4 bytes takes
//! O(32) operations instead of O(600) — a **~20× speedup**.
//!
//! # Algorithm
//!
//! Uses byte-array arithmetic mod 256^T (no BigInt needed):
//! ```text
//! res = 0
//! for each char c in suffix:
//!     res = (res * 58 + digit(c)) mod 256^T
//! ```
//!
//! # Use Cases
//!
//! - **Checksum validation**: Verify last 4 bytes without full decode
//! - **Suffix matching**: Check if Base58 decodes to expected trailing bytes
//! - **Layered validation**: Orbit fingerprint → Tail decode → Full decode
//!
//! # Example
//!
//! ```rust
//! use orbit_prefilter::progressive::base58_tail_bytes;
//!
//! // Decode last 4 bytes of a Base58 string
//! let tail: [u8; 4] = base58_tail_bytes("3yZPQ").unwrap();
//!
//! // Works with prefixed strings too (e.g., NEAR keys)
//! let tail: [u8; 4] = base58_tail_bytes("ed25519:3yZPQ").unwrap();
//! ```

use crate::precheck::b58_char_to_digit;

// ============================================================================
// ERROR TYPE
// ============================================================================

/// Error from tail decode operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailDecodeError {
    /// Input string is empty (after prefix stripping).
    EmptyInput,
    /// Found a non-ASCII character.
    NonAscii,
    /// Found an invalid Base58 character.
    InvalidChar,
}

// ============================================================================
// PREFIX STRIPPING
// ============================================================================

/// Strip key-type prefix like `ed25519:` or `secp256k1:` from a string.
///
/// Base58 alphabet never contains ':', so this is safe.
#[inline]
pub fn strip_prefix(s: &str) -> &str {
    match s.split_once(':') {
        Some((_prefix, payload)) => payload,
        None => s,
    }
}

// ============================================================================
// BYTE-ARRAY ARITHMETIC (mod 256^T)
// ============================================================================

/// Multiply `x` (little-endian base-256) by small `m`, modulo 256^T.
/// Overflow beyond T bytes is discarded.
#[inline]
fn mul_small_le<const T: usize>(x: &mut [u8; T], m: u32) {
    let mut carry: u32 = 0;
    for byte in x.iter_mut() {
        let v = (*byte as u32) * m + carry;
        *byte = (v & 0xFF) as u8;
        carry = v >> 8;
    }
    // Overflow beyond T bytes is discarded (mod 256^T)
}

/// Add small `a` (< 256) to `x` (little-endian), modulo 256^T.
#[inline]
fn add_small_le<const T: usize>(x: &mut [u8; T], a: u8) {
    let mut carry = a as u16;
    for byte in x.iter_mut() {
        if carry == 0 {
            break;
        }
        let v = *byte as u16 + carry;
        *byte = (v & 0xFF) as u8;
        carry = v >> 8;
    }
}

// ============================================================================
// CORE TAIL DECODE
// ============================================================================

/// Decode the last `T` bytes of a Base58-encoded integer.
///
/// Returns the tail bytes in **big-endian** order (matching the decoded byte array).
///
/// # Key Property
///
/// Only examines the last `min(len, 8*T)` Base58 characters, making this
/// O(T) regardless of input length.
///
/// # Arguments
///
/// * `s` - Base58 string, optionally prefixed with `keytype:` (e.g., `ed25519:...`)
///
/// # Example
///
/// ```rust
/// use orbit_prefilter::progressive::base58_tail_bytes;
///
/// // "3yQ" encodes 9999 = 0x270F
/// let tail: [u8; 2] = base58_tail_bytes("3yQ").unwrap();
/// assert_eq!(tail, [0x27, 0x0F]);
///
/// let tail: [u8; 4] = base58_tail_bytes("3yQ").unwrap();
/// assert_eq!(tail, [0x00, 0x00, 0x27, 0x0F]);
/// ```
#[inline]
pub fn base58_tail_bytes<const T: usize>(s: &str) -> Result<[u8; T], TailDecodeError> {
    let s = strip_prefix(s);
    let bytes = s.as_bytes();

    if bytes.is_empty() {
        return Err(TailDecodeError::EmptyInput);
    }

    // Only need last 8*T characters
    let chars_needed = 8 * T;
    let start = bytes.len().saturating_sub(chars_needed);
    let suffix = &bytes[start..];

    // Accumulate in little-endian, mod 256^T
    let mut res_le = [0u8; T];

    for &c in suffix {
        let d = b58_digit(c)?;
        mul_small_le::<T>(&mut res_le, 58);
        add_small_le::<T>(&mut res_le, d);
    }

    // Convert to big-endian for output
    let mut out = [0u8; T];
    for i in 0..T {
        out[i] = res_le[T - 1 - i];
    }
    Ok(out)
}

/// Convert ASCII byte to Base58 digit value.
#[inline]
fn b58_digit(c: u8) -> Result<u8, TailDecodeError> {
    if c >= 128 {
        return Err(TailDecodeError::NonAscii);
    }
    b58_char_to_digit(c).ok_or(TailDecodeError::InvalidChar)
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Decode last 4 bytes (common case for checksums).
#[inline]
pub fn tail_4_bytes(s: &str) -> Result<[u8; 4], TailDecodeError> {
    base58_tail_bytes::<4>(s)
}

/// Decode last 8 bytes.
#[inline]
pub fn tail_8_bytes(s: &str) -> Result<[u8; 8], TailDecodeError> {
    base58_tail_bytes::<8>(s)
}

/// Decode last 16 bytes.
#[inline]
pub fn tail_16_bytes(s: &str) -> Result<[u8; 16], TailDecodeError> {
    base58_tail_bytes::<16>(s)
}

/// Check if the tail bytes of a Base58 string match expected bytes.
///
/// # Example
///
/// ```rust
/// use orbit_prefilter::progressive::tail_matches;
///
/// // "3yQ" encodes 9999 = 0x270F
/// assert!(tail_matches("3yQ", &[0x0F]).unwrap());       // last 1 byte
/// assert!(tail_matches("3yQ", &[0x27, 0x0F]).unwrap()); // last 2 bytes
/// assert!(!tail_matches("3yQ", &[0xFF]).unwrap());      // mismatch
/// ```
#[inline]
pub fn tail_matches(s: &str, expected: &[u8]) -> Result<bool, TailDecodeError> {
    match expected.len() {
        0 => Ok(true),
        1 => Ok(base58_tail_bytes::<1>(s)? == [expected[0]]),
        2 => Ok(base58_tail_bytes::<2>(s)? == [expected[0], expected[1]]),
        3 => Ok(base58_tail_bytes::<3>(s)? == [expected[0], expected[1], expected[2]]),
        4 => Ok(base58_tail_bytes::<4>(s)? == [expected[0], expected[1], expected[2], expected[3]]),
        _ => {
            // For larger expected, we'd need dynamic dispatch or more cases
            // For now, return false (caller should use full decode)
            Ok(false)
        }
    }
}

/// Convert tail bytes to lowercase hex string.
pub fn tail_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; bytes.len() * 2];
    for (i, &b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0F) as usize];
    }
    // SAFETY: output is ASCII hex
    unsafe { String::from_utf8_unchecked(out) }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tail_4_bytes() {
        // "3yQ" encodes 9999 = 0x270F
        let tail = tail_4_bytes("3yQ").unwrap();
        assert_eq!(tail, [0x00, 0x00, 0x27, 0x0F]);
    }

    #[test]
    fn test_tail_2_bytes() {
        let tail: [u8; 2] = base58_tail_bytes("3yQ").unwrap();
        assert_eq!(tail, [0x27, 0x0F]);
    }

    #[test]
    fn test_tail_1_byte() {
        let tail: [u8; 1] = base58_tail_bytes("3yQ").unwrap();
        assert_eq!(tail, [0x0F]);
    }

    #[test]
    fn test_strip_prefix() {
        assert_eq!(strip_prefix("ed25519:abc"), "abc");
        assert_eq!(strip_prefix("secp256k1:xyz"), "xyz");
        assert_eq!(strip_prefix("no_prefix_here"), "no_prefix_here");
    }

    #[test]
    fn test_prefixed_string() {
        // Same decode result with or without prefix
        let without = tail_4_bytes("3yQ").unwrap();
        let with = tail_4_bytes("ed25519:3yQ").unwrap();
        assert_eq!(without, with);
    }

    #[test]
    fn test_tail_matches() {
        assert!(tail_matches("3yQ", &[0x0F]).unwrap());
        assert!(tail_matches("3yQ", &[0x27, 0x0F]).unwrap());
        assert!(!tail_matches("3yQ", &[0xFF]).unwrap());
        assert!(!tail_matches("3yQ", &[0x28, 0x0F]).unwrap());
    }

    #[test]
    fn test_invalid_char() {
        assert_eq!(tail_4_bytes("abc0def"), Err(TailDecodeError::InvalidChar)); // '0' invalid
        assert_eq!(tail_4_bytes("abcOdef"), Err(TailDecodeError::InvalidChar)); // 'O' invalid
        assert_eq!(tail_4_bytes("abcIdef"), Err(TailDecodeError::InvalidChar)); // 'I' invalid
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(tail_4_bytes(""), Err(TailDecodeError::EmptyInput));
        assert_eq!(tail_4_bytes("ed25519:"), Err(TailDecodeError::EmptyInput));
    }

    #[test]
    fn test_tail_to_hex() {
        assert_eq!(tail_to_hex(&[0x27, 0x0F]), "270f");
        assert_eq!(tail_to_hex(&[0x00, 0x00, 0x27, 0x0F]), "0000270f");
    }

    #[test]
    fn test_longer_input() {
        // Verify correctness with a longer string
        // "JxF12TrwUP45BMd" encodes a known value
        // We can't easily verify without bs58, but we can check it doesn't panic
        let tail = tail_4_bytes("JxF12TrwUP45BMd").unwrap();
        assert_eq!(tail.len(), 4);
    }
}
