//! Optimal base selection for terminating fractions.
//!
//! # Core Insight
//!
//! A fraction p/q terminates in base b **iff all prime factors of q divide b**.
//!
//! | Fraction | Optimal Base | Representation |
//! |----------|--------------|----------------|
//! | 1/3 | 3 (or 6, 12) | 0.1 (or 0.2, 0.4) |
//! | 1/5 | 5 (or 10) | 0.1 (or 0.2) |
//! | 1/7 | 7 | 0.1 |
//! | 1/6 | 6 (or 12) | 0.1 (or 0.2) |
//!
//! # Supported Bases
//!
//! We support a curated set of bases with good properties:
//!
//! | Base | Factors | Terminates |
//! |------|---------|------------|
//! | 6 | 2×3 | 1/2, 1/3, 1/6 |
//! | 10 | 2×5 | 1/2, 1/5, 1/10 |
//! | 12 | 2²×3 | 1/2, 1/3, 1/4, 1/6, 1/12 |
//! | 30 | 2×3×5 | 1/2, 1/3, 1/5, 1/6, 1/10, 1/15, 1/30 |
//! | 60 | 2²×3×5 | Many! (Babylonian) |

use crate::encode::Sign;

/// Supported bases for terminating fraction encoding.
/// Ordered by size for "smallest sufficient base" selection.
pub const SUPPORTED_BASES: &[u64] = &[6, 10, 12, 30, 60];

/// Alphabets for each supported base.
/// Using 0-9 for digits 0-9, then A-Z, then a-z for higher digits.
pub const BASE6_ALPHABET: &[u8] = b"012345";
pub const BASE10_ALPHABET: &[u8] = b"0123456789";
pub const BASE12_ALPHABET: &[u8] = b"0123456789AB";
pub const BASE30_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRST"; // Skip I, O
pub const BASE60_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwx"; // Skip confusable chars

// ============================================================================
// PRIME FACTORIZATION
// ============================================================================

/// Compute prime factorization of n.
/// Returns list of (prime, exponent) pairs.
pub fn prime_factors(mut n: u64) -> Vec<(u64, u32)> {
    if n <= 1 {
        return vec![];
    }

    let mut factors = Vec::new();
    let mut d = 2u64;

    while d * d <= n {
        let mut exp = 0u32;
        while n % d == 0 {
            n /= d;
            exp += 1;
        }
        if exp > 0 {
            factors.push((d, exp));
        }
        d += 1;
    }

    if n > 1 {
        factors.push((n, 1));
    }

    factors
}

/// Compute the "radical" of n: product of distinct prime factors.
/// This is the minimum base where 1/n terminates.
pub fn radical(n: u64) -> u64 {
    prime_factors(n).iter().map(|(p, _)| *p).product()
}

/// Compute the smallest power of the radical that n divides.
/// This determines how many fractional digits are needed.
pub fn termination_power(n: u64) -> u32 {
    let factors = prime_factors(n);
    factors.iter().map(|(_, exp)| *exp).max().unwrap_or(0)
}

// ============================================================================
// BASE SELECTION
// ============================================================================

/// Check if fraction p/q terminates in base b.
/// True iff all prime factors of q divide b.
pub fn terminates_in_base(denom: u64, base: u64) -> bool {
    if denom == 0 {
        return false;
    }

    let denom_primes: Vec<u64> = prime_factors(denom).iter().map(|(p, _)| *p).collect();
    let base_primes: Vec<u64> = prime_factors(base).iter().map(|(p, _)| *p).collect();

    denom_primes.iter().all(|p| base_primes.contains(p))
}

/// Find the smallest supported base where p/q terminates.
/// Returns None if no supported base works (e.g., 1/7).
pub fn optimal_supported_base(denom: u64) -> Option<u64> {
    SUPPORTED_BASES.iter().copied().find(|&b| terminates_in_base(denom, b))
}

/// Find the theoretical minimum base where 1/denom terminates.
/// This is the radical of denom (product of distinct prime factors).
pub fn minimum_base(denom: u64) -> u64 {
    if denom <= 1 {
        return 2;
    }
    radical(denom).max(2)
}

// ============================================================================
// FRACTION COMPUTATION
// ============================================================================

/// Compute the terminating digits of p/q in base b.
/// Returns (integer_part, fractional_digits).
///
/// Panics if the fraction doesn't terminate in the given base.
pub fn fraction_digits(num: u64, denom: u64, base: u64) -> (u64, Vec<u8>) {
    assert!(denom > 0, "denominator must be positive");
    assert!(terminates_in_base(denom, base), "fraction must terminate in base");

    let integer_part = num / denom;
    let mut remainder = num % denom;

    let mut frac_digits = Vec::new();

    // Compute fractional digits via long division
    // Since fraction terminates, this will eventually reach 0
    let max_digits = 64; // Safety limit
    for _ in 0..max_digits {
        if remainder == 0 {
            break;
        }
        remainder *= base;
        let digit = remainder / denom;
        frac_digits.push(digit as u8);
        remainder %= denom;
    }

    (integer_part, frac_digits)
}

/// Convert digit to character using the appropriate alphabet.
pub fn digit_to_char(digit: u8, base: u64) -> Option<char> {
    let alphabet = match base {
        6 => BASE6_ALPHABET,
        10 => BASE10_ALPHABET,
        12 => BASE12_ALPHABET,
        30 => BASE30_ALPHABET,
        60 => BASE60_ALPHABET,
        _ => return None,
    };

    alphabet.get(digit as usize).map(|&b| b as char)
}

/// Convert character to digit using the appropriate alphabet.
pub fn char_to_digit(c: char, base: u64) -> Option<u8> {
    let alphabet = match base {
        6 => BASE6_ALPHABET,
        10 => BASE10_ALPHABET,
        12 => BASE12_ALPHABET,
        30 => BASE30_ALPHABET,
        60 => BASE60_ALPHABET,
        _ => return None,
    };

    alphabet.iter().position(|&b| b == c as u8).map(|i| i as u8)
}

// ============================================================================
// TAIL MARKER ENCODING (mod 29 trick)
// ============================================================================

/// Base58 alphabet for tail markers.
const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Map base to base_id (0-4).
fn base_to_id(base: u64) -> Option<u8> {
    match base {
        6 => Some(0),
        10 => Some(1),
        12 => Some(2),
        30 => Some(3),
        60 => Some(4),
        _ => None,
    }
}

/// Map base_id (0-4) to base.
fn id_to_base(id: u8) -> Option<u64> {
    match id {
        0 => Some(6),
        1 => Some(10),
        2 => Some(12),
        3 => Some(30),
        4 => Some(60),
        _ => None,
    }
}

/// Pack base_id + sign into a residue mod 29.
/// Format: base_id * 5 + sign_bit * 2
/// - base_id: 0-4 (5 values)
/// - sign_bit: 0-1 (2 values)
/// - Total: 10 values (0-9), fits in mod 29
fn pack_tail_residue(base_id: u8, sign: Sign) -> u8 {
    let sign_bit = if sign == Sign::Negative { 1u8 } else { 0u8 };
    base_id * 5 + sign_bit * 2
}

/// Unpack base_id + sign from residue mod 29.
fn unpack_tail_residue(residue: u8) -> Option<(u64, Sign)> {
    let r = residue % 29;
    if r >= 25 {
        return None; // Invalid (only 0-24 are valid: 5 bases × 5 slots)
    }
    let base_id = r / 5;
    let sign_bit = (r % 5) / 2;
    let base = id_to_base(base_id)?;
    let sign = if sign_bit >= 1 { Sign::Negative } else { Sign::Positive };
    Some((base, sign))
}

/// Find a Base58 character whose digit value mod 29 equals target.
fn char_for_residue(target: u8) -> char {
    let target = target % 29;
    // Find first char in B58 alphabet where index mod 29 == target
    for (i, &c) in B58_ALPHABET.iter().enumerate() {
        if (i as u8) % 29 == target {
            return c as char;
        }
    }
    // Fallback (should never happen for valid targets)
    '1'
}

/// Extract residue mod 29 from a Base58 character.
fn residue_from_char(c: char) -> Option<u8> {
    B58_ALPHABET
        .iter()
        .position(|&b| b == c as u8)
        .map(|i| (i % 29) as u8)
}

// ============================================================================
// ENCODING
// ============================================================================

/// Encode a fraction as a string in its optimal base.
/// Format: [sign][integer].[fractional][tail_char]
///
/// The tail character encodes base + sign via mod 29 residue.
/// Returns None if no supported base can represent the fraction.
pub fn encode_terminating(num: u64, denom: u64, sign: Sign) -> Option<String> {
    let base = optimal_supported_base(denom)?;
    encode_in_base(num, denom, base, sign)
}

/// Encode a fraction in a specific base.
pub fn encode_in_base(num: u64, denom: u64, base: u64, sign: Sign) -> Option<String> {
    if !terminates_in_base(denom, base) {
        return None;
    }

    let (int_part, frac_digits) = fraction_digits(num, denom, base);
    let base_id = base_to_id(base)?;

    let mut result = String::new();

    // Integer part (no sign prefix - sign is in tail)
    if int_part == 0 {
        result.push('0');
    } else {
        let mut int_digits = Vec::new();
        let mut n = int_part;
        while n > 0 {
            int_digits.push(digit_to_char((n % base) as u8, base)?);
            n /= base;
        }
        int_digits.reverse();
        for c in int_digits {
            result.push(c);
        }
    }

    // Fractional part
    if !frac_digits.is_empty() {
        result.push('.');
        for d in &frac_digits {
            result.push(digit_to_char(*d, base)?);
        }
    }

    // Tail marker: single char encoding base + sign
    let tail_residue = pack_tail_residue(base_id, sign);
    result.push(char_for_residue(tail_residue));

    Some(result)
}

/// Encode with explicit suffix (for human readability).
pub fn encode_terminating_verbose(num: u64, denom: u64, sign: Sign) -> Option<String> {
    let base = optimal_supported_base(denom)?;
    let (int_part, frac_digits) = fraction_digits(num, denom, base);

    let mut result = String::new();

    if sign == Sign::Negative {
        result.push('-');
    }

    if int_part == 0 {
        result.push('0');
    } else {
        let mut int_digits = Vec::new();
        let mut n = int_part;
        while n > 0 {
            int_digits.push(digit_to_char((n % base) as u8, base)?);
            n /= base;
        }
        int_digits.reverse();
        for c in int_digits {
            result.push(c);
        }
    }

    if !frac_digits.is_empty() {
        result.push('.');
        for d in &frac_digits {
            result.push(digit_to_char(*d, base)?);
        }
    }

    result.push('_');
    result.push_str(&base.to_string());

    Some(result)
}

/// Decoded fraction result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTerminating {
    pub numerator: u64,
    pub denominator: u64,
    pub sign: Sign,
    pub base: u64,
}

/// Decode a terminating fraction string.
/// Expects format: [integer].[fractional][tail_char]
///
/// The tail character (last char) encodes base + sign via mod 29 residue.
pub fn decode_terminating(s: &str) -> Option<DecodedTerminating> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Extract tail character (last char)
    let tail_char = s.chars().last()?;
    let main = &s[..s.len() - tail_char.len_utf8()];

    // Decode base + sign from tail
    let tail_residue = residue_from_char(tail_char)?;
    let (base, sign) = unpack_tail_residue(tail_residue)?;

    // Split integer and fractional parts
    let (int_str, frac_str) = if let Some((i, f)) = main.split_once('.') {
        (i, f)
    } else {
        (main, "")
    };

    // Parse integer part
    let mut int_val = 0u64;
    for c in int_str.chars() {
        let d = char_to_digit(c, base)? as u64;
        int_val = int_val * base + d;
    }

    // Parse fractional part and compute numerator/denominator
    let mut frac_num = 0u64;
    let mut frac_denom = 1u64;
    for c in frac_str.chars() {
        let d = char_to_digit(c, base)? as u64;
        frac_num = frac_num * base + d;
        frac_denom *= base;
    }

    // Combine: int_val + frac_num/frac_denom = (int_val * frac_denom + frac_num) / frac_denom
    let numerator = int_val * frac_denom + frac_num;
    let denominator = frac_denom;

    // Reduce to lowest terms
    let g = gcd(numerator, denominator);

    Some(DecodedTerminating {
        numerator: numerator / g,
        denominator: denominator / g,
        sign,
        base,
    })
}

/// Decode verbose format: [sign][integer].[fractional]_[base]
pub fn decode_terminating_verbose(s: &str) -> Option<DecodedTerminating> {
    let s = s.trim();

    // Extract base from suffix
    let (main, base_str) = s.rsplit_once('_')?;
    let base: u64 = base_str.parse().ok()?;

    if !SUPPORTED_BASES.contains(&base) {
        return None;
    }

    // Handle sign
    let (sign, main) = if let Some(rest) = main.strip_prefix('-') {
        (Sign::Negative, rest)
    } else {
        (Sign::Positive, main)
    };

    // Split integer and fractional parts
    let (int_str, frac_str) = if let Some((i, f)) = main.split_once('.') {
        (i, f)
    } else {
        (main, "")
    };

    // Parse integer part
    let mut int_val = 0u64;
    for c in int_str.chars() {
        let d = char_to_digit(c, base)? as u64;
        int_val = int_val * base + d;
    }

    // Parse fractional part
    let mut frac_num = 0u64;
    let mut frac_denom = 1u64;
    for c in frac_str.chars() {
        let d = char_to_digit(c, base)? as u64;
        frac_num = frac_num * base + d;
        frac_denom *= base;
    }

    let numerator = int_val * frac_denom + frac_num;
    let denominator = frac_denom;
    let g = gcd(numerator, denominator);

    Some(DecodedTerminating {
        numerator: numerator / g,
        denominator: denominator / g,
        sign,
        base,
    })
}

/// Greatest common divisor.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prime_factors() {
        assert_eq!(prime_factors(12), vec![(2, 2), (3, 1)]);
        assert_eq!(prime_factors(7), vec![(7, 1)]);
        assert_eq!(prime_factors(60), vec![(2, 2), (3, 1), (5, 1)]);
        assert_eq!(prime_factors(1), vec![]);
    }

    #[test]
    fn test_radical() {
        assert_eq!(radical(12), 6);  // 12 = 2² × 3, radical = 2 × 3 = 6
        assert_eq!(radical(8), 2);   // 8 = 2³, radical = 2
        assert_eq!(radical(30), 30); // 30 = 2 × 3 × 5, radical = 30
    }

    #[test]
    fn test_terminates_in_base() {
        // 1/3 terminates in bases divisible by 3
        assert!(terminates_in_base(3, 6));
        assert!(terminates_in_base(3, 12));
        assert!(!terminates_in_base(3, 10));

        // 1/5 terminates in bases divisible by 5
        assert!(terminates_in_base(5, 10));
        assert!(!terminates_in_base(5, 12));

        // 1/6 needs both 2 and 3
        assert!(terminates_in_base(6, 6));
        assert!(terminates_in_base(6, 12));
        assert!(!terminates_in_base(6, 10));

        // 1/7 only terminates in bases divisible by 7
        assert!(!terminates_in_base(7, 6));
        assert!(!terminates_in_base(7, 60));
    }

    #[test]
    fn test_optimal_supported_base() {
        assert_eq!(optimal_supported_base(3), Some(6));   // First base with factor 3
        assert_eq!(optimal_supported_base(5), Some(10));  // First base with factor 5
        assert_eq!(optimal_supported_base(4), Some(6));   // 4=2², 6 has factor 2
        assert_eq!(optimal_supported_base(6), Some(6));   // 6=2×3
        assert_eq!(optimal_supported_base(7), None);      // Prime, no supported base works
    }

    #[test]
    fn test_fraction_digits() {
        // 1/3 in base 12 = 0.4
        assert_eq!(fraction_digits(1, 3, 12), (0, vec![4]));

        // 1/4 in base 12 = 0.3
        assert_eq!(fraction_digits(1, 4, 12), (0, vec![3]));

        // 1/6 in base 12 = 0.2
        assert_eq!(fraction_digits(1, 6, 12), (0, vec![2]));

        // 1/2 in base 10 = 0.5
        assert_eq!(fraction_digits(1, 2, 10), (0, vec![5]));

        // 7/3 in base 12 = 2.4
        assert_eq!(fraction_digits(7, 3, 12), (2, vec![4]));
    }

    #[test]
    fn test_encode_terminating() {
        // 1/3 with single-char tail
        let encoded = encode_terminating(1, 3, Sign::Positive).unwrap();
        println!("1/3 = {} (len={})", encoded, encoded.len());
        // Should be short: "0.2" + tail char
        assert!(encoded.len() <= 5);

        // 1/5 → "0.2" + tail for base 10
        let encoded = encode_terminating(1, 5, Sign::Positive).unwrap();
        println!("1/5 = {}", encoded);

        // -7/3: sign is in tail, not prefix
        let encoded = encode_terminating(7, 3, Sign::Negative).unwrap();
        println!("-7/3 = {}", encoded);
        // Should NOT start with '-' (sign is in tail)
        assert!(!encoded.starts_with('-'));
    }

    #[test]
    fn test_tail_char_decoding() {
        // Test that we can extract base + sign from tail
        let encoded = encode_terminating(1, 3, Sign::Positive).unwrap();
        let tail = encoded.chars().last().unwrap();
        let residue = residue_from_char(tail).unwrap();
        let (base, sign) = unpack_tail_residue(residue).unwrap();

        println!("Encoded: {}, tail='{}', residue={}, base={}, sign={:?}",
                 encoded, tail, residue, base, sign);

        assert_eq!(base, 6); // Optimal base for denom=3
        assert_eq!(sign, Sign::Positive);
    }

    #[test]
    fn test_roundtrip() {
        let test_cases = [
            (1, 3, Sign::Positive),
            (1, 5, Sign::Positive),
            (7, 3, Sign::Negative),
            (1, 6, Sign::Positive),
            (5, 12, Sign::Positive),
        ];

        for (num, denom, sign) in test_cases {
            if let Some(encoded) = encode_terminating(num, denom, sign) {
                let decoded = decode_terminating(&encoded).unwrap();
                assert_eq!(decoded.numerator, num, "numerator mismatch for {}/{}", num, denom);
                assert_eq!(decoded.denominator, denom, "denominator mismatch for {}/{}", num, denom);
                assert_eq!(decoded.sign, sign, "sign mismatch for {}/{}", num, denom);
                println!("{:+}{}/{} → {} → {:+}{}/{}",
                         if sign == Sign::Negative { "-" } else { "" }, num, denom,
                         encoded,
                         if decoded.sign == Sign::Negative { "-" } else { "" },
                         decoded.numerator, decoded.denominator);
            }
        }
    }

    #[test]
    fn test_verbose_format() {
        // Verbose format for human readability
        let verbose = encode_terminating_verbose(1, 3, Sign::Negative).unwrap();
        println!("-1/3 verbose = {}", verbose);
        assert!(verbose.starts_with('-'));
        assert!(verbose.contains('_'));

        let decoded = decode_terminating_verbose(&verbose).unwrap();
        assert_eq!(decoded.numerator, 1);
        assert_eq!(decoded.denominator, 3);
        assert_eq!(decoded.sign, Sign::Negative);
    }

    #[test]
    fn test_base_12_is_nice() {
        // Base 12 terminates many common fractions
        let terminates: Vec<u64> = (1..=12)
            .filter(|&d| terminates_in_base(d, 12))
            .collect();

        println!("Fractions that terminate in base 12: {:?}", terminates);
        // Should include: 1, 2, 3, 4, 6, 12
        assert!(terminates.contains(&2));
        assert!(terminates.contains(&3));
        assert!(terminates.contains(&4));
        assert!(terminates.contains(&6));
        assert!(terminates.contains(&12));
    }
}
