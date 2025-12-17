//! Orbit fingerprinting for Base58 validation.
//!
//! Uses modular arithmetic to compute O(n) fingerprints that can validate
//! Base58 strings against expected bytes without full O(n²) decoding.

/// Moduli for orbit4: product = 54,901
/// False positive rate: ~1.8 × 10⁻⁵ (1 in 55,000)
const ORBIT4_MODULI: [u32; 4] = [7, 11, 23, 31];

/// Moduli for orbit8: product = 168,318,615,157
/// False positive rate: ~6 × 10⁻¹² (1 in 168 billion)
const ORBIT8_MODULI: [u32; 8] = [7, 11, 23, 31, 37, 41, 43, 47];

/// 4-modulus fingerprint (1 in 55k false positive rate)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Orbit4 {
    pub residues: [u32; 4],
}

/// 8-modulus fingerprint (1 in 168 billion false positive rate)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Orbit8 {
    pub residues: [u32; 8],
}

impl Orbit4 {
    /// Compute fingerprint from Base58 digits.
    /// Caller must have already validated that all digits are valid Base58.
    #[inline]
    pub fn from_b58_digits(digits: impl Iterator<Item = u8>) -> Self {
        let mut acc = [0u64; 4];
        for d in digits {
            for (i, &m) in ORBIT4_MODULI.iter().enumerate() {
                acc[i] = (acc[i] * 58 + d as u64) % m as u64;
            }
        }
        Self {
            residues: [acc[0] as u32, acc[1] as u32, acc[2] as u32, acc[3] as u32],
        }
    }

    /// Compute fingerprint from raw bytes (big-endian base-256).
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut acc = [0u64; 4];
        for &b in bytes {
            for (i, &m) in ORBIT4_MODULI.iter().enumerate() {
                acc[i] = (acc[i] * 256 + b as u64) % m as u64;
            }
        }
        Self {
            residues: [acc[0] as u32, acc[1] as u32, acc[2] as u32, acc[3] as u32],
        }
    }

    /// Check if fingerprints match.
    #[inline]
    pub fn matches(&self, other: &Self) -> bool {
        self.residues == other.residues
    }

    /// Product of moduli (for documentation).
    pub const PRODUCT: u64 = 7 * 11 * 23 * 31; // 54,901

    /// False positive rate as a fraction.
    pub const FP_RATE: f64 = 1.0 / 54_901.0;
}

impl Orbit8 {
    /// Compute fingerprint from Base58 digits.
    #[inline]
    pub fn from_b58_digits(digits: impl Iterator<Item = u8>) -> Self {
        let mut acc = [0u64; 8];
        for d in digits {
            for (i, &m) in ORBIT8_MODULI.iter().enumerate() {
                acc[i] = (acc[i] * 58 + d as u64) % m as u64;
            }
        }
        Self {
            residues: [
                acc[0] as u32, acc[1] as u32, acc[2] as u32, acc[3] as u32,
                acc[4] as u32, acc[5] as u32, acc[6] as u32, acc[7] as u32,
            ],
        }
    }

    /// Compute fingerprint from raw bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut acc = [0u64; 8];
        for &b in bytes {
            for (i, &m) in ORBIT8_MODULI.iter().enumerate() {
                acc[i] = (acc[i] * 256 + b as u64) % m as u64;
            }
        }
        Self {
            residues: [
                acc[0] as u32, acc[1] as u32, acc[2] as u32, acc[3] as u32,
                acc[4] as u32, acc[5] as u32, acc[6] as u32, acc[7] as u32,
            ],
        }
    }

    #[inline]
    pub fn matches(&self, other: &Self) -> bool {
        self.residues == other.residues
    }

    pub const PRODUCT: u128 = 7 * 11 * 23 * 31 * 37 * 41 * 43 * 47; // 168,318,615,157
    pub const FP_RATE: f64 = 1.0 / 168_318_615_157.0;
}

// =============================================================================
// MAGIC MODULI: Exploiting 58 = 2 × 29 for O(1) B58-side computation
// =============================================================================

/// Magic moduli [8, 29]: O(1) on B58 side, O(n) on bytes side.
///
/// Key insight: `58 = 2 × 29` means:
/// - `58 ≡ 0 (mod 29)` → Only the **last** B58 digit matters
/// - `58³ ≡ 0 (mod 8)` → Only the last **3** B58 digits matter
///
/// False positive rate: 1 in 232 (~0.43%)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Magic2 {
    pub mod8: u8,
    pub mod29: u8,
}

impl Magic2 {
    /// Compute fingerprint from Base58 digits - O(1) time!
    /// Only examines last 3 digits for mod8, last 1 for mod29.
    #[inline]
    pub fn from_b58_digits(digits: &[u8]) -> Self {
        let n = digits.len();

        // mod 29: only last digit (58 ≡ 0 mod 29)
        let mod29 = if n > 0 { digits[n - 1] % 29 } else { 0 };

        // mod 8: only last 3 digits (58³ ≡ 0 mod 8)
        // 58 ≡ 2 mod 8, so: value = d[-3]*4 + d[-2]*2 + d[-1]
        let mod8 = match n {
            0 => 0,
            1 => digits[0] % 8,
            2 => ((digits[0] as u16 * 2 + digits[1] as u16) % 8) as u8,
            _ => {
                let d0 = digits[n - 3] as u16;
                let d1 = digits[n - 2] as u16;
                let d2 = digits[n - 1] as u16;
                ((d0 * 4 + d1 * 2 + d2) % 8) as u8
            }
        };

        Self { mod8, mod29 }
    }

    /// Compute fingerprint from raw bytes - O(n) Horner's method.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut acc29 = 0u32;
        for &b in bytes {
            // 256 ≡ 0 mod 8, so mod8 = last byte mod 8
            acc29 = (acc29 * 256 + b as u32) % 29;
        }
        // mod 8: 256 ≡ 0 mod 8, so only last byte matters
        let mod8 = bytes.last().map(|&b| b % 8).unwrap_or(0);
        Self {
            mod8,
            mod29: acc29 as u8,
        }
    }

    #[inline]
    pub fn matches(&self, other: &Self) -> bool {
        self.mod8 == other.mod8 && self.mod29 == other.mod29
    }

    pub const PRODUCT: u32 = 8 * 29; // 232
    pub const FP_RATE: f64 = 1.0 / 232.0; // ~0.43%
}

/// Magic moduli [8, 29, 57]: O(1)+O(n) on B58 side, O(n) on bytes side.
///
/// Adds mod 57 to Magic2 for better false positive rate.
/// - `58 ≡ 1 (mod 57)` → Digit sum (O(n), but simple)
///
/// False positive rate: 1 in 13,224 (~0.0076%)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Magic3 {
    pub mod8: u8,
    pub mod29: u8,
    pub mod57: u8,
}

impl Magic3 {
    /// Compute fingerprint from Base58 digits.
    /// mod8 and mod29 are O(1), mod57 is O(n) digit sum.
    #[inline]
    pub fn from_b58_digits(digits: &[u8]) -> Self {
        let n = digits.len();

        // mod 29: only last digit (58 ≡ 0 mod 29)
        let mod29 = if n > 0 { digits[n - 1] % 29 } else { 0 };

        // mod 8: only last 3 digits
        let mod8 = match n {
            0 => 0,
            1 => digits[0] % 8,
            2 => ((digits[0] as u16 * 2 + digits[1] as u16) % 8) as u8,
            _ => {
                let d0 = digits[n - 3] as u16;
                let d1 = digits[n - 2] as u16;
                let d2 = digits[n - 1] as u16;
                ((d0 * 4 + d1 * 2 + d2) % 8) as u8
            }
        };

        // mod 57: digit sum (58 ≡ 1 mod 57)
        let mut sum = 0u32;
        for &d in digits {
            sum += d as u32;
        }
        let mod57 = (sum % 57) as u8;

        Self { mod8, mod29, mod57 }
    }

    /// Compute fingerprint from raw bytes - O(n) Horner's method.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut acc29 = 0u32;
        let mut acc57 = 0u32;
        for &b in bytes {
            acc29 = (acc29 * 256 + b as u32) % 29;
            acc57 = (acc57 * 256 + b as u32) % 57;
        }
        let mod8 = bytes.last().map(|&b| b % 8).unwrap_or(0);
        Self {
            mod8,
            mod29: acc29 as u8,
            mod57: acc57 as u8,
        }
    }

    #[inline]
    pub fn matches(&self, other: &Self) -> bool {
        self.mod8 == other.mod8 && self.mod29 == other.mod29 && self.mod57 == other.mod57
    }

    pub const PRODUCT: u32 = 8 * 29 * 57; // 13,224
    pub const FP_RATE: f64 = 1.0 / 13_224.0; // ~0.0076%
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orbit4_consistency() {
        // Value 9999 = 0x270F
        // Base58: "3yQ" = digits [2, 56, 23] (0-indexed in Base58 alphabet)
        // 'Q' = 23 in Base58 (after skipping 'I' and 'O')
        let digits = [2u8, 56, 23]; // '3' = 2, 'y' = 56, 'Q' = 23
        let bytes = [0x27u8, 0x0F];

        let fp_digits = Orbit4::from_b58_digits(digits.iter().copied());
        let fp_bytes = Orbit4::from_bytes(&bytes);

        assert!(fp_digits.matches(&fp_bytes));
    }

    #[test]
    fn test_orbit4_mismatch() {
        let bytes_a = [0x27u8, 0x0F]; // 9999
        let bytes_b = [0x27u8, 0x10]; // 10000

        let fp_a = Orbit4::from_bytes(&bytes_a);
        let fp_b = Orbit4::from_bytes(&bytes_b);

        assert!(!fp_a.matches(&fp_b));
    }

    #[test]
    fn test_orbit8_stronger() {
        // Same test with orbit8
        let bytes_a = [0x27u8, 0x0F];
        let bytes_b = [0x27u8, 0x10];

        let fp_a = Orbit8::from_bytes(&bytes_a);
        let fp_b = Orbit8::from_bytes(&bytes_b);

        assert!(!fp_a.matches(&fp_b));
    }

    #[test]
    fn test_magic2_consistency() {
        // Value 9999 = 0x270F
        // Base58: "3yQ" = digits [2, 56, 23]
        let digits = [2u8, 56, 23];
        let bytes = [0x27u8, 0x0F];

        let fp_digits = Magic2::from_b58_digits(&digits);
        let fp_bytes = Magic2::from_bytes(&bytes);

        assert!(fp_digits.matches(&fp_bytes));
    }

    #[test]
    fn test_magic2_mismatch() {
        let bytes_a = [0x27u8, 0x0F]; // 9999
        let bytes_b = [0x27u8, 0x10]; // 10000

        let fp_a = Magic2::from_bytes(&bytes_a);
        let fp_b = Magic2::from_bytes(&bytes_b);

        assert!(!fp_a.matches(&fp_b));
    }

    #[test]
    fn test_magic3_consistency() {
        // Value 9999 = 0x270F
        let digits = [2u8, 56, 23];
        let bytes = [0x27u8, 0x0F];

        let fp_digits = Magic3::from_b58_digits(&digits);
        let fp_bytes = Magic3::from_bytes(&bytes);

        assert!(fp_digits.matches(&fp_bytes));
    }

    #[test]
    fn test_magic3_mismatch() {
        let bytes_a = [0x27u8, 0x0F];
        let bytes_b = [0x27u8, 0x10];

        let fp_a = Magic3::from_bytes(&bytes_a);
        let fp_b = Magic3::from_bytes(&bytes_b);

        assert!(!fp_a.matches(&fp_b));
    }
}
