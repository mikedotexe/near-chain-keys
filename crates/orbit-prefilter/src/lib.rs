//! # orbit-prefilter
//!
//! O(n) Base58 pre-filter for the DID/VC ecosystem.
//!
//! Reject invalid Base58 inputs **367× faster** than full decoding for 600+ character
//! payloads like `did:peer:4` and BBS+ proofs.
//!
//! ## Use Cases
//!
//! - **DoS protection**: Reject malformed inputs at API boundaries instantly
//! - **Cache validation**: Verify Base58 strings match expected bytes without decode
//! - **Queue filtering**: Pre-filter high-volume message streams
//!
//! ## Performance
//!
//! **Rejection** (invalid char at end of string):
//!
//! | Size      | bs58 decode | Orbit     | Speedup    |
//! |-----------|-------------|-----------|------------|
//! | 64 chars  | 1.4 µs      | 62 ns     | **23×**    |
//! | 256 chars | 27.5 µs     | 196 ns    | **140×**   |
//! | 600 chars | 165 µs      | 450 ns    | **367×**   |
//! | 2800 chars| 3.78 ms     | 1.9 µs    | **1989×**  |
//!
//! **Validation** (with expected bytes):
//!
//! | Size       | bs58 decode | Orbit    | Speedup   |
//! |------------|-------------|----------|-----------|
//! | 600 chars  | 161 µs      | 6.5 µs   | **25×**   |
//! | 1200 chars | 680 µs      | 13.3 µs  | **51×**   |
//! | 2800 chars | 3.64 ms     | 31.6 µs  | **115×**  |
//!
//! ## False Positive Rate
//!
//! - **orbit4**: 1 in 55,000 (~0.0018%)
//! - **orbit8**: 1 in 168 billion (~0.0000000006%)
//!
//! ## Security Warning
//!
//! **Orbit is NOT cryptographically secure.** An adversary can craft collisions.
//! Use only for non-adversarial contexts (caches, queues, DoS protection).
//!
//! ## Example
//!
//! ```rust
//! use orbit_prefilter::{prefilter, PrefilterResult};
//!
//! // Fast rejection of invalid input
//! let garbage = "did:peer:4zQm0000InvalidBase58!!!";
//! assert_eq!(prefilter(garbage, None), PrefilterResult::InvalidChars);
//!
//! // Validation against expected bytes
//! let b58 = "3yQ";
//! let expected = [0x27, 0x0F]; // 9999 in big-endian
//! assert_eq!(prefilter(b58, Some(&expected)), PrefilterResult::ProbablyValid);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod fingerprint;
pub mod precheck;
pub mod progressive;

// Re-export main API
pub use fingerprint::{Orbit4, Orbit8, Magic2, Magic3};
pub use precheck::{
    prefilter, prefilter_strong, prefilter_inline,
    prefilter_layered, prefilter_layered_inline,
    PrefilterResult,
    is_valid_base58_chars, find_invalid_char, b58_char_to_digit,
};
