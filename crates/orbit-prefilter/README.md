# orbit-prefilter

O(n) Base58 pre-filter for the DID/VC ecosystem.

Reject invalid Base58 inputs **367x faster** than full decoding for 600+ character payloads like `did:peer:4` and BBS+ proofs.

## Quick Start

```rust
use orbit_prefilter::{prefilter, PrefilterResult};

// Fast rejection of invalid input
let garbage = "did:peer:4zQm0000InvalidBase58!!!";
assert_eq!(prefilter(garbage, None), PrefilterResult::InvalidChars);

// Validation against expected bytes
let b58 = "3yQ";
let expected = [0x27, 0x0F]; // 9999 in big-endian
assert_eq!(prefilter(b58, Some(&expected)), PrefilterResult::ProbablyValid);
```

## Use Cases

- **DoS protection**: Reject malformed inputs at API boundaries instantly
- **Cache validation**: Verify Base58 strings match expected bytes without decode
- **Queue filtering**: Pre-filter high-volume message streams

## Performance

**Rejection** (invalid char at end of string):

| Size       | bs58 decode | Orbit     | Speedup    |
|------------|-------------|-----------|------------|
| 64 chars   | 1.4 us      | 62 ns     | **23x**    |
| 256 chars  | 27.5 us     | 196 ns    | **140x**   |
| 600 chars  | 165 us      | 450 ns    | **367x**   |
| 2800 chars | 3.78 ms     | 1.9 us    | **1989x**  |

**Validation** (with expected bytes):

| Size       | bs58 decode | Orbit    | Speedup   |
|------------|-------------|----------|-----------|
| 600 chars  | 161 us      | 6.5 us   | **25x**   |
| 1200 chars | 680 us      | 13.3 us  | **51x**   |
| 2800 chars | 3.64 ms     | 31.6 us  | **115x**  |

## API

```rust
pub enum PrefilterResult {
    InvalidChars,       // Definitely reject - invalid Base58 character found
    ProbablyValid,      // Fingerprints match - 99.998% confident values are equal
    DefinitelyInvalid,  // Fingerprints don't match - definitely different values
    NeedsFullDecode,    // All chars valid but no expected bytes to compare
}

// Standard prefilter (orbit4: 1 in 55k false positive rate)
pub fn prefilter(input: &str, expected: Option<&[u8]>) -> PrefilterResult;

// Stronger prefilter (orbit8: 1 in 168 billion false positive rate)
pub fn prefilter_strong(input: &str, expected: Option<&[u8]>) -> PrefilterResult;

// Zero-allocation inline prefilter
pub fn prefilter_inline(input: &str, expected: &[u8]) -> PrefilterResult;
```

## False Positive Rates

| Variant | Moduli Product | False Positive Rate |
|---------|----------------|---------------------|
| orbit4  | 54,901         | 1 in 55,000 (~0.0018%) |
| orbit8  | 168 billion    | 1 in 168 billion (~6e-12) |

## Security Warning

**Orbit is NOT cryptographically secure.** An adversary can craft collisions by choosing values that are multiples of the moduli product apart.

Use orbit only in non-adversarial contexts:
- DoS protection at API boundaries
- Cache key validation
- Message queue filtering
- Pre-filtering before expensive operations

Do NOT use orbit as a substitute for cryptographic hashes or signatures.

## How It Works

Orbit uses modular arithmetic to compute O(n) fingerprints. Since Base58 uses base 58 and bytes use base 256, and both can be reduced modulo small primes independently, we can validate that a Base58 string *probably* decodes to expected bytes without actually performing the O(n^2) decode.

The key insight: computing `(value mod p)` is O(n) for any base, while converting between bases is O(n^2).

## no_std Support

This crate supports `no_std` environments:

```toml
[dependencies]
orbit-prefilter = { version = "0.1", default-features = false }
```

## License

MIT OR Apache-2.0
