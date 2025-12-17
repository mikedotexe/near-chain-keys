//! Benchmarks demonstrating orbit prefilter speedup for large Base58 payloads.
//!
//! Target use case: did:peer:4 (600-1200 chars) and BBS+ proofs (500-1000 chars)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use orbit_prefilter::{
    prefilter, prefilter_strong, prefilter_inline, PrefilterResult,
    Orbit4, Magic2, Magic3, b58_char_to_digit,
    progressive::{base58_tail_bytes, tail_4_bytes, tail_matches},
};

/// Base58 alphabet for generating test data
const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Generate a random valid Base58 string of given length
fn generate_b58_string(len: usize, seed: u64) -> String {
    let mut result = Vec::with_capacity(len);
    let mut state = seed;
    for _ in 0..len {
        // Simple LCG for deterministic "random" generation
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let idx = (state >> 56) as usize % B58_ALPHABET.len();
        result.push(B58_ALPHABET[idx]);
    }
    String::from_utf8(result).unwrap()
}

/// Generate corresponding bytes for orbit comparison (deterministic from same seed)
fn generate_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut result = Vec::with_capacity(len);
    let mut state = seed;
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        result.push((state >> 56) as u8);
    }
    result
}

/// Benchmark: Reject invalid input (first char invalid)
fn bench_rejection_instant(c: &mut Criterion) {
    let mut group = c.benchmark_group("rejection_instant");

    // Invalid at first char - should be instant for both
    for size in [64, 256, 600, 2800] {
        let valid = generate_b58_string(size, 42);
        let invalid = format!("0{}", &valid[1..]); // '0' is invalid Base58

        group.bench_with_input(BenchmarkId::new("orbit", size), &invalid, |b, input| {
            b.iter(|| prefilter(black_box(input), None))
        });

        group.bench_with_input(BenchmarkId::new("bs58_decode", size), &invalid, |b, input| {
            b.iter(|| bs58::decode(black_box(input)).into_vec())
        });
    }

    group.finish();
}

/// Benchmark: Reject invalid input (last char invalid) - worst case for char validation
fn bench_rejection_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("rejection_at_end");

    for size in [64, 256, 600, 2800] {
        let valid = generate_b58_string(size, 42);
        let invalid = format!("{}0", &valid[..valid.len()-1]); // '0' at end

        group.bench_with_input(BenchmarkId::new("orbit", size), &invalid, |b, input| {
            b.iter(|| prefilter(black_box(input), None))
        });

        group.bench_with_input(BenchmarkId::new("bs58_decode", size), &invalid, |b, input| {
            b.iter(|| bs58::decode(black_box(input)).into_vec())
        });
    }

    group.finish();
}

/// Benchmark: Valid chars, no expected bytes (NeedsFullDecode path)
fn bench_valid_chars_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_chars_check");

    for size in [64, 256, 600, 2800] {
        let input = generate_b58_string(size, 42);

        group.bench_with_input(BenchmarkId::new("orbit", size), &input, |b, input| {
            b.iter(|| prefilter(black_box(input), None))
        });

        // bs58 doesn't have a char-check-only mode, so compare to full decode
        group.bench_with_input(BenchmarkId::new("bs58_decode", size), &input, |b, input| {
            b.iter(|| bs58::decode(black_box(input)).into_vec())
        });
    }

    group.finish();
}

/// Benchmark: Full validation with expected bytes (the key use case)
fn bench_validation_with_expected(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation_with_expected");

    for size in [64, 256, 600, 2800] {
        let input = generate_b58_string(size, 42);
        let expected = generate_bytes(size, 42); // Different seed = won't match, but that's fine

        group.bench_with_input(BenchmarkId::new("orbit4", size), &(&input, &expected), |b, (input, expected)| {
            b.iter(|| prefilter(black_box(input), Some(black_box(expected.as_slice()))))
        });

        group.bench_with_input(BenchmarkId::new("orbit8", size), &(&input, &expected), |b, (input, expected)| {
            b.iter(|| prefilter_strong(black_box(input), Some(black_box(expected.as_slice()))))
        });

        group.bench_with_input(BenchmarkId::new("orbit_inline", size), &(&input, &expected), |b, (input, expected)| {
            b.iter(|| prefilter_inline(black_box(input), black_box(expected.as_slice())))
        });

        // bs58 decode + compare
        group.bench_with_input(BenchmarkId::new("bs58_decode", size), &(&input, &expected), |b, (input, _expected)| {
            b.iter(|| {
                let decoded = bs58::decode(black_box(input)).into_vec();
                black_box(decoded)
            })
        });
    }

    group.finish();
}

/// Benchmark: Realistic did:peer:4 scenario
fn bench_did_peer_4(c: &mut Criterion) {
    let mut group = c.benchmark_group("did_peer_4_realistic");

    // Typical did:peer:4 is 600-1200 chars
    let sizes = [600, 800, 1000, 1200];

    for size in sizes {
        let b58_payload = generate_b58_string(size, 12345);
        let did = format!("did:peer:4z{}", b58_payload);

        // Extract just the Base58 part (after "did:peer:4z")
        let b58_part = &did[12..];
        let expected_bytes = generate_bytes(size / 2, 12345); // Rough expected decoded size

        group.bench_with_input(BenchmarkId::new("orbit_prefilter", size), &(b58_part, &expected_bytes), |b, (input, expected)| {
            b.iter(|| prefilter(black_box(input), Some(black_box(expected.as_slice()))))
        });

        group.bench_with_input(BenchmarkId::new("bs58_full_decode", size), &b58_part, |b, input| {
            b.iter(|| bs58::decode(black_box(input)).into_vec())
        });
    }

    group.finish();
}

/// Sanity check: verify our prefilter actually works correctly
fn bench_correctness_check(c: &mut Criterion) {
    // This isn't really a benchmark, but verifies our test data is valid
    let mut group = c.benchmark_group("correctness");

    let valid_b58 = "3yQ"; // Known: encodes 9999 = 0x270F
    let expected = [0x27u8, 0x0F];

    group.bench_function("known_value", |b| {
        b.iter(|| {
            let result = prefilter(black_box(valid_b58), Some(black_box(&expected)));
            assert_eq!(result, PrefilterResult::ProbablyValid);
            result
        })
    });

    group.finish();
}

/// Benchmark: Compare magic moduli vs orbit4 fingerprinting
/// This isolates just the fingerprint computation (not char validation)
fn bench_magic_vs_orbit(c: &mut Criterion) {
    let mut group = c.benchmark_group("magic_vs_orbit");

    for size in [64, 256, 600, 1200, 2800] {
        let b58_str = generate_b58_string(size, 42);
        let b58_digits: Vec<u8> = b58_str
            .bytes()
            .map(|c| b58_char_to_digit(c).unwrap())
            .collect();
        let bytes = generate_bytes(size, 42);

        // Current orbit4 approach - O(n) both sides
        group.bench_with_input(
            BenchmarkId::new("orbit4", size),
            &(&b58_digits, &bytes),
            |b, (digits, bytes)| {
                b.iter(|| {
                    let fp1 = Orbit4::from_b58_digits(black_box(digits.iter().copied()));
                    let fp2 = Orbit4::from_bytes(black_box(bytes));
                    black_box(fp1.matches(&fp2))
                })
            },
        );

        // Magic2 [8,29] - O(1) B58 side
        group.bench_with_input(
            BenchmarkId::new("magic2", size),
            &(&b58_digits, &bytes),
            |b, (digits, bytes)| {
                b.iter(|| {
                    let fp1 = Magic2::from_b58_digits(black_box(digits));
                    let fp2 = Magic2::from_bytes(black_box(bytes));
                    black_box(fp1.matches(&fp2))
                })
            },
        );

        // Magic3 [8,29,57] - O(1)+O(n) B58 side
        group.bench_with_input(
            BenchmarkId::new("magic3", size),
            &(&b58_digits, &bytes),
            |b, (digits, bytes)| {
                b.iter(|| {
                    let fp1 = Magic3::from_b58_digits(black_box(digits));
                    let fp2 = Magic3::from_bytes(black_box(bytes));
                    black_box(fp1.matches(&fp2))
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: Just B58-side fingerprint computation (isolates O(1) vs O(n))
fn bench_b58_side_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("b58_side_only");

    for size in [64, 256, 600, 1200, 2800] {
        let b58_str = generate_b58_string(size, 42);
        let b58_digits: Vec<u8> = b58_str
            .bytes()
            .map(|c| b58_char_to_digit(c).unwrap())
            .collect();

        // Orbit4 B58 side - O(n)
        group.bench_with_input(
            BenchmarkId::new("orbit4_b58", size),
            &b58_digits,
            |b, digits| {
                b.iter(|| Orbit4::from_b58_digits(black_box(digits.iter().copied())))
            },
        );

        // Magic2 B58 side - O(1)
        group.bench_with_input(
            BenchmarkId::new("magic2_b58", size),
            &b58_digits,
            |b, digits| {
                b.iter(|| Magic2::from_b58_digits(black_box(digits)))
            },
        );

        // Magic3 B58 side - O(1)+O(n) digit sum
        group.bench_with_input(
            BenchmarkId::new("magic3_b58", size),
            &b58_digits,
            |b, digits| {
                b.iter(|| Magic3::from_b58_digits(black_box(digits)))
            },
        );
    }

    group.finish();
}

/// Benchmark: Progressive decode vs full decode for last 4 bytes
fn bench_progressive_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("progressive_decode");

    for size in [64, 256, 600, 1200, 2800] {
        let b58_str = generate_b58_string(size, 42);

        // Progressive tail decode - O(32) for 4 bytes
        group.bench_with_input(
            BenchmarkId::new("tail_4_bytes", size),
            &b58_str,
            |b, input| {
                b.iter(|| tail_4_bytes(black_box(input)))
            },
        );

        // Progressive tail decode - O(64) for 8 bytes
        group.bench_with_input(
            BenchmarkId::new("tail_8_bytes", size),
            &b58_str,
            |b, input| {
                b.iter(|| base58_tail_bytes::<8>(black_box(input)))
            },
        );

        // Progressive tail decode - O(128) for 16 bytes
        group.bench_with_input(
            BenchmarkId::new("tail_16_bytes", size),
            &b58_str,
            |b, input| {
                b.iter(|| base58_tail_bytes::<16>(black_box(input)))
            },
        );

        // Full bs58 decode for comparison
        group.bench_with_input(
            BenchmarkId::new("bs58_full_decode", size),
            &b58_str,
            |b, input| {
                b.iter(|| bs58::decode(black_box(input)).into_vec())
            },
        );
    }

    group.finish();
}

/// Benchmark: Suffix matching with known expected bytes
fn bench_suffix_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("suffix_matching");

    for size in [256, 600, 1200, 2800] {
        let b58_str = generate_b58_string(size, 42);

        // Generate random expected suffix (will usually mismatch)
        let expected_suffix: Vec<u8> = generate_bytes(4, 123);

        // Tail match - O(32) for 4 bytes
        group.bench_with_input(
            BenchmarkId::new("tail_matches", size),
            &(&b58_str, &expected_suffix),
            |b, (input, suffix)| {
                b.iter(|| tail_matches(black_box(input), black_box(suffix)))
            },
        );

        // Full bs58 decode + compare
        group.bench_with_input(
            BenchmarkId::new("bs58_full_compare", size),
            &(&b58_str, &expected_suffix),
            |b, (input, suffix)| {
                b.iter(|| {
                    let decoded = bs58::decode(black_box(input)).into_vec();
                    if let Ok(bytes) = decoded {
                        if bytes.len() >= 4 {
                            black_box(&bytes[bytes.len()-4..] == suffix.as_slice());
                        }
                    }
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: Combined orbit + progressive validation strategy
fn bench_layered_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("layered_validation");

    for size in [600, 1200, 2800] {
        let b58_str = generate_b58_string(size, 42);
        let b58_digits: Vec<u8> = b58_str
            .bytes()
            .map(|c| b58_char_to_digit(c).unwrap())
            .collect();
        let expected_bytes = generate_bytes(size, 42);

        // Layer 1: Orbit fingerprint only
        group.bench_with_input(
            BenchmarkId::new("orbit4_only", size),
            &(&b58_digits, &expected_bytes),
            |b, (digits, bytes)| {
                b.iter(|| {
                    let fp1 = Orbit4::from_b58_digits(black_box(digits.iter().copied()));
                    let fp2 = Orbit4::from_bytes(black_box(bytes));
                    black_box(fp1.matches(&fp2))
                })
            },
        );

        // Layer 2: Progressive tail only
        group.bench_with_input(
            BenchmarkId::new("tail_only", size),
            &(&b58_str, &expected_bytes),
            |b, (input, bytes)| {
                b.iter(|| {
                    let suffix = &bytes[bytes.len().saturating_sub(4)..];
                    tail_matches(black_box(input), black_box(suffix))
                })
            },
        );

        // Combined: Orbit + Progressive tail
        group.bench_with_input(
            BenchmarkId::new("orbit_then_tail", size),
            &(&b58_str, &b58_digits, &expected_bytes),
            |b, (input, digits, bytes)| {
                b.iter(|| {
                    // First: orbit fingerprint
                    let fp1 = Orbit4::from_b58_digits(digits.iter().copied());
                    let fp2 = Orbit4::from_bytes(bytes);
                    if !fp1.matches(&fp2) {
                        return black_box(false);
                    }
                    // Second: progressive tail
                    let suffix = &bytes[bytes.len().saturating_sub(4)..];
                    black_box(tail_matches(input, suffix).unwrap_or(false))
                })
            },
        );

        // Baseline: Full bs58 decode
        group.bench_with_input(
            BenchmarkId::new("bs58_full", size),
            &b58_str,
            |b, input| {
                b.iter(|| bs58::decode(black_box(input)).into_vec())
            },
        );
    }

    group.finish();
}

/// Benchmark: Full layered prefilter API
fn bench_prefilter_layered(c: &mut Criterion) {
    let mut group = c.benchmark_group("prefilter_api");

    for size in [64, 256, 600, 1200, 2800] {
        let b58_str = generate_b58_string(size, 42);
        let expected_bytes = generate_bytes(size, 42);

        // prefilter (orbit4 only)
        group.bench_with_input(
            BenchmarkId::new("prefilter", size),
            &(&b58_str, &expected_bytes),
            |b, (input, bytes)| {
                b.iter(|| prefilter(black_box(input), Some(black_box(bytes.as_slice()))))
            },
        );

        // prefilter_layered (orbit4 + tail)
        group.bench_with_input(
            BenchmarkId::new("prefilter_layered", size),
            &(&b58_str, &expected_bytes),
            |b, (input, bytes)| {
                b.iter(|| {
                    orbit_prefilter::prefilter_layered(black_box(input), black_box(bytes.as_slice()))
                })
            },
        );

        // bs58 full decode + compare
        group.bench_with_input(
            BenchmarkId::new("bs58_full", size),
            &(&b58_str, &expected_bytes),
            |b, (input, bytes)| {
                b.iter(|| {
                    match bs58::decode(black_box(input)).into_vec() {
                        Ok(decoded) => black_box(decoded.as_slice() == bytes.as_slice()),
                        Err(_) => black_box(false),
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_rejection_instant,
    bench_rejection_end,
    bench_valid_chars_only,
    bench_validation_with_expected,
    bench_did_peer_4,
    bench_correctness_check,
    bench_magic_vs_orbit,
    bench_b58_side_only,
    bench_progressive_decode,
    bench_suffix_matching,
    bench_layered_validation,
    bench_prefilter_layered,
);

criterion_main!(benches);
