//! Benchmark: NEAR's explicit pubkey approach vs tail-encoded signatures
//!
//! Compares:
//! 1. NEAR-style: Borsh-serialized (signature, pubkey) tuple
//! 2. Tail-encoded: Base58(sig || pubkey) + tail char
//!
//! Run with: cargo bench --bench near_comparison

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use borsh::{BorshSerialize, BorshDeserialize};
use tail_encoding::signature::{
    Curve, SigFormat,
    encode_signature, encode_signature_with_pubkey,
    decode_signature, decode_signature_full, extract_signature_meta,
};

// ============================================================================
// NEAR-style structures (simplified)
// ============================================================================

/// Simulates NEAR's Ed25519 signature (64 bytes)
#[derive(BorshSerialize, BorshDeserialize, Clone)]
struct NearSignature([u8; 64]);

/// Simulates NEAR's Ed25519 public key (32 bytes)
#[derive(BorshSerialize, BorshDeserialize, Clone)]
struct NearPublicKey([u8; 32]);

/// NEAR-style: signature + pubkey as separate Borsh fields
#[derive(BorshSerialize, BorshDeserialize, Clone)]
struct NearSignedData {
    signature: NearSignature,
    public_key: NearPublicKey,
}

// ============================================================================
// SIZE COMPARISON
// ============================================================================

fn bench_size_comparison(c: &mut Criterion) {
    let sig_bytes = [0xABu8; 64];
    let pubkey_bytes = [0xCDu8; 32];

    // NEAR-style encoding
    let near_data = NearSignedData {
        signature: NearSignature(sig_bytes),
        public_key: NearPublicKey(pubkey_bytes),
    };
    let near_encoded = borsh::to_vec(&near_data).unwrap();

    // Tail-encoded
    let tail_encoded = encode_signature_with_pubkey(&sig_bytes, &pubkey_bytes, Curve::Ed25519);

    println!("\n=== SIZE COMPARISON ===");
    println!("NEAR Borsh:    {} bytes", near_encoded.len());
    println!("Tail-encoded:  {} chars ({} bytes UTF-8)", tail_encoded.len(), tail_encoded.len());
    println!("Raw payload:   {} bytes (sig + pubkey)", 64 + 32);
    println!();

    // Verify we can roundtrip both
    let _near_decoded: NearSignedData = borsh::from_slice(&near_encoded).unwrap();
    let tail_decoded = decode_signature_full(&tail_encoded).unwrap();
    assert_eq!(tail_decoded.signature, sig_bytes);
    assert_eq!(tail_decoded.pubkey.unwrap(), pubkey_bytes);
}

// ============================================================================
// ENCODING BENCHMARKS
// ============================================================================

fn bench_encoding(c: &mut Criterion) {
    let sig_bytes = [0xABu8; 64];
    let pubkey_bytes = [0xCDu8; 32];

    let mut group = c.benchmark_group("encoding");

    // NEAR-style Borsh encoding
    group.bench_function("near_borsh_encode", |b| {
        b.iter(|| {
            let data = NearSignedData {
                signature: NearSignature(black_box(sig_bytes)),
                public_key: NearPublicKey(black_box(pubkey_bytes)),
            };
            borsh::to_vec(&data).unwrap()
        })
    });

    // Tail-encoding with pubkey
    group.bench_function("tail_encode_with_pubkey", |b| {
        b.iter(|| {
            encode_signature_with_pubkey(
                black_box(&sig_bytes),
                black_box(&pubkey_bytes),
                Curve::Ed25519,
            )
        })
    });

    // Tail-encoding without pubkey (for comparison)
    group.bench_function("tail_encode_sig_only", |b| {
        b.iter(|| {
            encode_signature(
                black_box(&sig_bytes),
                Curve::Ed25519,
                SigFormat::Raw,
                None,
            )
        })
    });

    group.finish();
}

// ============================================================================
// DECODING BENCHMARKS
// ============================================================================

fn bench_decoding(c: &mut Criterion) {
    let sig_bytes = [0xABu8; 64];
    let pubkey_bytes = [0xCDu8; 32];

    // Pre-encode both formats
    let near_data = NearSignedData {
        signature: NearSignature(sig_bytes),
        public_key: NearPublicKey(pubkey_bytes),
    };
    let near_encoded = borsh::to_vec(&near_data).unwrap();
    let tail_encoded = encode_signature_with_pubkey(&sig_bytes, &pubkey_bytes, Curve::Ed25519);

    let mut group = c.benchmark_group("decoding");

    // NEAR-style Borsh decoding
    group.bench_function("near_borsh_decode", |b| {
        b.iter(|| {
            let decoded: NearSignedData = borsh::from_slice(black_box(&near_encoded)).unwrap();
            black_box(decoded)
        })
    });

    // Tail-decoding (full, with pubkey split)
    group.bench_function("tail_decode_full", |b| {
        b.iter(|| {
            decode_signature_full(black_box(&tail_encoded)).unwrap()
        })
    });

    // Tail-decoding (basic, returns combined payload)
    group.bench_function("tail_decode_basic", |b| {
        b.iter(|| {
            decode_signature(black_box(&tail_encoded)).unwrap()
        })
    });

    group.finish();
}

// ============================================================================
// METADATA EXTRACTION (O(1) vs field access)
// ============================================================================

fn bench_metadata_extraction(c: &mut Criterion) {
    let sig_bytes = [0xABu8; 64];
    let pubkey_bytes = [0xCDu8; 32];

    let near_data = NearSignedData {
        signature: NearSignature(sig_bytes),
        public_key: NearPublicKey(pubkey_bytes),
    };
    let near_encoded = borsh::to_vec(&near_data).unwrap();
    let tail_encoded = encode_signature_with_pubkey(&sig_bytes, &pubkey_bytes, Curve::Ed25519);

    let mut group = c.benchmark_group("metadata_extraction");

    // NEAR: Must decode to access pubkey
    group.bench_function("near_decode_for_pubkey", |b| {
        b.iter(|| {
            let decoded: NearSignedData = borsh::from_slice(black_box(&near_encoded)).unwrap();
            black_box(decoded.public_key)
        })
    });

    // Tail: O(1) metadata extraction (just reads last char)
    group.bench_function("tail_extract_meta_o1", |b| {
        b.iter(|| {
            extract_signature_meta(black_box(&tail_encoded)).unwrap()
        })
    });

    group.finish();
}

// ============================================================================
// VARYING PAYLOAD SIZES
// ============================================================================

fn bench_varying_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("varying_sig_sizes");

    // Test with different "signature" sizes to see scaling
    // (Not realistic for Ed25519, but shows algorithmic complexity)
    for size in [64, 128, 256, 512].iter() {
        let sig_bytes: Vec<u8> = (0..*size).map(|i| i as u8).collect();
        let pubkey_bytes = [0xCDu8; 32];

        let tail_encoded = encode_signature_with_pubkey(&sig_bytes, &pubkey_bytes, Curve::Ed25519);

        group.bench_with_input(
            BenchmarkId::new("tail_decode", size),
            &tail_encoded,
            |b, encoded| {
                b.iter(|| decode_signature_full(black_box(encoded)).unwrap())
            },
        );

        group.bench_with_input(
            BenchmarkId::new("tail_meta_only", size),
            &tail_encoded,
            |b, encoded| {
                b.iter(|| extract_signature_meta(black_box(encoded)).unwrap())
            },
        );
    }

    group.finish();
}

// ============================================================================
// CRITERION MAIN
// ============================================================================

fn run_size_comparison(c: &mut Criterion) {
    bench_size_comparison(c);
}

criterion_group!(
    benches,
    run_size_comparison,
    bench_encoding,
    bench_decoding,
    bench_metadata_extraction,
    bench_varying_sizes,
);

criterion_main!(benches);
