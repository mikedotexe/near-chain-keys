# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cross-chain key management on NEAR, with supporting infrastructure for routing and O(n) Base58 validation.

**Primary Product**: chain-keys NEAR contract
**Standalone Crate**: orbit-prefilter (publishable to crates.io)
**Supporting Infrastructure**: tail-encoding, wire-frame, api-server

## Crates

### chain-keys (PRIMARY)
NEAR smart contract for cross-chain key bindings.
- `crates/chain-keys/contract/src/lib.rs` - Contract methods (add_key, delete_key, etc.)
- `crates/chain-keys/contract/src/derivation.rs` - On-chain address derivation

### orbit-prefilter (STANDALONE)
Production-ready O(n) Base58 pre-filter. Rejects invalid inputs 367x faster than full decoding.
- `crates/orbit-prefilter/src/fingerprint.rs` - Core orbit fingerprinting (Orbit4, Orbit8)
- `crates/orbit-prefilter/src/precheck.rs` - Main prefilter API
- `crates/orbit-prefilter/src/progressive.rs` - Progressive validation

### wire-frame
Binary framing for cross-chain payload routing with 42-byte overhead.
- `crates/wire-frame/src/lib.rs` - Frame/parse/peek APIs

### tail-encoding
Self-describing encoding with CAIP support and cross-chain key derivation.
- `crates/tail-encoding/src/key_derivation.rs` - Derive addresses from public keys
- `crates/tail-encoding/src/caip.rs` - CAIP-2/CAIP-10 encoding
- Experimental: signature.rs, error_correction.rs, fraction.rs, layered.rs, optimal_base.rs

### api-server
HTTP router for cross-chain payload routing.
- `api-server/src/main.rs` - Axum server
- `api-server/src/routes.rs` - POST /broadcast, POST /broadcast/bin endpoints
- `api-server/src/queue.rs` - Per-chain bounded queues

## Build & Run

```bash
cargo test --workspace              # Run all tests
cargo bench -p orbit-prefilter      # Benchmarks

# NEAR contract
cd crates/chain-keys
cargo wasm                          # Build WASM
cargo t                             # Run contract tests

# API server
cd api-server && cargo run
```

## The Orbit Insight

```
58 − 16 = 42    →    58 ≡ 16 (mod 42)    →    58 ≡ 2⁴ (mod 42)
```

When computing mod 42, multiplying by 58 (Base58) equals multiplying by 16 (hex), which is just a left shift by 4 bits. This enables O(n) probabilistic validation without full decode.
