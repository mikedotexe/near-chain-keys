# chain-keys

Cross-chain key management and routing infrastructure, with O(n) Base58 validation.

## Project Structure

```
┌─────────────────────────────────────┐
│ chain-keys (NEAR contract)          │  PRIMARY PRODUCT
│ Cross-chain key bindings on NEAR    │
└─────────────────────────────────────┘

┌─────────────────┐
│ orbit-prefilter │  STANDALONE CRATE (publishable)
│ O(n) validation │
└─────────────────┘

┌────────────────┐  ┌─────────────┐  ┌────────────┐
│ tail-encoding  │  │ wire-frame  │  │ api-server │  SUPPORTING INFRASTRUCTURE
│ key derivation │  │ binary frame│  │ HTTP router│
└────────────────┘  └─────────────┘  └────────────┘
```

### Primary Product

**chain-keys** - NEAR smart contract for cross-chain key management. Add a public key, get derived addresses for Bitcoin, Ethereum, Solana, and more.

### Supporting Infrastructure

- **tail-encoding** - Address derivation, CAIP-2/CAIP-10 encoding, and experimental encoding research
- **wire-frame** - Binary framing for cross-chain payloads (42 bytes overhead, O(1) routing)
- **api-server** - HTTP router that routes payloads to chain-specific queues

### Standalone Crate

**orbit-prefilter** - O(n) Base58 pre-filter. Rejects invalid inputs 367x faster than full decoding.

## Quick Start

### NEAR Contract

```bash
cd crates/chain-keys
cargo wasm                    # Build WASM
cargo t                       # Run tests

# Deploy and use
near call <contract> add_key '{"public_key": "ed25519:...", "curve": "ed25519", "caip2_chain": "eip155:1"}' --accountId you.near
```

### Orbit Prefilter

```rust
use orbit_prefilter::{prefilter, PrefilterResult};

let result = prefilter("did:peer:4zQm...", Some(&expected_bytes));
match result {
    PrefilterResult::InvalidChars => { /* reject instantly */ }
    PrefilterResult::ProbablyValid => { /* fingerprints match */ }
    _ => { /* ... */ }
}
```

### Wire Frame

```rust
use wire_frame::{frame, peek_namespace, Namespace};

// Frame a payload for cross-chain routing
let framed = frame(Namespace::Near, &chain_ref, payload);

// O(1) peek at namespace without parsing
let ns = peek_namespace(&framed);  // Some(Namespace::Near)
```

### API Server

```bash
cd api-server
cargo run

# Text endpoint (CAIP-compact)
curl -X POST http://localhost:3000/broadcast -d "payload..."

# Binary endpoint (wire-frame)
cargo run -p wire-frame --example gen_frame -- near | \
  curl -X POST --data-binary @- http://localhost:3000/broadcast/bin
```

## The Orbit Insight

```
58 - 16 = 42    →    58 ≡ 16 (mod 42)    →    58 ≡ 2^4 (mod 42)
```

When computing mod 42, multiplying by 58 (Base58) equals multiplying by 16 (hex) - a 4-bit left shift. This enables O(n) probabilistic validation without O(n²) full decode.

## Building

```bash
cargo build --workspace
cargo test --workspace
cargo bench -p orbit-prefilter

# NEAR contract
cd crates/chain-keys && cargo wasm
```

## Crate Details

### chain-keys

NEAR contract methods:
- `add_key(public_key, curve, caip2_chain, metadata)` - Add key with derived address
- `delete_key(public_key)` - Remove a key binding
- `get_pubkey_info(public_key)` - Query binding for a key
- `get_keys(caip2_chain)` - List keys for a chain
- `get_keys_by_namespace(namespace)` - List keys by namespace

Supported chains: Ethereum, Bitcoin (P2WPKH, P2TR), Solana, NEAR, Cosmos

### orbit-prefilter

Performance (600 char payload):
- Rejection: **367x faster** than bs58 decode
- Validation: **25x faster** with fingerprint comparison

See [orbit-prefilter README](crates/orbit-prefilter/README.md) for full API.

### tail-encoding

Core modules:
- `key_derivation` - Derive addresses from public keys
- `caip` - CAIP-2/CAIP-10 encoding and parsing
- `residue`, `encode`, `decode` - Base detection and encoding

Experimental modules (research):
- `signature` - Curve metadata in tail
- `error_correction` - Typo detection/correction
- `fraction`, `optimal_base`, `layered` - Alternative encodings

### wire-frame

Binary framing format:
```
[payload (variable)][trailer: ns(1) + chain_ref(32) + version(1)][tag: blake3(8)]
```

42 bytes fixed overhead. O(1) namespace peek for routing.

## License

MIT OR Apache-2.0
