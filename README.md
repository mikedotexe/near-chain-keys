# chain-keys

A NEAR smart contract for cross-chain key management. Register a public key, get canonical addresses for Bitcoin, Ethereum, Solana, and more - all derived on-chain.

## The Problem

The blockchain ecosystem has a fundamental identity challenge: **one keypair generates different addresses on different chains**.

Consider an [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) keypair. The same 32-byte public key becomes:
- **NEAR**: `98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de` (hex, 64 chars)
- **Solana**: `BGCCDDHfysuuVnaNVtEhhqeT4k9Muyem3Kpgq2U1m9HX` (Base58, 44 chars)

Same bytes, different encoding. But [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) is even more fragmented:
- **Ethereum**: `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` ([keccak256](https://en.wikipedia.org/wiki/SHA-3) hash, [EIP-55](https://eips.ethereum.org/EIPS/eip-55) checksummed)
- **Bitcoin P2WPKH**: `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` ([HASH160](https://learnmeabitcoin.com/technical/cryptography/hash160/), [bech32](https://en.bitcoin.it/wiki/Bech32))
- **Bitcoin P2TR**: `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0` ([BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) x-only, [bech32m](https://en.bitcoin.it/wiki/BIP_0350))
- **Cosmos**: `cosmos1...` (bech32 with chain-specific HRP)

One key, four completely different addresses. Users managing cross-chain portfolios face a bookkeeping nightmare, and there's no on-chain proof that these addresses share the same underlying key.

## The Solution: chain-keys Contract

This NEAR contract creates a verifiable registry of cross-chain key bindings. When you register a public key:

1. **Specify** the curve (Ed25519 or secp256k1) and target chain ([CAIP-2](https://chainagnostic.org/CAIPs/caip-2) identifier)
2. **Derive** the canonical address using on-chain cryptographic primitives (keccak256, SHA256, RIPEMD160, bech32)
3. **Store** the binding: `public_key → (chain, address, metadata)`

Now anyone can query: *"What's the Ethereum address for this NEAR key?"* or *"Show me all Bitcoin addresses registered to this account."*

### How It Works

**You bring your own key OR let [Outlayer](https://outlayer.fastnear.com) TEE generate one.**

**Option 1: Registry-only (self-custody)**
- Register a public key you control (hardware wallet, local generation)
- Contract derives canonical addresses for ETH, BTC, SOL, etc.
- You sign cross-chain transactions yourself

**Option 2: TEE-automated signing (recommended)**
1. Create a `PROTECTED_ED25519` secret in [Outlayer](https://outlayer.fastnear.com/secrets)
2. TEE generates keypair internally (private key never exposed)
3. Register the public key in chain-keys contract
4. Contract derives cross-chain addresses
5. Outlayer TEE signs transactions on your behalf

The `PROTECTED_*` prefix ensures the key was generated inside the TEE—backed by [Confidential Key Derivation (CKD)](https://outlayer.fastnear.com/docs/secrets#confidential-key-derivation) using the NEAR MPC Network. No single party ever sees the private key.

### Trust Models Compared

| Approach | Key Origin | Who Sees Private Key? | Trust |
|----------|------------|----------------------|-------|
| **Self-custody** | Your device | Only you | Yourself |
| **Outlayer TEE** | Generated in TEE | Only TEE enclave | Intel TDX + MPC |
| **MPC Chain Signatures** | Distributed nodes | Nobody (threshold) | NEAR MPC Network |

chain-keys works with any of these models—it's just a registry. The Outlayer TEE path is recommended for automated cross-chain signing because the private key is generated inside the secure enclave and never leaves it.

## Quick Start

```bash
cd crates/chain-keys
cargo wasm                    # Build WASM (outputs to res/chain_keys.wasm)
cargo t                       # Run tests
```

### Contract Methods

**Write methods** (require owner signature):
```bash
# Add a key with cross-chain binding
near call <contract> add_key '{
  "public_key": "secp256k1:...",
  "curve": "Secp256k1",
  "caip2_chain": "eip155:1",
  "metadata": [["label", "hot wallet"]]
}' --accountId you.near --deposit 0.1

# Remove a key (fails if it has a chain binding)
near call <contract> delete_key '{"public_key": "ed25519:..."}' --accountId you.near

# Force remove a key and its binding
near call <contract> force_delete_key '{"public_key": "secp256k1:..."}' --accountId you.near

# Update metadata for an existing key
near call <contract> update_metadata '{
  "public_key": "secp256k1:...",
  "metadata": [["origin", "tee:outlayer"], ["keystore", "ks.near"]]
}' --accountId you.near

# Add key with TEE attestation proof
near call <contract> add_key_with_attestation '{
  "public_key": "secp256k1:...",
  "curve": "Secp256k1",
  "caip2_chain": "eip155:1",
  "tee_attestation": {
    "tee_type": "tdx",
    "attestation_contract": "keystore-dao.near",
    "rtmr3": "abc123...",
    "verified_at": 12345678
  }
}' --accountId you.near --deposit 0.1

# Update TEE attestation for existing key
near call <contract> update_tee_attestation '{
  "public_key": "secp256k1:...",
  "tee_attestation": {
    "tee_type": "tdx",
    "attestation_contract": "keystore-dao.near",
    "verified_at": 12345678
  }
}' --accountId you.near

# Add key with CROSS-CONTRACT VERIFIED attestation
# Verifies RTMR3 is approved by the DAO before storing
# Also adds as NEAR access key
near call <contract> add_key_with_verified_attestation '{
  "public_key": "secp256k1:...",
  "curve": "Secp256k1",
  "caip2_chain": "eip155:1",
  "attestation_contract": "keystore-dao.near",
  "tee_attestation": {
    "tee_type": "tdx",
    "attestation_contract": "keystore-dao.near",
    "rtmr3": "abc123def456...",
    "verified_at": 12345678
  }
}' --accountId you.near --deposit 0.1 --gas 50000000000000

# Register TEE key (REGISTRY ONLY - no NEAR access key)
# Recommended for cross-chain TEE keys that don't need NEAR signing
near call <contract> register_tee_key '{
  "public_key": "secp256k1:...",
  "curve": "Secp256k1",
  "caip2_chain": "eip155:1",
  "attestation_contract": "keystore-dao.near",
  "tee_attestation": {
    "tee_type": "tdx",
    "attestation_contract": "keystore-dao.near",
    "rtmr3": "abc123def456...",
    "verified_at": 12345678
  }
}' --accountId you.near --gas 50000000000000
```

**View methods** (no signature required):
```bash
# Get binding for a specific key
near view <contract> get_pubkey_info '{"public_key": "secp256k1:..."}'

# List all keys for a chain
near view <contract> get_keys '{"caip2_chain": "eip155:1"}'

# List all Bitcoin keys (grouped by address type)
near view <contract> get_bitcoin_keys '{}'

# List keys by namespace
near view <contract> get_keys_by_namespace '{"namespace": "bip122"}'

# List all TEE-attested keys
near view <contract> get_tee_attested_keys '{}'

# List keys by TEE type
near view <contract> get_keys_by_tee_type '{"tee_type": "tdx"}'
```

### Supported Chains

| Chain | CAIP-2 Identifier | Curve | Address Format |
|-------|-------------------|-------|----------------|
| Ethereum | `eip155:1` | secp256k1 | EIP-55 checksummed |
| Bitcoin (SegWit) | `bip122:000000000019d6689c085ae165831e93` | secp256k1 | P2WPKH (bc1q...) |
| Bitcoin (Taproot) | `bip122:000000000019d6689c085ae165831e93:p2tr` | secp256k1 | P2TR (bc1p...) |
| Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | Ed25519 | Base58 |
| NEAR | `near:mainnet` | Ed25519 | Hex (implicit account) |

### Metadata Conventions

The `metadata` field accepts arbitrary key-value pairs. For TEE integration and interoperability, we recommend these conventions:

| Key | Description | Example Values |
|-----|-------------|----------------|
| `origin` | Key provenance | `tee:outlayer`, `hardware:ledger`, `software:local` |
| `keystore` | Linked keystore account | `keystore.near`, `ks.testnet` |
| `attestation_type` | TEE attestation type | `tdx`, `sgx`, `sev`, `simulated` |
| `attestation_time` | Unix timestamp of verification | `1702857600` |
| `label` | Human-readable label | `hot wallet`, `trading`, `cold storage` |
| `derivation_path` | BIP-44 path if HD wallet | `m/44'/60'/0'/0/0` |

**Example: TEE-managed key**
```bash
near call <contract> add_key '{
  "public_key": "secp256k1:...",
  "curve": "Secp256k1",
  "caip2_chain": "eip155:1",
  "metadata": [
    ["origin", "tee:outlayer"],
    ["keystore", "keystore.near"],
    ["attestation_type", "tdx"],
    ["attestation_time", "1702857600"],
    ["label", "ETH trading"]
  ]
}' --accountId you.near --deposit 0.1
```

**Example: Self-custody key**
```bash
near call <contract> add_key '{
  "public_key": "secp256k1:...",
  "curve": "Secp256k1",
  "caip2_chain": "bip122:000000000019d6689c085ae165831e93:p2tr",
  "metadata": [
    ["origin", "hardware:ledger"],
    ["label", "BTC cold storage"],
    ["derivation_path", "m/86h/0h/0h/0/0"]
  ]
}' --accountId you.near --deposit 0.1
```

Use `update_metadata` to add attestation info after initial registration or to refresh timestamps.

### TEE Attestation (Structured)

Beyond metadata conventions, chain-keys supports **structured TEE attestation** for provable key provenance:

```rust
struct TeeAttestation {
    tee_type: String,              // "tdx", "sgx", "phala", "sev"
    attestation_contract: String,  // Contract that verified attestation
    rtmr3: Option<String>,         // Runtime measurement (96 hex chars)
    verified_at: u64,              // Block height when verified
}
```

**Attestation methods:**

| Method | Trust Model | Gas | Adds NEAR Key? | Use Case |
|--------|-------------|-----|----------------|----------|
| `add_key_with_attestation` | Caller-provided | ~10 TGas | Yes | Off-chain verified |
| `add_key_with_verified_attestation` | Cross-contract | ~35 TGas | Yes | On-chain verified + NEAR key |
| `register_tee_key` | Cross-contract | ~35 TGas | **No** | Registry only (recommended for TEE) |

**Verified attestation flow:**
1. Caller provides `TeeAttestation` with RTMR3 measurement
2. Contract calls `is_rtmr3_approved(rtmr3)` on the attestation DAO
3. If approved → key is registered with attestation proof
4. If rejected → transaction fails

This proves "The TEE code measurement (RTMR3) is trusted by the DAO contract" without requiring changes to the DAO.

**Use structured attestation when:**
- You need to query all keys by TEE type (`get_keys_by_tee_type`)
- You want machine-readable attestation proofs
- You're building automated verification workflows

**Use metadata conventions when:**
- You need flexible, human-readable labels
- Attestation data doesn't fit the structured schema
- Backwards compatibility with existing tooling

Both can be used together—`tee_attestation` for structured data, `metadata` for additional context.

---

## Self-Hosted TEE (Outlayer without MPC)

For users who want full control over their cross-chain keys without depending on the NEAR MPC Network, Outlayer supports a **self-hosted mode**:

```bash
# Generate a master secret (store this securely!)
KEYSTORE_MASTER_SECRET=$(openssl rand -hex 32)

# Run keystore-worker with direct master secret
KEYSTORE_MASTER_SECRET=$KEYSTORE_MASTER_SECRET \
TEE_MODE=tdx \
cargo run --release
```

**How it works:**
- Master secret initializes the keystore directly (no MPC/CKD)
- Per-repo keys derived via HMAC-SHA256 (deterministic)
- ChaCha20-Poly1305 encryption for secrets
- TEE isolation protects master secret in memory

**Security model:**

| Property | MPC-backed (default) | Self-hosted |
|----------|---------------------|-------------|
| Master secret recovery | MPC network restores | Operator must backup |
| TEE restart | Automatic via CKD | Manual restore |
| Trust model | Threshold (t-of-n nodes) | Single operator |
| Key derivation | Deterministic | Deterministic |

**When to use self-hosted:**
- Private/airgapped deployments
- Full custody requirements
- No NEAR MPC dependency
- Development and testing

See [Outlayer keystore-worker](https://github.com/pkulik/near-outlayer/tree/main/keystore-worker) for setup details.

---

## Supporting Infrastructure

Beyond the contract, this repository includes supporting crates for cross-chain payload routing and encoding research.

### Repository Layout

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

### Crates

- **orbit-prefilter** - Standalone O(n) [Base58](https://en.bitcoin.it/wiki/Base58Check_encoding) pre-filter. Rejects invalid inputs 367× faster than full decoding. See [Deep Dive](#deep-dive-the-orbit-insight) for the math.
- **tail-encoding** - Address derivation, [CAIP-2](https://chainagnostic.org/CAIPs/caip-2)/[CAIP-10](https://chainagnostic.org/CAIPs/caip-10) encoding, and experimental encoding research
- **wire-frame** - Binary framing for cross-chain payloads (42 bytes overhead, O(1) routing)
- **api-server** - HTTP router that routes payloads to chain-specific queues

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

## Building

```bash
cargo build --workspace
cargo test --workspace
cargo bench -p orbit-prefilter

# NEAR contract
cd crates/chain-keys && cargo wasm
```

## Crate Details

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

## Deep Dive: The Orbit Insight

### The Intuition

**Why Base58?** Bitcoin introduced the [Base58](https://en.bitcoin.it/wiki/Base58Check_encoding) alphabet specifically to avoid ambiguous characters: no `0` (zero) vs `O` (oh), no `l` (ell) vs `I` (eye) vs `1` (one). This makes addresses safer to transcribe manually. Solana, [IPFS CIDs](https://docs.ipfs.tech/concepts/content-addressing/), and [Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/) adopted it too.

**The problem**: Validating a Base58 string requires decoding it to bytes, which involves arbitrary-precision arithmetic. For a string of length n, this is O(n²) - each digit affects all previously accumulated digits.

**The insight**: We can detect *definitely invalid* inputs much faster using modular arithmetic, without ever doing the full decode.

Think of it like checking divisibility by 9: instead of dividing a large number, you can sum its digits. If the digit sum isn't divisible by 9, the number isn't either. We're doing something similar for Base58.

### The Mathematics

#### The Vanishing Modulus

The key observation: `58 = 2 × 29`, which means `58 ≡ 0 (mod 29)`.

When you encode a value V as a Base58 string d₀d₁d₂...dₙ₋₁:

```
V = d₀×58^(n-1) + d₁×58^(n-2) + ... + dₙ₋₂×58¹ + dₙ₋₁×58⁰
```

Taking this mod 29:

```
V mod 29 = 0 + 0 + ... + 0 + dₙ₋₁ mod 29
         = dₙ₋₁ mod 29
```

All the higher powers vanish! Only the **last digit** contributes to the value mod 29. This means we can extract `V mod 29` in O(1) time by looking at a single character.

**The trade-off**: A single modulus only distinguishes 29 equivalence classes. Two different byte sequences that happen to have the same value mod 29 will produce identical fingerprints - a **false positive**. With just mod 29, roughly 1 in 29 (~3.4%) of invalid inputs would incorrectly pass. That's why we combine multiple moduli.

#### Horner's Method for O(n) Fingerprinting

For moduli where 58 doesn't vanish (like 7, 11, 23, 31), we use [Horner's method](https://en.wikipedia.org/wiki/Horner%27s_method):

```
acc = 0
for each digit d in the string:
    acc = (acc × 58 + d) mod p
```

This computes `V mod p` in O(n) time using only small integer arithmetic - no arbitrary precision needed.

The orbit-prefilter uses four primes (7, 11, 23, 31) with product 54,901. We compute the same fingerprint on both sides:
- **Base58 side**: Process the string character by character
- **Bytes side**: Process expected bytes with base 256

If the fingerprints don't match, the input is **definitely invalid**. If they match, it's **probably valid** (1 in ~55,000 false positive rate).

#### The 42 Connection

The number 42 appears throughout this project - not as a joke, but from genuine mathematics:

```
58 - 16 = 42    →    58 ≡ 16 (mod 42)    →    58 ≡ 2⁴ (mod 42)
```

When computing mod 42, multiplying by 58 is equivalent to multiplying by 16, which is a 4-bit left shift. This connects Base58 arithmetic to hexadecimal in an elegant way - the wire-frame protocol's 42-byte overhead is a nod to this relationship.

### Performance Results

On a 600-character payload (realistic for DIDs):

| Operation | bs58 decode | orbit-prefilter | Speedup |
|-----------|-------------|-----------------|---------|
| Rejection (invalid char) | 165 μs | 450 ns | **367×** |
| Validation (with expected bytes) | 161 μs | 6.5 μs | **25×** |

The rejection speedup is dramatic because we fail fast on invalid characters without any accumulation. Even validation is 25× faster because fingerprint computation is O(n) with minimal work per character.

### Security Note

Orbit fingerprinting is **NOT cryptographically secure**. An adversary can craft collisions by choosing values that differ by multiples of the moduli product.

Use orbit-prefilter for:
- DoS protection at API boundaries
- Cache key validation
- Pre-filtering before expensive operations
- Message queue filtering

For adversarial contexts, always follow a "probably valid" result with a full decode.

## License

MIT OR Apache-2.0
