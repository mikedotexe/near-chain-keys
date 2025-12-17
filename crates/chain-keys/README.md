# chain-keys

NEAR smart contract for cross-chain key management.

Add a public key with a destination chain, and the contract derives the canonical address on that chain. Keys are bound to their cross-chain identities on-chain.

## Building

```bash
cargo wasm      # Build WASM to res/chain_keys.wasm
cargo t         # Run tests
```

## Contract Methods

### Write Methods

```rust
// Add a key with automatic address derivation
add_key(public_key: String, curve: String, caip2_chain: String, metadata: Option<String>) -> Promise

// Remove a key
delete_key(public_key: String) -> Promise

// Force remove (owner only)
force_delete_key(public_key: String) -> Promise
```

### View Methods

```rust
// Query binding for a specific key
get_pubkey_info(public_key: String) -> Option<ChainBinding>

// List all keys for a chain
get_keys(caip2_chain: String) -> Vec<KeyInfo>

// List keys by namespace
get_keys_by_namespace(namespace: String) -> Vec<KeyInfo>

// Bitcoin-specific: get both address types
get_bitcoin_keys() -> BitcoinKeys
```

## Usage

```bash
# Add an Ed25519 key for Ethereum
near call <contract> add_key '{
  "public_key": "ed25519:...",
  "curve": "ed25519",
  "caip2_chain": "eip155:1"
}' --accountId you.near

# Add a secp256k1 key for Bitcoin mainnet
near call <contract> add_key '{
  "public_key": "secp256k1:...",
  "curve": "secp256k1",
  "caip2_chain": "bip122:000000000019d6689c085ae165831e93"
}' --accountId you.near

# Query keys
near view <contract> get_pubkey_info '{"public_key": "ed25519:..."}'
near view <contract> get_keys '{"caip2_chain": "eip155:1"}'
```

## Supported Chains

| CAIP-2 Chain ID | Network | Supported Curves |
|-----------------|---------|------------------|
| `eip155:1` | Ethereum Mainnet | secp256k1 |
| `bip122:000000000019d6689c085ae165831e93` | Bitcoin Mainnet | secp256k1 |
| `cosmos:cosmoshub-4` | Cosmos Hub | secp256k1 |
| `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | Solana Mainnet | ed25519 |
| `near:mainnet` | NEAR Mainnet | ed25519 |

## Address Derivation

The contract derives addresses on-chain using standard algorithms:

- **Ethereum**: Keccak256(pubkey)[12:32], EIP-55 checksummed
- **Bitcoin P2WPKH**: RIPEMD160(SHA256(pubkey)), bech32
- **Bitcoin P2TR**: Schnorr tweaked pubkey, bech32m
- **Solana**: Raw Ed25519 pubkey, Base58
- **NEAR**: Hex-encoded Ed25519 pubkey
- **Cosmos**: RIPEMD160(SHA256(pubkey)), bech32 with chain prefix

## License

MIT OR Apache-2.0
