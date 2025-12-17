# wire-frame

Binary framing for cross-chain payload routing.

## Format

```
[payload (variable)][trailer (34 bytes)][tag (8 bytes)]

Trailer: namespace (1) + chain_ref (32) + version (1)
Tag: blake3(payload || trailer) truncated to 8 bytes
```

**42 bytes fixed overhead** regardless of payload size.

## Usage

```rust
use wire_frame::{frame, parse, peek_namespace, verify_tag, Namespace};

// Frame a payload
let chain_ref = [0u8; 32];  // Chain-specific reference (e.g., genesis hash)
let payload = b"contract bytecode...";
let framed = frame(Namespace::Near, &chain_ref, payload);

// O(1) routing - peek namespace without parsing
let ns = peek_namespace(&framed);  // Some(Namespace::Near)

// Verify integrity
assert!(verify_tag(&framed));

// Full parse
let frame = parse(&framed).unwrap();
assert_eq!(frame.payload, payload);
assert_eq!(frame.namespace, Namespace::Near);
```

## Supported Namespaces

| Namespace | Value | Chain |
|-----------|-------|-------|
| Eip155 | 0 | Ethereum, EVM chains |
| Bip122 | 1 | Bitcoin |
| Cosmos | 2 | Cosmos Hub, Cosmos SDK chains |
| Solana | 3 | Solana |
| Polkadot | 4 | Polkadot, Substrate chains |
| Near | 5 | NEAR Protocol |
| Starknet | 6 | StarkNet |

## API

```rust
// Create frames
pub fn frame(namespace: Namespace, chain_ref: &[u8; 32], payload: &[u8]) -> Vec<u8>;
pub fn frame_versioned(namespace: Namespace, chain_ref: &[u8; 32], payload: &[u8], version: u8) -> Vec<u8>;

// O(1) inspection
pub fn peek_namespace(data: &[u8]) -> Option<Namespace>;
pub fn peek_chain_ref(data: &[u8]) -> Option<[u8; 32]>;

// Verification
pub fn verify_tag(data: &[u8]) -> bool;

// Parsing
pub fn parse(data: &[u8]) -> Result<Frame<'_>, ParseError>;
pub fn parse_unchecked(data: &[u8]) -> Result<Frame<'_>, ParseError>;
```

## CLI Example

```bash
# Generate test frames
cargo run -p wire-frame --example gen_frame -- near
cargo run -p wire-frame --example gen_frame -- ethereum
cargo run -p wire-frame --example gen_frame -- solana
```

## License

MIT OR Apache-2.0
