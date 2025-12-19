# chain-keys / near-contract

NEAR Authorization Contract for TEE Keystore. Submit signed intents, trigger TEE signing, and get cross-chain addresses - all with multi-wallet support.

## Overview

This contract provides a **trust-minimized** authorization layer for TEE-based key management:

1. **Submit intents** - Users sign authorization intents with any supported wallet
2. **Get addresses** - Discover derived addresses before funding
3. **Trigger signing** - Anyone can trigger TEE execution (authorization controls scope)
4. **Watch events** - Relayers broadcast signed transactions

Supports 7 signature standards via NEAR Intents:
- NEP-413 (NEAR wallets)
- ERC-191 (Ethereum/MetaMask)
- TIP-191 (Tron)
- Raw Ed25519 (Solana/Phantom)
- WebAuthn (Passkeys)
- TonConnect (TON)
- SEP-53 (Stellar)

## Building

```bash
cargo wasm      # Build WASM to res/chain_keys.wasm
cargo c         # Check compilation
cargo t         # Run tests
```

## Deployment

```bash
# Deploy contract
near deploy chain-keys.near res/chain_keys.wasm

# Initialize with OutLayer configuration
near call chain-keys.near new '{
  "outlayer": "outlayer.near",
  "code_source": {
    "type": "github",
    "repo": "your-org/chain-keys",
    "commit": "abc123def456",
    "build_target": "wasm32-wasip1"
  },
  "secrets_ref": {
    "profile": "default",
    "account_id": "chain-keys.near"
  },
  "limits": {
    "max_instructions": 10000000,
    "max_memory_mb": 128,
    "max_execution_seconds": 60
  }
}' --accountId chain-keys.near
```

## Contract Methods

### Write Methods

#### `get_address` - Discover your cross-chain address

Get the derived address for an account on any supported chain. No authorization required - this is deterministic public information.

```bash
# Get Solana address for solana.mike.near
near call chain-keys.near get_address '{
  "account_id": "solana.mike.near",
  "chain_id": "solana:mainnet"
}' --accountId mike.near --deposit 0.1

# Get NEAR address (ed25519:prefix format)
near call chain-keys.near get_address '{
  "account_id": "alice.near",
  "chain_id": "near:mainnet"
}' --accountId alice.near --deposit 0.1
```

**Returns:**
```json
{
  "success": true,
  "operation": "get_address",
  "account_id": "solana.mike.near",
  "chain_id": "solana:mainnet",
  "public_key": "JCeogNwjUmBneNdJjrewebgaEwRNSFib5Hz7diDcZ1TJ",
  "address": "JCeogNwjUmBneNdJjrewebgaEwRNSFib5Hz7diDcZ1TJ"
}
```

#### `submit_intent` - Create an authorization

Submit a signed intent to authorize signing operations. The intent must be signed with a supported wallet.

```bash
# Submit an authorization intent (NEP-413 signed)
near call chain-keys.near submit_intent '{
  "multi_payload": {
    "Nep413": {
      "payload": {
        "message": "{\"actions\":[{\"AuthorizeSigning\":{\"chain_id\":\"solana:mainnet\"}}]}",
        "nonce": [1,2,3,...],
        "recipient": "chain-keys.near",
        "callback_url": null
      },
      "signature": "ed25519:...",
      "public_key": "ed25519:..."
    }
  }
}' --accountId solana.mike.near
```

**Returns:** `AuthorizationId` (e.g., `1`)

#### `run` - Trigger TEE signing

Execute a signing operation using an existing authorization. Anyone can call this - the authorization controls what gets signed.

```bash
# Sign a Solana transaction
# tx_params is base64-encoded transaction message
near call chain-keys.near run '{
  "auth_id": 1,
  "tx_params": [72, 101, 108, 108, 111]
}' --accountId relayer.near --deposit 0.2
```

**Emits event:** `run_completed` with signature

#### `revoke` - Cancel an authorization

Revoke an authorization before it's used. Requires a signed payload with `RevokeAuthorization` action.

```bash
near call chain-keys.near revoke '{
  "multi_payload": {
    "Nep413": {
      "payload": {
        "message": "{\"actions\":[{\"RevokeAuthorization\":{\"auth_id\":1}}]}",
        "nonce": [4,5,6,...],
        "recipient": "chain-keys.near",
        "callback_url": null
      },
      "signature": "ed25519:...",
      "public_key": "ed25519:..."
    }
  }
}' --accountId solana.mike.near
```

### View Methods

#### `get_authorization` - Check authorization status

```bash
near view chain-keys.near get_authorization '{"auth_id": 1}'
```

**Returns:**
```json
{
  "id": 1,
  "signer_id": "solana.mike.near",
  "public_key": "ed25519:...",
  "created_at": 12345678,
  "deadline": 1735000000,
  "actions_json": "[{\"AuthorizeSigning\":{\"chain_id\":\"solana:mainnet\"}}]",
  "status": "Active"
}
```

#### `get_config` - View contract configuration

```bash
near view chain-keys.near get_config '{}'
```

**Returns:**
```json
{
  "outlayer": "outlayer.near",
  "code_source": {
    "type": "github",
    "repo": "your-org/chain-keys",
    "commit": "abc123"
  },
  "secrets_ref": {
    "profile": "default",
    "account_id": "chain-keys.near"
  },
  "limits": {
    "max_instructions": 10000000,
    "max_memory_mb": 128,
    "max_execution_seconds": 60
  }
}
```

#### `is_nonce_used` - Check nonce replay protection

```bash
near view chain-keys.near is_nonce_used '{
  "pk_fingerprint": "a1b2c3d4e5f6...",
  "nonce": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
}'
```

## Demo Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Discover Address                                       │
│  near call chain-keys.near get_address '{                       │
│    "account_id": "solana.mike.near",                            │
│    "chain_id": "solana:mainnet"                                 │
│  }' --accountId mike.near --deposit 0.1                         │
│  → Returns: { "address": "JCeog..." }                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: Fund the Address                                       │
│  (Send SOL from external wallet to JCeog...)                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: Submit Authorization                                   │
│  near call chain-keys.near submit_intent '{...}'                │
│  → Returns: auth_id = 1                                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 4: Trigger Signing                                        │
│  near call chain-keys.near run '{                               │
│    "auth_id": 1,                                                │
│    "tx_params": [...]                                           │
│  }' --accountId relayer.near --deposit 0.2                      │
│  → EVENT: run_completed { signature: "..." }                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  Step 5: Broadcast                                              │
│  Relayer watches NEP-297 events, broadcasts to Solana           │
└─────────────────────────────────────────────────────────────────┘
```

## NEP-297 Events

The contract emits standard NEP-297 events for indexing and relayer integration:

```json
{"standard":"chain-keys","version":"1.0.0","event":"authorization_created","data":{...}}
{"standard":"chain-keys","version":"1.0.0","event":"authorization_revoked","data":{...}}
{"standard":"chain-keys","version":"1.0.0","event":"run_started","data":{...}}
{"standard":"chain-keys","version":"1.0.0","event":"run_completed","data":{...}}
{"standard":"chain-keys","version":"1.0.0","event":"run_failed","data":{...}}
```

## Supported Chains

| CAIP-2 Chain ID | Network | Curve | Status |
|-----------------|---------|-------|--------|
| `solana:mainnet` | Solana Mainnet | Ed25519 | v1 |
| `solana:devnet` | Solana Devnet | Ed25519 | v1 |
| `near:mainnet` | NEAR Mainnet | Ed25519 | v1 |
| `near:testnet` | NEAR Testnet | Ed25519 | v1 |
| `eip155:1` | Ethereum Mainnet | secp256k1 | planned |
| `bip122:000000000019d6689c085ae165831e93` | Bitcoin Mainnet | secp256k1 | planned |

## Authorization Status

| Status | Description |
|--------|-------------|
| `Active` | Ready to use |
| `Consumed` | Already used (single-use) |
| `Revoked` | Cancelled by signer |
| `Expired` | Past deadline |

## Trust Model

This contract is **trust-minimized**:

- **No owner gates** - Anyone can submit intents and trigger runs
- **Secrets protection** - `secrets_ref` is contract config, not user input
- **Caller pays** - Execution costs paid by whoever calls `run()`
- **Policy enforcement** - TEE validates tx_params against authorization

## License

MIT OR Apache-2.0
