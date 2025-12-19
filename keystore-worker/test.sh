#!/bin/bash
# Test the keystore-worker with wasmtime

cd "$(dirname "$0")"

# 32-byte hex secret (64 hex chars)
MASTER_SECRET="4242424242424242424242424242424242424242424242424242424242424242"

echo "=== Test 1: get_address operation ==="
GET_ADDR_INPUT='{"operation":"get_address","account_id":"alice.near","chain_id":"solana:mainnet"}'
echo "Input:"
echo "$GET_ADDR_INPUT" | jq .
echo ""
echo "Output:"
echo "$GET_ADDR_INPUT" | wasmtime run --env MASTER_SECRET="$MASTER_SECRET" target/wasm32-wasip1/release/keystore-worker.wasm | jq .

echo ""
echo "=== Test 2: sign operation (legacy format, no operation field) ==="
# Test input: "Hello World!" base64 encoded = SGVsbG8gV29ybGQh
SIGN_INPUT='{"run_id":1,"auth_id":42,"authorization":{"signer_id":"alice.near","public_key":"ed25519:ABC123","actions":"[{\"action\":\"authorize_signing\",\"chain_id\":\"solana:mainnet\"}]","deadline":1735000000},"tx_params":"SGVsbG8gV29ybGQh"}'
echo "Input:"
echo "$SIGN_INPUT" | jq .
echo ""
echo "Output:"
echo "$SIGN_INPUT" | wasmtime run --env MASTER_SECRET="$MASTER_SECRET" target/wasm32-wasip1/release/keystore-worker.wasm | jq .
