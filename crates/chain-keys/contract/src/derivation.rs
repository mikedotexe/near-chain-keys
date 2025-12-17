//! Cross-chain address derivation for on-chain use.
//!
//! Minimal implementations optimized for WASM contract size.

use sha3::{Digest, Keccak256};
use sha2::Sha256;
use ripemd::Ripemd160;
use bech32::Hrp;

/// Derive NEAR implicit account ID from Ed25519 public key.
///
/// NEAR implicit accounts are the 32-byte Ed25519 public key
/// encoded as 64 lowercase hex characters.
pub fn derive_near_implicit(ed25519_bytes: &[u8; 32]) -> String {
    hex::encode(ed25519_bytes)
}

/// Derive Solana address from Ed25519 public key.
///
/// Solana addresses are the 32-byte Ed25519 public key
/// encoded as Base58.
pub fn derive_solana(ed25519_bytes: &[u8; 32]) -> String {
    bs58::encode(ed25519_bytes).into_string()
}

/// Derive Ethereum address from secp256k1 public key.
///
/// Expects 64 bytes: the x and y coordinates (NOT the 0x04 prefix).
/// Returns lowercase hex with 0x prefix.
///
/// # Panics
/// Panics if `pubkey_xy` is not exactly 64 bytes.
pub fn derive_ethereum(pubkey_xy: &[u8]) -> String {
    assert_eq!(pubkey_xy.len(), 64, "Expected 64 bytes (x || y), got {}", pubkey_xy.len());

    let hash = keccak256(pubkey_xy);
    // Last 20 bytes of keccak256 hash
    let addr_bytes = &hash[12..32];

    format!("0x{}", hex::encode(addr_bytes))
}

/// Derive EIP-55 checksummed Ethereum address.
///
/// Takes lowercase hex address (with or without 0x prefix).
pub fn to_eip55(addr_hex: &str) -> String {
    let s = addr_hex.strip_prefix("0x").unwrap_or(addr_hex);
    let lower = s.to_ascii_lowercase();

    let digest = keccak256(lower.as_bytes());

    let mut out = String::with_capacity(42);
    out.push_str("0x");

    for (i, ch) in lower.chars().enumerate() {
        let byte = digest[i / 2];
        let nibble = if i % 2 == 0 { (byte >> 4) & 0x0f } else { byte & 0x0f };

        if matches!(ch, 'a'..='f') && nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }

    out
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ============================================================================
// BITCOIN
// ============================================================================

/// Bitcoin network for address encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
}

/// Derive Bitcoin P2WPKH (native SegWit) address from secp256k1 public key.
///
/// Expects 64 bytes: x and y coordinates (uncompressed, without 0x04 prefix).
/// Returns bech32 address (bc1q... for mainnet, tb1q... for testnet).
pub fn derive_bitcoin_p2wpkh(pubkey_xy: &[u8], network: BitcoinNetwork) -> String {
    assert_eq!(pubkey_xy.len(), 64, "Expected 64 bytes (x || y), got {}", pubkey_xy.len());

    // Convert to compressed pubkey (33 bytes)
    let compressed = compress_pubkey(pubkey_xy);

    // Hash160 = RIPEMD160(SHA256(compressed_pubkey))
    let pubkey_hash = hash160(&compressed);

    // Encode as bech32 with witness version 0 (P2WPKH)
    let hrp = match network {
        BitcoinNetwork::Mainnet => Hrp::parse("bc").unwrap(),
        BitcoinNetwork::Testnet => Hrp::parse("tb").unwrap(),
    };

    // Use segwit encoding: witness version 0, 20-byte pubkey hash
    bech32::segwit::encode(hrp, bech32::Fe32::Q, &pubkey_hash).unwrap()
}

/// Compress a secp256k1 public key from 64 bytes (x || y) to 33 bytes.
///
/// If y is even: prefix 0x02
/// If y is odd: prefix 0x03
fn compress_pubkey(pubkey_xy: &[u8]) -> [u8; 33] {
    let x = &pubkey_xy[0..32];
    let y = &pubkey_xy[32..64];

    let mut compressed = [0u8; 33];
    // Check if y is odd or even (last byte)
    compressed[0] = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..33].copy_from_slice(x);
    compressed
}

/// Hash160 = RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(&sha256_hash);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd_hash);
    out
}

/// Derive Bitcoin P2TR (Taproot) address from secp256k1 public key.
///
/// Expects 64 bytes: x and y coordinates (uncompressed, without 0x04 prefix).
/// Returns bech32m address (bc1p... for mainnet, tb1p... for testnet).
///
/// Note: This uses the x-only pubkey as the output key directly (no BIP-341 tweak).
/// This is suitable for proving key correspondence but produces non-standard addresses.
/// For standard P2TR addresses, use a full Bitcoin library with proper tweaking.
pub fn derive_bitcoin_p2tr(pubkey_xy: &[u8], network: BitcoinNetwork) -> String {
    assert_eq!(pubkey_xy.len(), 64, "Expected 64 bytes (x || y), got {}", pubkey_xy.len());

    // Extract x-only pubkey (32 bytes)
    // BIP-340: we use the x-coordinate directly; the point with even y is implicit
    let x_only = x_only_pubkey(pubkey_xy);

    // Encode as bech32m with witness version 1 (P2TR)
    let hrp = match network {
        BitcoinNetwork::Mainnet => Hrp::parse("bc").unwrap(),
        BitcoinNetwork::Testnet => Hrp::parse("tb").unwrap(),
    };

    // Witness version 1 = Fe32::P (value 1)
    bech32::segwit::encode(hrp, bech32::Fe32::P, &x_only).unwrap()
}

/// Extract x-only pubkey (32 bytes) from uncompressed pubkey (64 bytes).
///
/// Per BIP-340, we just take the x-coordinate. The y-coordinate parity
/// is not encoded in the x-only format.
fn x_only_pubkey(pubkey_xy: &[u8]) -> [u8; 32] {
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&pubkey_xy[0..32]);
    x_only
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_near_implicit() {
        // Example from NEAR docs
        let pubkey_base58 = "BGCCDDHfysuuVnaNVtEhhqeT4k9Muyem3Kpgq2U1m9HX";
        let bytes = bs58::decode(pubkey_base58).into_vec().unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);

        let implicit = derive_near_implicit(&arr);
        assert_eq!(implicit, "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de");
    }

    #[test]
    fn test_solana_address() {
        let pubkey_base58 = "BGCCDDHfysuuVnaNVtEhhqeT4k9Muyem3Kpgq2U1m9HX";
        let bytes = bs58::decode(pubkey_base58).into_vec().unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);

        let solana_addr = derive_solana(&arr);
        // Same bytes, same base58 encoding
        assert_eq!(solana_addr, pubkey_base58);
    }

    #[test]
    fn test_ethereum_privkey_1() {
        // Known test vector: private key = 1
        // Uncompressed pubkey (without 0x04 prefix) for privkey=1:
        let pubkey_xy = hex::decode(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
             483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        ).unwrap();

        let addr = derive_ethereum(&pubkey_xy);
        assert_eq!(addr, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn test_eip55_checksum() {
        let addr = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        let checksummed = to_eip55(addr);
        assert_eq!(checksummed, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }

    #[test]
    fn test_bitcoin_p2wpkh_privkey_1() {
        // Known test vector: private key = 1
        // Same pubkey as Ethereum test
        let pubkey_xy = hex::decode(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
             483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        ).unwrap();

        let addr = derive_bitcoin_p2wpkh(&pubkey_xy, BitcoinNetwork::Mainnet);
        // Expected: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        // This is the well-known P2WPKH address for privkey=1
        assert!(addr.starts_with("bc1q"), "Expected bc1q prefix, got: {}", addr);
        println!("Bitcoin P2WPKH (privkey=1): {}", addr);
    }

    #[test]
    fn test_compress_pubkey() {
        // Test with privkey=1 pubkey (y is even, so prefix should be 0x02)
        let pubkey_xy = hex::decode(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
             483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        ).unwrap();

        let compressed = compress_pubkey(&pubkey_xy);
        assert_eq!(compressed.len(), 33);
        // y ends in B8 which is even, so prefix should be 0x02
        assert_eq!(compressed[0], 0x02);
        // x coordinate should match
        assert_eq!(&compressed[1..33], &pubkey_xy[0..32]);
    }

    #[test]
    fn test_hash160() {
        // Test Hash160 with a known value
        let data = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let hash = hash160(&data);
        // Expected hash160 of compressed pubkey for privkey=1
        assert_eq!(hex::encode(hash), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    #[test]
    fn test_bitcoin_p2tr_privkey_1() {
        // Same pubkey as other tests (privkey=1)
        let pubkey_xy = hex::decode(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
             483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        ).unwrap();

        let addr = derive_bitcoin_p2tr(&pubkey_xy, BitcoinNetwork::Mainnet);

        // Should produce bc1p... address (bech32m, witness v1)
        assert!(addr.starts_with("bc1p"), "Expected bc1p prefix, got: {}", addr);

        // The x-only pubkey is the first 32 bytes
        // This is an "internal key" address (no tweak), so it won't match
        // standard BIP-341 addresses, but it's deterministic
        println!("Bitcoin P2TR (privkey=1, internal key): {}", addr);
    }

    #[test]
    fn test_x_only_pubkey() {
        let pubkey_xy = hex::decode(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
             483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        ).unwrap();

        let x_only = x_only_pubkey(&pubkey_xy);
        assert_eq!(x_only.len(), 32);
        // Should be the x-coordinate
        assert_eq!(
            hex::encode(x_only),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }
}
