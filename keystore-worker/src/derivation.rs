//! Key derivation for TEE worker.
//!
//! Uses HKDF to derive chain-specific signing keys from the master secret.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::policy;

/// Load master secret from environment variable.
///
/// OutLayer injects this based on the secrets_ref config.
pub fn load_master_secret() -> Result<[u8; 32], String> {
    let hex_secret =
        std::env::var("MASTER_SECRET").map_err(|_| "MASTER_SECRET env var not set")?;

    let bytes = hex::decode(&hex_secret).map_err(|e| format!("Invalid hex in MASTER_SECRET: {}", e))?;

    if bytes.len() != 32 {
        return Err(format!(
            "MASTER_SECRET must be 32 bytes, got {}",
            bytes.len()
        ));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

/// Derive a signing key for a specific account and chain.
///
/// Uses HKDF-SHA256 with domain separation:
/// - IKM: master_secret
/// - Info: "{account_id}|{chain_id}|signing|v1"
pub fn derive_signing_key(
    master_secret: &[u8; 32],
    account_id: &str,
    chain_id: &str,
) -> [u8; 32] {
    let info = format!("{}|{}|signing|v1", account_id, chain_id);
    let hk = Hkdf::<Sha256>::new(None, master_secret);
    let mut output = [0u8; 32];
    hk.expand(info.as_bytes(), &mut output)
        .expect("32 bytes is valid HKDF output length");
    output
}

/// Get the public key from a signing key, formatted for the chain.
///
/// For ed25519 chains (Solana, NEAR): returns base58-encoded 32-byte pubkey
/// For secp256k1 chains (EVM, Bitcoin): returns hex-encoded compressed pubkey
pub fn get_public_key(signing_key: &[u8; 32], chain_id: &str) -> Result<String, String> {
    if policy::is_ed25519_chain(chain_id) {
        let key = SigningKey::from_bytes(signing_key);
        let pubkey = key.verifying_key();
        Ok(bs58::encode(pubkey.as_bytes()).into_string())
    } else if policy::is_secp256k1_chain(chain_id) {
        Err("secp256k1 chains not yet implemented".to_string())
    } else {
        Err(format!("Unsupported chain: {}", chain_id))
    }
}

/// Format an address for the chain.
///
/// For Solana: address == public key (base58)
/// For NEAR: address == public key with ed25519: prefix
/// For EVM: address == keccak256(uncompressed_pubkey)[12:] with 0x prefix
pub fn format_address(public_key: &str, chain_id: &str) -> String {
    if chain_id.starts_with("solana:") {
        // Solana: address is the public key
        public_key.to_string()
    } else if chain_id.starts_with("near:") {
        // NEAR: implicit account format (just the pubkey, or ed25519:pubkey)
        format!("ed25519:{}", public_key)
    } else {
        // Default: return pubkey as-is
        public_key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_signing_key_deterministic() {
        let secret = [0x42u8; 32];
        let key1 = derive_signing_key(&secret, "alice.near", "solana:mainnet");
        let key2 = derive_signing_key(&secret, "alice.near", "solana:mainnet");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_signing_key_different_accounts() {
        let secret = [0x42u8; 32];
        let key1 = derive_signing_key(&secret, "alice.near", "solana:mainnet");
        let key2 = derive_signing_key(&secret, "bob.near", "solana:mainnet");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_signing_key_different_chains() {
        let secret = [0x42u8; 32];
        let key1 = derive_signing_key(&secret, "alice.near", "solana:mainnet");
        let key2 = derive_signing_key(&secret, "alice.near", "eip155:1");
        assert_ne!(key1, key2);
    }
}
