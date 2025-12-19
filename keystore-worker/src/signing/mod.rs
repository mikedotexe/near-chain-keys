//! Signing module for TEE worker.
//!
//! Dispatches to chain-specific signing implementations.

mod solana;

use crate::policy;

/// Sign transaction data for the given chain.
///
/// Returns (public_key, signature) as base58-encoded strings.
pub fn sign(
    signing_key: &[u8; 32],
    chain_id: &str,
    tx_params_b64: &str,
) -> Result<(String, String), String> {
    if policy::is_ed25519_chain(chain_id) {
        solana::sign_ed25519(signing_key, tx_params_b64)
    } else if policy::is_secp256k1_chain(chain_id) {
        Err(format!(
            "Chain '{}' uses secp256k1 which is not yet implemented",
            chain_id
        ))
    } else {
        Err(format!("Unsupported chain: {}", chain_id))
    }
}
