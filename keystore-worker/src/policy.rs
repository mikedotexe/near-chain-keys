//! Policy validation for TEE worker.
//!
//! Validates that the transaction request matches the authorization constraints.

use crate::input::SignInput;

/// Validate that the request conforms to the authorization policy.
pub fn validate(input: &SignInput, chain_id: &str) -> Result<(), String> {
    // 1. Validate chain_id format (CAIP-2)
    validate_chain_id(chain_id)?;

    // 2. Check deadline hasn't passed
    // Note: In WASI, we don't have access to system time in a reliable way.
    // The contract already validated the deadline before calling OutLayer.
    // We trust the contract's deadline check.
    let _ = input.authorization.deadline;

    // 3. Future: Validate max_value against tx_params
    // This requires parsing tx_params which is chain-specific.
    // For v1, we just trust the authorization.

    Ok(())
}

/// Validate CAIP-2 chain identifier format.
pub fn validate_chain_id(chain_id: &str) -> Result<(), String> {
    // CAIP-2: namespace:reference
    // namespace: [-a-z0-9]{3,8}
    // reference: [-_a-zA-Z0-9]{1,32}

    let parts: Vec<&str> = chain_id.split(':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid CAIP-2 chain_id '{}': expected namespace:reference",
            chain_id
        ));
    }

    let namespace = parts[0];
    let reference = parts[1];

    // Validate namespace
    if namespace.len() < 3 || namespace.len() > 8 {
        return Err(format!(
            "Invalid CAIP-2 namespace '{}': must be 3-8 chars",
            namespace
        ));
    }

    // Validate reference
    if reference.is_empty() || reference.len() > 32 {
        return Err(format!(
            "Invalid CAIP-2 reference '{}': must be 1-32 chars",
            reference
        ));
    }

    Ok(())
}

/// Check if a chain uses ed25519 (Solana, NEAR).
pub fn is_ed25519_chain(chain_id: &str) -> bool {
    chain_id.starts_with("solana:") || chain_id.starts_with("near:")
}

/// Check if a chain uses secp256k1 (EVM, Bitcoin).
#[allow(dead_code)]
pub fn is_secp256k1_chain(chain_id: &str) -> bool {
    chain_id.starts_with("eip155:") || chain_id.starts_with("bip122:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_chain_id_valid() {
        assert!(validate_chain_id("solana:mainnet").is_ok());
        assert!(validate_chain_id("eip155:1").is_ok());
        assert!(validate_chain_id("near:mainnet").is_ok());
        assert!(validate_chain_id("bip122:000000000019d6689c085ae165831e93").is_ok());
    }

    #[test]
    fn test_validate_chain_id_invalid() {
        assert!(validate_chain_id("invalid").is_err());
        assert!(validate_chain_id("ab:ref").is_err()); // namespace too short
        assert!(validate_chain_id(":reference").is_err());
        assert!(validate_chain_id("namespace:").is_err());
    }

    #[test]
    fn test_is_ed25519_chain() {
        assert!(is_ed25519_chain("solana:mainnet"));
        assert!(is_ed25519_chain("solana:devnet"));
        assert!(is_ed25519_chain("near:mainnet"));
        assert!(!is_ed25519_chain("eip155:1"));
        assert!(!is_ed25519_chain("bip122:000000"));
    }
}
