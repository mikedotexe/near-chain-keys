//! Authorization module for TEE keystore intents.
//!
//! Uses NEAR Intents MultiPayload for multi-wallet signature verification,
//! supporting 7 signature types: NEP-413, ERC-191, TIP-191, Raw Ed25519,
//! WebAuthn, TonConnect, and SEP-53.

use defuse_core::{
    crypto::{PublicKey, SignedPayload},
    payload::{multi::MultiPayload, DefusePayload, ExtractDefusePayload},
    Deadline,
};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{near, AccountId};

// ============================================================================
// KEYSTORE ACTIONS - What the user authorizes
// ============================================================================

/// Actions that can be authorized via an intent.
///
/// Supports batching: multiple actions in a single signed envelope.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum KeystoreAction {
    /// Authorize a TEE to sign transactions on a specific chain.
    ///
    /// Can batch multiple AuthorizeSigning actions for different chains
    /// in a single intent.
    AuthorizeSigning {
        /// CAIP-2 chain identifier (e.g., "eip155:1", "bip122:...")
        chain_id: String,
        /// Optional key reference (derivation path or binding ID)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_ref: Option<String>,
        /// Optional maximum value per transaction (chain-specific format)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_value: Option<String>,
        /// Optional validity deadline for this authorization
        #[serde(default, skip_serializing_if = "Option::is_none")]
        valid_until: Option<Deadline>,
    },

    /// Register a TEE-derived key for a specific chain.
    RegisterKey {
        /// CAIP-2 chain identifier
        chain_id: String,
    },

    /// Revoke an existing authorization.
    ///
    /// The signature commits to the specific auth_id being revoked,
    /// preventing griefing attacks where a malicious actor could
    /// redirect a revocation to a different authorization.
    RevokeAuthorization {
        /// The authorization ID to revoke
        auth_id: AuthorizationId,
    },
}

/// The message content within an intent envelope.
/// This is what gets serialized inside DefusePayload.message.
#[near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct KeystoreIntentMessage {
    /// List of actions to authorize
    pub actions: Vec<KeystoreAction>,
}

// ============================================================================
// AUTHORIZATION STATE
// ============================================================================

/// Unique identifier for an authorization.
pub type AuthorizationId = u64;

/// State of an authorization.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum AuthorizationStatus {
    /// Authorization is active and can be consumed
    Active,
    /// Authorization has been consumed (used)
    Consumed { consumed_at: u64 },
    /// Authorization has been revoked
    Revoked { revoked_at: u64 },
    /// Authorization has expired
    Expired,
}

/// A stored authorization record.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct Authorization {
    /// Unique ID
    pub id: AuthorizationId,
    /// The signer who authorized this
    pub signer_id: String,
    /// Recovered public key from signature verification
    pub public_key: String,
    /// When this was created (block height)
    pub created_at: u64,
    /// Deadline for this authorization
    pub deadline: u64,
    /// The authorized actions (stored as JSON for flexibility)
    pub actions_json: String,
    /// Current status
    pub status: AuthorizationStatus,
}

// ============================================================================
// VERIFICATION FUNCTIONS
// ============================================================================

/// Result of verifying a MultiPayload.
pub struct VerifiedIntent {
    /// The recovered public key
    pub public_key: PublicKey,
    /// The extracted payload with signer, contract, deadline, nonce
    pub payload: DefusePayload<KeystoreIntentMessage>,
}

/// Verify a MultiPayload and extract the DefusePayload.
///
/// This uses the NEAR Intents signature verification which supports
/// 7 different wallet/signature types.
pub fn verify_intent(
    multi_payload: MultiPayload,
    expected_contract: &AccountId,
) -> Result<VerifiedIntent, IntentError> {
    // 1. Verify signature and recover public key
    let public_key = multi_payload
        .verify()
        .ok_or(IntentError::InvalidSignature)?;

    // 2. Extract the DefusePayload
    let payload: DefusePayload<KeystoreIntentMessage> = multi_payload
        .extract_defuse_payload()
        .map_err(|e| IntentError::InvalidPayload(e.to_string()))?;

    // 3. Verify the verifying_contract matches
    if &payload.verifying_contract != expected_contract {
        return Err(IntentError::WrongContract {
            expected: expected_contract.clone(),
            got: payload.verifying_contract.clone(),
        });
    }

    // 4. Check deadline hasn't passed
    if payload.deadline.has_expired() {
        return Err(IntentError::DeadlinePassed);
    }

    Ok(VerifiedIntent { public_key, payload })
}

// ============================================================================
// ERRORS
// ============================================================================

/// Errors that can occur during intent processing.
#[derive(Debug)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum IntentError {
    /// Signature verification failed
    InvalidSignature,
    /// Payload deserialization failed
    InvalidPayload(String),
    /// Intent was signed for wrong contract
    WrongContract { expected: AccountId, got: AccountId },
    /// Deadline has passed
    DeadlinePassed,
    /// Nonce has already been used
    NonceReused,
    /// Authorization not found
    NotFound,
    /// Authorization has expired
    Expired,
    /// Authorization has already been consumed
    AlreadyConsumed,
    /// Authorization has been revoked
    Revoked,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::InvalidSignature => write!(f, "Signature verification failed"),
            IntentError::InvalidPayload(e) => write!(f, "Invalid payload: {}", e),
            IntentError::WrongContract { expected, got } => {
                write!(f, "Wrong contract: expected {}, got {}", expected, got)
            }
            IntentError::DeadlinePassed => write!(f, "Intent deadline has passed"),
            IntentError::NonceReused => write!(f, "Nonce has already been used"),
            IntentError::NotFound => write!(f, "Authorization not found"),
            IntentError::Expired => write!(f, "Authorization has expired"),
            IntentError::AlreadyConsumed => write!(f, "Authorization already consumed"),
            IntentError::Revoked => write!(f, "Authorization has been revoked"),
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Convert a public key to a string representation.
/// PublicKey already implements Display with the format "curve:base58data"
pub fn public_key_to_string(pk: &PublicKey) -> String {
    pk.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::serde_json;

    #[test]
    fn test_authorize_signing_serialize() {
        let action = KeystoreAction::AuthorizeSigning {
            chain_id: "eip155:1".to_string(),
            key_ref: None,
            max_value: Some("1000000".to_string()),
            valid_until: None,
        };

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("authorize_signing"));
        assert!(json.contains("eip155:1"));
    }

    #[test]
    fn test_register_key_deserialize() {
        let json = r#"{"action":"register_key","chain_id":"solana:mainnet"}"#;
        let action: KeystoreAction = serde_json::from_str(json).unwrap();

        match action {
            KeystoreAction::RegisterKey { chain_id } => {
                assert_eq!(chain_id, "solana:mainnet");
            }
            _ => panic!("Expected RegisterKey"),
        }
    }

    #[test]
    fn test_revoke_authorization_serialize() {
        let action = KeystoreAction::RevokeAuthorization { auth_id: 42 };

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("revoke_authorization"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_revoke_authorization_deserialize() {
        let json = r#"{"action":"revoke_authorization","auth_id":123}"#;
        let action: KeystoreAction = serde_json::from_str(json).unwrap();

        match action {
            KeystoreAction::RevokeAuthorization { auth_id } => {
                assert_eq!(auth_id, 123);
            }
            _ => panic!("Expected RevokeAuthorization"),
        }
    }

    #[test]
    fn test_batched_actions_serialize() {
        let actions = vec![
            KeystoreAction::AuthorizeSigning {
                chain_id: "eip155:1".to_string(),
                key_ref: None,
                max_value: None,
                valid_until: None,
            },
            KeystoreAction::AuthorizeSigning {
                chain_id: "eip155:42161".to_string(), // Arbitrum
                key_ref: None,
                max_value: Some("1000000000000000000".to_string()), // 1 ETH
                valid_until: None,
            },
        ];

        let json = serde_json::to_string(&actions).unwrap();
        assert!(json.contains("eip155:1"));
        assert!(json.contains("eip155:42161"));
    }
}
