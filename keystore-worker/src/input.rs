//! Input parsing for TEE worker.
//!
//! Parses the JSON input from stdin that the contract sends.
//! Supports two operations: "sign" (default) and "get_address".

use serde::Deserialize;

/// Operations the worker can perform.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Sign,
    GetAddress,
}

impl Default for Operation {
    fn default() -> Self {
        Operation::Sign
    }
}

/// Parsed worker input - either a sign request or get_address request.
#[derive(Debug)]
pub enum WorkerRequest {
    Sign(SignInput),
    GetAddress(GetAddressInput),
}

/// Input for signing operations.
#[derive(Debug, Deserialize)]
pub struct SignInput {
    pub run_id: u64,
    pub auth_id: u64,
    pub authorization: AuthorizationSnapshot,
    /// Base64-encoded transaction parameters
    pub tx_params: String,
}

/// Input for get_address operations.
#[derive(Debug, Deserialize)]
pub struct GetAddressInput {
    pub account_id: String,
    pub chain_id: String,
}

/// Raw input that can be either operation type.
#[derive(Debug, Deserialize)]
struct RawInput {
    #[serde(default)]
    operation: Operation,
    // Sign fields (optional)
    run_id: Option<u64>,
    auth_id: Option<u64>,
    authorization: Option<AuthorizationSnapshot>,
    tx_params: Option<String>,
    // GetAddress fields (optional)
    account_id: Option<String>,
    chain_id: Option<String>,
}

// Legacy: Keep WorkerInput as alias for backwards compatibility
pub type WorkerInput = SignInput;

/// Snapshot of authorization data from the contract.
#[derive(Debug, Deserialize)]
pub struct AuthorizationSnapshot {
    pub signer_id: String,
    pub public_key: String,
    /// JSON-encoded actions array
    pub actions: String,
    pub deadline: u64,
}

/// A keystore action (matches contract's KeystoreAction enum).
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum KeystoreAction {
    AuthorizeSigning {
        chain_id: String,
        #[serde(default)]
        key_ref: Option<String>,
        #[serde(default)]
        max_value: Option<String>,
        #[serde(default)]
        valid_until: Option<u64>,
    },
    RegisterKey {
        chain_id: String,
    },
    RevokeAuthorization {
        auth_id: u64,
    },
}

/// Parse input JSON from stdin into a WorkerRequest.
pub fn parse_request(input_str: &str) -> Result<WorkerRequest, String> {
    let raw: RawInput =
        serde_json::from_str(input_str).map_err(|e| format!("Invalid input JSON: {}", e))?;

    match raw.operation {
        Operation::Sign => {
            let run_id = raw.run_id.ok_or("Missing run_id for sign operation")?;
            let auth_id = raw.auth_id.ok_or("Missing auth_id for sign operation")?;
            let authorization = raw
                .authorization
                .ok_or("Missing authorization for sign operation")?;
            let tx_params = raw
                .tx_params
                .ok_or("Missing tx_params for sign operation")?;

            Ok(WorkerRequest::Sign(SignInput {
                run_id,
                auth_id,
                authorization,
                tx_params,
            }))
        }
        Operation::GetAddress => {
            let account_id = raw
                .account_id
                .ok_or("Missing account_id for get_address operation")?;
            let chain_id = raw
                .chain_id
                .ok_or("Missing chain_id for get_address operation")?;

            Ok(WorkerRequest::GetAddress(GetAddressInput {
                account_id,
                chain_id,
            }))
        }
    }
}

/// Parse input JSON from stdin (legacy, for sign operations only).
pub fn parse_input(input_str: &str) -> Result<WorkerInput, String> {
    serde_json::from_str(input_str).map_err(|e| format!("Invalid input JSON: {}", e))
}

/// Extract the first chain_id from authorization actions.
///
/// For v1, we only support single-chain authorizations.
pub fn extract_chain_id(input: &WorkerInput) -> Result<String, String> {
    let actions: Vec<KeystoreAction> = serde_json::from_str(&input.authorization.actions)
        .map_err(|e| format!("Invalid actions JSON: {}", e))?;

    for action in actions {
        match action {
            KeystoreAction::AuthorizeSigning { chain_id, .. } => {
                return Ok(chain_id);
            }
            KeystoreAction::RegisterKey { chain_id } => {
                return Ok(chain_id);
            }
            _ => continue,
        }
    }

    Err("No chain_id found in authorization actions".to_string())
}

/// Decode tx_params from base64.
pub fn decode_tx_params(tx_params: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(tx_params)
        .map_err(|e| format!("Invalid base64 tx_params: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_input() {
        let json = r#"{
            "run_id": 1,
            "auth_id": 42,
            "authorization": {
                "signer_id": "alice.near",
                "public_key": "ed25519:ABC123",
                "actions": "[{\"action\":\"authorize_signing\",\"chain_id\":\"solana:mainnet\"}]",
                "deadline": 1735000000
            },
            "tx_params": "SGVsbG8gV29ybGQ="
        }"#;

        let input = parse_input(json).unwrap();
        assert_eq!(input.run_id, 1);
        assert_eq!(input.auth_id, 42);
        assert_eq!(input.authorization.signer_id, "alice.near");
    }

    #[test]
    fn test_parse_request_sign_default() {
        // Without explicit operation field, defaults to sign
        let json = r#"{
            "run_id": 1,
            "auth_id": 42,
            "authorization": {
                "signer_id": "alice.near",
                "public_key": "ed25519:ABC123",
                "actions": "[{\"action\":\"authorize_signing\",\"chain_id\":\"solana:mainnet\"}]",
                "deadline": 1735000000
            },
            "tx_params": "SGVsbG8gV29ybGQ="
        }"#;

        let request = parse_request(json).unwrap();
        match request {
            WorkerRequest::Sign(input) => {
                assert_eq!(input.run_id, 1);
                assert_eq!(input.auth_id, 42);
            }
            _ => panic!("Expected Sign request"),
        }
    }

    #[test]
    fn test_parse_request_get_address() {
        let json = r#"{
            "operation": "get_address",
            "account_id": "alice.near",
            "chain_id": "solana:mainnet"
        }"#;

        let request = parse_request(json).unwrap();
        match request {
            WorkerRequest::GetAddress(input) => {
                assert_eq!(input.account_id, "alice.near");
                assert_eq!(input.chain_id, "solana:mainnet");
            }
            _ => panic!("Expected GetAddress request"),
        }
    }

    #[test]
    fn test_parse_request_explicit_sign() {
        let json = r#"{
            "operation": "sign",
            "run_id": 1,
            "auth_id": 42,
            "authorization": {
                "signer_id": "alice.near",
                "public_key": "ed25519:ABC123",
                "actions": "[]",
                "deadline": 1735000000
            },
            "tx_params": "dGVzdA=="
        }"#;

        let request = parse_request(json).unwrap();
        match request {
            WorkerRequest::Sign(input) => {
                assert_eq!(input.run_id, 1);
            }
            _ => panic!("Expected Sign request"),
        }
    }

    #[test]
    fn test_extract_chain_id() {
        let input = WorkerInput {
            run_id: 1,
            auth_id: 42,
            authorization: AuthorizationSnapshot {
                signer_id: "alice.near".to_string(),
                public_key: "ed25519:ABC".to_string(),
                actions: r#"[{"action":"authorize_signing","chain_id":"solana:mainnet"}]"#
                    .to_string(),
                deadline: 1735000000,
            },
            tx_params: "".to_string(),
        };

        let chain_id = extract_chain_id(&input).unwrap();
        assert_eq!(chain_id, "solana:mainnet");
    }
}
