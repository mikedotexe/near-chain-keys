//! Output formatting for TEE worker.
//!
//! Formats JSON responses for stdout (max 900 bytes for NEAR).

use serde::Serialize;

/// Success response for signing operations.
#[derive(Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub run_id: u64,
    pub auth_id: u64,
    pub chain_id: String,
    pub public_key: String,
    pub signature: String,
}

/// Error response.
#[derive(Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub run_id: u64,
    pub auth_id: u64,
    pub error: String,
}

/// Address response for get_address operations.
#[derive(Serialize)]
pub struct AddressResponse {
    pub success: bool,
    pub operation: String,
    pub account_id: String,
    pub chain_id: String,
    pub public_key: String,
    pub address: String,
}

/// Format a success response as JSON.
pub fn success_response(
    run_id: u64,
    auth_id: u64,
    chain_id: &str,
    public_key: &str,
    signature: &str,
) -> String {
    let response = SuccessResponse {
        success: true,
        run_id,
        auth_id,
        chain_id: chain_id.to_string(),
        public_key: public_key.to_string(),
        signature: signature.to_string(),
    };

    // Compact JSON to stay under 900 byte limit
    serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(
            r#"{{"success":true,"run_id":{},"auth_id":{},"chain_id":"{}","public_key":"{}","signature":"{}"}}"#,
            run_id, auth_id, chain_id, public_key, signature
        )
    })
}

/// Format an address response as JSON.
pub fn address_response(
    account_id: &str,
    chain_id: &str,
    public_key: &str,
    address: &str,
) -> String {
    let response = AddressResponse {
        success: true,
        operation: "get_address".to_string(),
        account_id: account_id.to_string(),
        chain_id: chain_id.to_string(),
        public_key: public_key.to_string(),
        address: address.to_string(),
    };

    serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(
            r#"{{"success":true,"operation":"get_address","account_id":"{}","chain_id":"{}","public_key":"{}","address":"{}"}}"#,
            account_id, chain_id, public_key, address
        )
    })
}

/// Format an error response as JSON.
pub fn error_response(run_id: u64, auth_id: u64, error: &str) -> String {
    let response = ErrorResponse {
        success: false,
        run_id,
        auth_id,
        error: error.to_string(),
    };

    serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(
            r#"{{"success":false,"run_id":{},"auth_id":{},"error":"{}"}}"#,
            run_id, auth_id, error.replace('"', "'")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_response() {
        let json = success_response(1, 42, "solana:mainnet", "ABC123", "SIG456");
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"run_id\":1"));
        assert!(json.contains("\"chain_id\":\"solana:mainnet\""));
    }

    #[test]
    fn test_error_response() {
        let json = error_response(1, 42, "Something went wrong");
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("\"error\":\"Something went wrong\""));
    }

    #[test]
    fn test_response_under_900_bytes() {
        // Typical response should be well under 900 bytes
        let json = success_response(
            999999,
            999999,
            "solana:mainnet",
            "7C4jsPZpht5XuJDCf3y6T42LPd1WALhPqj5JTLg6P5Gk", // ~43 chars
            "5TuPCJJmMnXBenwCHmXxN3PgxYrF2kzLoLR8Eo7sCZdkMqRq8FPZvzPxYrKyBqYNJpWJfDHXsT9yVwTnVnRnTxCu", // ~87 chars
        );
        assert!(json.len() < 900, "Response too long: {} bytes", json.len());
    }

    #[test]
    fn test_address_response() {
        let json = address_response(
            "alice.near",
            "solana:mainnet",
            "JCeogNwjUmBneNdJjrewebgaEwRNSFib5Hz7diDcZ1TJ",
            "JCeogNwjUmBneNdJjrewebgaEwRNSFib5Hz7diDcZ1TJ",
        );
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"operation\":\"get_address\""));
        assert!(json.contains("\"account_id\":\"alice.near\""));
        assert!(json.contains("\"chain_id\":\"solana:mainnet\""));
    }
}
