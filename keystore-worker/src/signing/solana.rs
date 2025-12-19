//! Ed25519 signing for Solana and NEAR chains.

use ed25519_dalek::{Signer, SigningKey};

/// Sign message with ed25519 key.
///
/// tx_params is expected to be base64-encoded message bytes.
/// Returns (public_key, signature) as base58-encoded strings.
pub fn sign_ed25519(
    signing_key_bytes: &[u8; 32],
    tx_params_b64: &str,
) -> Result<(String, String), String> {
    // Decode the transaction message from base64
    use base64::Engine;
    let message = base64::engine::general_purpose::STANDARD
        .decode(tx_params_b64)
        .map_err(|e| format!("Invalid base64 tx_params: {}", e))?;

    // Create signing key from bytes
    let signing_key = SigningKey::from_bytes(signing_key_bytes);

    // Get public key
    let public_key = signing_key.verifying_key();

    // Sign the message
    let signature = signing_key.sign(&message);

    // Encode as base58 (Solana convention)
    let public_key_b58 = bs58::encode(public_key.as_bytes()).into_string();
    let signature_b58 = bs58::encode(signature.to_bytes()).into_string();

    Ok((public_key_b58, signature_b58))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_sign_ed25519_roundtrip() {
        // Known test key
        let key_bytes = [0x42u8; 32];

        // Test message
        let message = b"Hello, Solana!";
        use base64::Engine;
        let message_b64 = base64::engine::general_purpose::STANDARD.encode(message);

        // Sign
        let (pubkey_b58, sig_b58) = sign_ed25519(&key_bytes, &message_b64).unwrap();

        // Verify signature
        let pubkey_bytes = bs58::decode(&pubkey_b58).into_vec().unwrap();
        let sig_bytes = bs58::decode(&sig_b58).into_vec().unwrap();

        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_sign_ed25519_deterministic() {
        let key_bytes = [0x42u8; 32];
        use base64::Engine;
        let message_b64 = base64::engine::general_purpose::STANDARD.encode(b"test");

        let (pk1, sig1) = sign_ed25519(&key_bytes, &message_b64).unwrap();
        let (pk2, sig2) = sign_ed25519(&key_bytes, &message_b64).unwrap();

        assert_eq!(pk1, pk2);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_public_key_format() {
        let key_bytes = [0x42u8; 32];
        use base64::Engine;
        let message_b64 = base64::engine::general_purpose::STANDARD.encode(b"test");

        let (pubkey_b58, _) = sign_ed25519(&key_bytes, &message_b64).unwrap();

        // Solana public keys are 32 bytes, which encode to 43-44 base58 chars
        assert!(pubkey_b58.len() >= 32 && pubkey_b58.len() <= 44);
    }
}
