//! Self-describing encoder with tail metadata.
//!
//! Appends a metadata byte before encoding, such that the tail residues
//! reveal the encoding parameters.


/// Sign of the encoded value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sign {
    Positive,
    Negative,
}

/// Metadata packed into a single byte
#[derive(Debug, Clone, Copy)]
pub struct Metadata {
    /// Sign bit (0 = positive, 1 = negative)
    pub sign: Sign,
    /// Base identifier (0 = B58, 1 = B64, 2 = B32)
    pub base_id: u8,
    /// Checksum (payload mod 31)
    pub checksum: u8,
}

impl Metadata {
    /// Pack metadata into a single byte.
    ///
    /// Format:
    /// - bits 0-4: checksum (mod 31, gives 5 bits)
    /// - bit 5: sign (0 = positive, 1 = negative)
    /// - bits 6-7: base_id (0 = B58, 1 = B64, 2 = B32)
    pub fn pack(&self) -> u8 {
        let sign_bit = if self.sign == Sign::Negative { 1 } else { 0 };
        (self.checksum & 0x1F) | (sign_bit << 5) | ((self.base_id & 0x03) << 6)
    }

    /// Unpack metadata from a byte.
    pub fn unpack(byte: u8) -> Self {
        let checksum = byte & 0x1F;
        let sign = if (byte >> 5) & 1 == 1 {
            Sign::Negative
        } else {
            Sign::Positive
        };
        let base_id = (byte >> 6) & 0x03;
        Self { sign, base_id, checksum }
    }
}

/// Compute checksum of payload (sum of bytes mod 31)
fn payload_checksum(payload: &[u8]) -> u8 {
    let sum: u32 = payload.iter().map(|&b| b as u32).sum();
    (sum % 31) as u8
}

/// Encode bytes as Base58 with self-describing metadata.
///
/// Appends a metadata byte encoding sign + base_id + checksum,
/// then encodes the result as Base58.
pub fn encode_base58(payload: &[u8], sign: Sign) -> String {
    let checksum = payload_checksum(payload);
    let metadata = Metadata {
        sign,
        base_id: 0, // Base58
        checksum,
    };

    // Append metadata byte to payload
    let mut data = payload.to_vec();
    data.push(metadata.pack());

    bs58::encode(&data).into_string()
}

/// Encode bytes as Base64 with self-describing metadata.
pub fn encode_base64(payload: &[u8], sign: Sign) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let checksum = payload_checksum(payload);
    let metadata = Metadata {
        sign,
        base_id: 1, // Base64
        checksum,
    };

    let mut data = payload.to_vec();
    data.push(metadata.pack());

    STANDARD.encode(&data)
}

/// Encode bytes as Base32 with self-describing metadata.
pub fn encode_base32(payload: &[u8], sign: Sign) -> String {
    let checksum = payload_checksum(payload);
    let metadata = Metadata {
        sign,
        base_id: 2, // Base32
        checksum,
    };

    let mut data = payload.to_vec();
    data.push(metadata.pack());

    data_encoding::BASE32.encode(&data)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_pack_unpack() {
        let meta = Metadata {
            sign: Sign::Negative,
            base_id: 2,
            checksum: 17,
        };

        let packed = meta.pack();
        let unpacked = Metadata::unpack(packed);

        assert_eq!(unpacked.sign, Sign::Negative);
        assert_eq!(unpacked.base_id, 2);
        assert_eq!(unpacked.checksum, 17);
    }

    #[test]
    fn test_encode_base58() {
        let payload = b"hello";
        let encoded = encode_base58(payload, Sign::Positive);

        // Should be valid Base58
        assert!(bs58::decode(&encoded).into_vec().is_ok());

        // Decode and check metadata
        let decoded = bs58::decode(&encoded).into_vec().unwrap();
        let meta_byte = decoded[decoded.len() - 1];
        let meta = Metadata::unpack(meta_byte);

        assert_eq!(meta.sign, Sign::Positive);
        assert_eq!(meta.base_id, 0); // Base58
    }

    #[test]
    fn test_encode_base64() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let payload = b"hello";
        let encoded = encode_base64(payload, Sign::Negative);

        // Should be valid Base64
        let decoded = STANDARD.decode(&encoded).unwrap();
        let meta_byte = decoded[decoded.len() - 1];
        let meta = Metadata::unpack(meta_byte);

        assert_eq!(meta.sign, Sign::Negative);
        assert_eq!(meta.base_id, 1); // Base64
    }

    #[test]
    fn test_encode_base32() {
        let payload = b"hello";
        let encoded = encode_base32(payload, Sign::Positive);

        // Should be valid Base32
        let decoded = data_encoding::BASE32.decode(encoded.as_bytes()).unwrap();
        let meta_byte = decoded[decoded.len() - 1];
        let meta = Metadata::unpack(meta_byte);

        assert_eq!(meta.sign, Sign::Positive);
        assert_eq!(meta.base_id, 2); // Base32
    }
}
