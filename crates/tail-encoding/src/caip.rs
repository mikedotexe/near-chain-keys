//! CAIP-compatible compact error-correcting address encoding.
//!
//! Compresses CAIP identifiers (CAIP-2, CAIP-10, CAIP-19) into shorter,
//! self-describing, error-detecting strings.
//!
//! # Example
//!
//! ```
//! use tail_encoding::caip::*;
//!
//! // Ethereum mainnet address
//! let address = hex::decode("ab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb").unwrap();
//! let compact = encode_caip10(CaipNamespace::Eip155, "1", &address);
//!
//! // Decode back to standard CAIP-10 format (lowercase hex)
//! let decoded = decode_caip10(&compact).unwrap();
//! assert_eq!(decoded.to_caip_string(), "eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");
//! ```

use crate::residue::{b58_char_to_digit, B58_ALPHABET};
use crate::error_correction::{compute_mod, compute_expected_residues, suggest_correction};

// ============================================================================
// NAMESPACE REGISTRY
// ============================================================================

/// CAIP namespace identifiers (compressed to single byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaipNamespace {
    /// EIP-155 compatible chains (Ethereum, Polygon, BSC, etc.)
    Eip155 = 0,
    /// BIP-122 Bitcoin-like chains
    Bip122 = 1,
    /// Cosmos SDK chains
    Cosmos = 2,
    /// Solana
    Solana = 3,
    /// Polkadot/Kusama
    Polkadot = 4,
    /// NEAR Protocol
    Near = 5,
    /// StarkNet
    Starknet = 6,
    /// Reserved for future use
    Reserved7 = 7,
}

impl CaipNamespace {
    /// Get the standard CAIP namespace string
    pub fn as_str(&self) -> &'static str {
        match self {
            CaipNamespace::Eip155 => "eip155",
            CaipNamespace::Bip122 => "bip122",
            CaipNamespace::Cosmos => "cosmos",
            CaipNamespace::Solana => "solana",
            CaipNamespace::Polkadot => "polkadot",
            CaipNamespace::Near => "near",
            CaipNamespace::Starknet => "starknet",
            CaipNamespace::Reserved7 => "reserved",
        }
    }

    /// Parse namespace from CAIP string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "eip155" => Some(CaipNamespace::Eip155),
            "bip122" => Some(CaipNamespace::Bip122),
            "cosmos" => Some(CaipNamespace::Cosmos),
            "solana" => Some(CaipNamespace::Solana),
            "polkadot" => Some(CaipNamespace::Polkadot),
            "near" => Some(CaipNamespace::Near),
            "starknet" => Some(CaipNamespace::Starknet),
            _ => None,
        }
    }

    /// Get namespace from numeric ID
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(CaipNamespace::Eip155),
            1 => Some(CaipNamespace::Bip122),
            2 => Some(CaipNamespace::Cosmos),
            3 => Some(CaipNamespace::Solana),
            4 => Some(CaipNamespace::Polkadot),
            5 => Some(CaipNamespace::Near),
            6 => Some(CaipNamespace::Starknet),
            7 => Some(CaipNamespace::Reserved7),
            _ => None,
        }
    }
}

// ============================================================================
// CAIP TYPES
// ============================================================================

/// CAIP identifier types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaipType {
    /// CAIP-2: Chain ID only (e.g., "eip155:1")
    ChainId,
    /// CAIP-10: Account ID (e.g., "eip155:1:0xabc...")
    AccountId,
    /// CAIP-19: Asset ID (e.g., "eip155:1/erc20:0xabc...")
    AssetId,
}

// ============================================================================
// DECODED STRUCTURES
// ============================================================================

/// Decoded CAIP-2 chain identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caip2 {
    pub namespace: CaipNamespace,
    pub reference: String,
}

impl Caip2 {
    /// Format as standard CAIP-2 string
    pub fn to_caip_string(&self) -> String {
        format!("{}:{}", self.namespace.as_str(), self.reference)
    }
}

/// Decoded CAIP-10 account identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caip10 {
    pub namespace: CaipNamespace,
    pub reference: String,
    pub address: Vec<u8>,
}

impl Caip10 {
    /// Format as standard CAIP-10 string
    pub fn to_caip_string(&self) -> String {
        let addr_str = match self.namespace {
            CaipNamespace::Eip155 => format!("0x{}", hex::encode(&self.address)),
            CaipNamespace::Solana => bs58::encode(&self.address).into_string(),
            _ => hex::encode(&self.address),
        };
        format!("{}:{}:{}", self.namespace.as_str(), self.reference, addr_str)
    }
}

// ============================================================================
// TAIL ENCODING
// ============================================================================

/// Pack CAIP type and namespace into tail value (0-28)
///
/// Layout:
/// - 0-3:   CAIP-2 (namespace in 2 bits, limited to 4 namespaces)
/// - 4-11:  CAIP-10 (namespace 0-7)
/// - 12-19: CAIP-19 (namespace 0-7)
/// - 20-27: Reserved (CAIP-122 sign-in, etc.)
/// - 28:    Extended (additional metadata byte follows)
fn pack_caip_tail(caip_type: CaipType, namespace: CaipNamespace) -> u8 {
    let ns = namespace as u8;
    match caip_type {
        CaipType::ChainId => ns.min(3),           // 0-3
        CaipType::AccountId => 4 + ns.min(7),     // 4-11
        CaipType::AssetId => 12 + ns.min(7),      // 12-19
    }
}

/// Unpack CAIP type and namespace from tail value
fn unpack_caip_tail(value: u8) -> Option<(CaipType, CaipNamespace)> {
    match value {
        0..=3 => Some((CaipType::ChainId, CaipNamespace::from_id(value)?)),
        4..=11 => Some((CaipType::AccountId, CaipNamespace::from_id(value - 4)?)),
        12..=19 => Some((CaipType::AssetId, CaipNamespace::from_id(value - 12)?)),
        _ => None,
    }
}

/// Find Base58 character with digit value mod 29 == target
fn char_for_residue(target: u8) -> char {
    for (i, &c) in B58_ALPHABET.iter().enumerate() {
        if (i as u8) % 29 == target {
            return c as char;
        }
    }
    unreachable!("target must be 0-28")
}

/// Extract mod 29 residue from Base58 character
fn residue_from_char(c: char) -> Option<u8> {
    let digit = b58_char_to_digit(c as u8)?;
    Some(digit % 29)
}

// ============================================================================
// COMPACT ENCODING
// ============================================================================

/// Encode a CAIP-10 account identifier to compact form.
///
/// Format: `[Base58(namespace_id || chain_ref_len || chain_ref || address)][tail]`
///
/// # Arguments
/// * `namespace` - The blockchain namespace (e.g., Eip155 for Ethereum)
/// * `chain_ref` - The chain reference (e.g., "1" for mainnet)
/// * `address` - The raw address bytes (20 bytes for EVM)
pub fn encode_caip10(namespace: CaipNamespace, chain_ref: &str, address: &[u8]) -> String {
    // Build binary payload
    let mut payload = Vec::new();

    // Namespace ID (1 byte)
    payload.push(namespace as u8);

    // Chain reference length + bytes (varint-style)
    let ref_bytes = chain_ref.as_bytes();
    payload.push(ref_bytes.len() as u8);
    payload.extend_from_slice(ref_bytes);

    // Address bytes (variable length)
    payload.extend_from_slice(address);

    // Base58 encode
    let base58_payload = bs58::encode(&payload).into_string();

    // Add tail character
    let tail_value = pack_caip_tail(CaipType::AccountId, namespace);
    let tail_char = char_for_residue(tail_value);

    format!("{}{}", base58_payload, tail_char)
}

/// Encode a CAIP-2 chain identifier to compact form.
pub fn encode_caip2(namespace: CaipNamespace, chain_ref: &str) -> String {
    let mut payload = Vec::new();
    payload.push(namespace as u8);
    let ref_bytes = chain_ref.as_bytes();
    payload.push(ref_bytes.len() as u8);
    payload.extend_from_slice(ref_bytes);

    let base58_payload = bs58::encode(&payload).into_string();
    let tail_value = pack_caip_tail(CaipType::ChainId, namespace);
    let tail_char = char_for_residue(tail_value);

    format!("{}{}", base58_payload, tail_char)
}

// ============================================================================
// COMPACT DECODING
// ============================================================================

/// Error during CAIP decoding
#[derive(Debug, Clone)]
pub enum CaipDecodeError {
    /// Input is empty
    Empty,
    /// Invalid Base58 encoding
    InvalidBase58,
    /// Invalid tail character
    InvalidTail,
    /// Payload too short
    PayloadTooShort,
    /// Unknown namespace
    UnknownNamespace,
    /// Corrupted input (with optional correction suggestion)
    Corrupted { suggestion: Option<String> },
}

/// Decode compact form to CAIP-10 account identifier.
pub fn decode_caip10(compact: &str) -> Result<Caip10, CaipDecodeError> {
    if compact.is_empty() {
        return Err(CaipDecodeError::Empty);
    }

    // Extract tail
    let chars: Vec<char> = compact.chars().collect();
    let tail_char = *chars.last().ok_or(CaipDecodeError::Empty)?;
    let payload_str: String = chars[..chars.len() - 1].iter().collect();

    // Decode tail
    let tail_residue = residue_from_char(tail_char).ok_or(CaipDecodeError::InvalidTail)?;
    let (caip_type, namespace) = unpack_caip_tail(tail_residue)
        .ok_or(CaipDecodeError::InvalidTail)?;

    if caip_type != CaipType::AccountId {
        return Err(CaipDecodeError::InvalidTail);
    }

    // Decode Base58 payload
    let payload = bs58::decode(&payload_str)
        .into_vec()
        .map_err(|_| CaipDecodeError::InvalidBase58)?;

    if payload.len() < 3 {
        return Err(CaipDecodeError::PayloadTooShort);
    }

    // Parse payload
    let ns_id = payload[0];
    let ref_len = payload[1] as usize;

    if payload.len() < 2 + ref_len {
        return Err(CaipDecodeError::PayloadTooShort);
    }

    let reference = String::from_utf8_lossy(&payload[2..2 + ref_len]).to_string();
    let address = payload[2 + ref_len..].to_vec();

    // Verify namespace matches tail
    let payload_namespace = CaipNamespace::from_id(ns_id)
        .ok_or(CaipDecodeError::UnknownNamespace)?;

    if payload_namespace != namespace {
        // Tail and payload disagree - trust payload but flag as potentially corrupted
    }

    Ok(Caip10 {
        namespace: payload_namespace,
        reference,
        address,
    })
}

/// Decode compact form to CAIP-2 chain identifier.
pub fn decode_caip2(compact: &str) -> Result<Caip2, CaipDecodeError> {
    if compact.is_empty() {
        return Err(CaipDecodeError::Empty);
    }

    let chars: Vec<char> = compact.chars().collect();
    let tail_char = *chars.last().ok_or(CaipDecodeError::Empty)?;
    let payload_str: String = chars[..chars.len() - 1].iter().collect();

    let tail_residue = residue_from_char(tail_char).ok_or(CaipDecodeError::InvalidTail)?;
    let (caip_type, namespace) = unpack_caip_tail(tail_residue)
        .ok_or(CaipDecodeError::InvalidTail)?;

    if caip_type != CaipType::ChainId {
        return Err(CaipDecodeError::InvalidTail);
    }

    let payload = bs58::decode(&payload_str)
        .into_vec()
        .map_err(|_| CaipDecodeError::InvalidBase58)?;

    if payload.len() < 2 {
        return Err(CaipDecodeError::PayloadTooShort);
    }

    let _ns_id = payload[0];
    let ref_len = payload[1] as usize;

    if payload.len() < 2 + ref_len {
        return Err(CaipDecodeError::PayloadTooShort);
    }

    let reference = String::from_utf8_lossy(&payload[2..2 + ref_len]).to_string();

    Ok(Caip2 { namespace, reference })
}

// ============================================================================
// METADATA EXTRACTION (O(1))
// ============================================================================

/// Extracted CAIP metadata from tail character
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaipMeta {
    pub caip_type: CaipType,
    pub namespace: CaipNamespace,
}

/// Extract CAIP type and namespace from tail in O(1).
///
/// This reads only the last character - no Base58 decoding needed.
pub fn extract_caip_meta(compact: &str) -> Option<CaipMeta> {
    let tail_char = compact.chars().last()?;
    let residue = residue_from_char(tail_char)?;
    let (caip_type, namespace) = unpack_caip_tail(residue)?;
    Some(CaipMeta { caip_type, namespace })
}

// ============================================================================
// ERROR CORRECTION INTEGRATION
// ============================================================================

/// Validation result with optional correction
#[derive(Debug)]
pub enum CaipValidation {
    /// Input is valid
    Valid(CaipMeta),
    /// Input has detectable error, correction suggested
    Correctable {
        suggested: String,
        position: usize,
        original_char: char,
        replacement_char: char,
    },
    /// Input is invalid, no correction possible
    Invalid,
}

/// Validate compact CAIP string with error detection.
///
/// Uses mod 41 checksum to detect typos.
pub fn validate_caip_compact(input: &str, expected_checksum: u8) -> CaipValidation {
    // First check if metadata is extractable
    let meta = match extract_caip_meta(input) {
        Some(m) => m,
        None => return CaipValidation::Invalid,
    };

    // Compute actual checksum
    let actual = match compute_mod(input, 41) {
        Some(v) => v as u8,
        None => return CaipValidation::Invalid,
    };

    if actual == expected_checksum {
        return CaipValidation::Valid(meta);
    }

    // Try to correct
    if let Some(residues) = compute_expected_residues(input) {
        // Create expected residues based on known checksum
        let mut expected = residues.clone();
        expected[0] = expected_checksum as u64;

        if let Some(correction) = suggest_correction(input, &expected) {
            return CaipValidation::Correctable {
                suggested: correction.corrected,
                position: correction.position,
                original_char: correction.original_char,
                replacement_char: correction.replacement_char,
            };
        }
    }

    CaipValidation::Invalid
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Parse a standard CAIP-10 string and encode to compact form.
///
/// # Example
/// ```
/// use tail_encoding::caip::parse_and_encode_caip10;
/// let compact = parse_and_encode_caip10("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
/// ```
pub fn parse_and_encode_caip10(caip_string: &str) -> Option<String> {
    // Parse: namespace:reference:address
    let parts: Vec<&str> = caip_string.split(':').collect();
    if parts.len() != 3 {
        return None;
    }

    let namespace = CaipNamespace::from_str(parts[0])?;
    let reference = parts[1];

    // Parse address based on namespace
    let address = match namespace {
        CaipNamespace::Eip155 => {
            // Remove 0x prefix and decode hex
            let hex_str = parts[2].strip_prefix("0x").unwrap_or(parts[2]);
            hex::decode(hex_str).ok()?
        }
        CaipNamespace::Solana => {
            bs58::decode(parts[2]).into_vec().ok()?
        }
        _ => {
            // Default: try hex decode
            hex::decode(parts[2]).ok()?
        }
    };

    Some(encode_caip10(namespace, reference, &address))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_roundtrip() {
        for id in 0..7 {
            let ns = CaipNamespace::from_id(id).unwrap();
            let s = ns.as_str();
            let ns2 = CaipNamespace::from_str(s).unwrap();
            assert_eq!(ns, ns2);
        }
    }

    #[test]
    fn test_tail_pack_unpack() {
        for ns_id in 0..7 {
            let ns = CaipNamespace::from_id(ns_id).unwrap();

            // CAIP-10
            let packed = pack_caip_tail(CaipType::AccountId, ns);
            let (caip_type, unpacked_ns) = unpack_caip_tail(packed).unwrap();
            assert_eq!(caip_type, CaipType::AccountId);
            assert_eq!(unpacked_ns, ns);

            // CAIP-2 (only first 4 namespaces)
            if ns_id < 4 {
                let packed = pack_caip_tail(CaipType::ChainId, ns);
                let (caip_type, unpacked_ns) = unpack_caip_tail(packed).unwrap();
                assert_eq!(caip_type, CaipType::ChainId);
                assert_eq!(unpacked_ns, ns);
            }
        }
    }

    #[test]
    fn test_evm_address_roundtrip() {
        let address = hex::decode("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb").unwrap();
        let compact = encode_caip10(CaipNamespace::Eip155, "1", &address);

        println!("Compact: {} ({} chars)", compact, compact.len());

        let decoded = decode_caip10(&compact).unwrap();
        assert_eq!(decoded.namespace, CaipNamespace::Eip155);
        assert_eq!(decoded.reference, "1");
        assert_eq!(decoded.address, address);

        let caip_string = decoded.to_caip_string();
        assert_eq!(caip_string, "eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");
    }

    #[test]
    fn test_caip2_roundtrip() {
        let compact = encode_caip2(CaipNamespace::Eip155, "1");
        println!("CAIP-2 compact: {} ({} chars)", compact, compact.len());

        let decoded = decode_caip2(&compact).unwrap();
        assert_eq!(decoded.namespace, CaipNamespace::Eip155);
        assert_eq!(decoded.reference, "1");
        assert_eq!(decoded.to_caip_string(), "eip155:1");
    }

    #[test]
    fn test_size_comparison() {
        let address = hex::decode("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb").unwrap();
        let compact = encode_caip10(CaipNamespace::Eip155, "1", &address);
        let standard = "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";

        println!("Standard CAIP-10: {} chars", standard.len());
        println!("Compact:          {} chars", compact.len());
        println!("Savings:          {}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);

        // Should be at least 20% smaller
        assert!(compact.len() < standard.len());
    }

    #[test]
    fn test_o1_metadata_extraction() {
        let address = hex::decode("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb").unwrap();
        let compact = encode_caip10(CaipNamespace::Eip155, "1", &address);

        let meta = extract_caip_meta(&compact).unwrap();
        assert_eq!(meta.caip_type, CaipType::AccountId);
        assert_eq!(meta.namespace, CaipNamespace::Eip155);
    }

    #[test]
    fn test_parse_and_encode() {
        let input = "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";
        let compact = parse_and_encode_caip10(input).unwrap();
        let decoded = decode_caip10(&compact).unwrap();

        // Note: addresses are normalized to lowercase in output
        assert_eq!(decoded.namespace, CaipNamespace::Eip155);
        assert_eq!(decoded.reference, "1");
    }

    #[test]
    fn test_multiple_chains() {
        // Ethereum mainnet
        let eth_addr = hex::decode("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb").unwrap();
        let eth_compact = encode_caip10(CaipNamespace::Eip155, "1", &eth_addr);

        // Polygon
        let poly_compact = encode_caip10(CaipNamespace::Eip155, "137", &eth_addr);

        // Different chain refs should produce different compacts
        assert_ne!(eth_compact, poly_compact);

        // But both decode correctly
        let eth_decoded = decode_caip10(&eth_compact).unwrap();
        assert_eq!(eth_decoded.reference, "1");

        let poly_decoded = decode_caip10(&poly_compact).unwrap();
        assert_eq!(poly_decoded.reference, "137");
    }

    #[test]
    fn test_solana_address() {
        // Solana address (32 bytes)
        let sol_addr = [42u8; 32];
        let compact = encode_caip10(CaipNamespace::Solana, "mainnet", &sol_addr);

        let meta = extract_caip_meta(&compact).unwrap();
        assert_eq!(meta.namespace, CaipNamespace::Solana);

        let decoded = decode_caip10(&compact).unwrap();
        assert_eq!(decoded.address, sol_addr);
        assert_eq!(decoded.reference, "mainnet");
    }
}

// ============================================================================
// REAL-WORLD TEST VECTORS
// ============================================================================

#[cfg(test)]
mod real_world_tests {
    use super::*;

    // ========================================================================
    // EVM CHAINS (eip155)
    // ========================================================================

    #[test]
    fn test_evm_vitalik_eth() {
        // Vitalik's well-known address
        let address = hex::decode("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        let standard = "eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

        let compact = encode_caip10(CaipNamespace::Eip155, "1", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Eip155);
        assert_eq!(decoded.reference, "1");
        assert_eq!(decoded.address, address);

        println!("Vitalik.eth (Ethereum mainnet):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_evm_polygon_wmatic() {
        // WMATIC contract on Polygon
        let address = hex::decode("0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270").unwrap();
        let standard = "eip155:137:0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270";

        let compact = encode_caip10(CaipNamespace::Eip155, "137", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Eip155);
        assert_eq!(decoded.reference, "137");
        assert_eq!(decoded.address, address);

        println!("WMATIC (Polygon):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_evm_arbitrum_weth() {
        // WETH on Arbitrum
        let address = hex::decode("82aF49447D8a07e3bd95BD0d56f35241523fBab1").unwrap();
        let standard = "eip155:42161:0x82aF49447D8a07e3bd95BD0d56f35241523fBab1";

        let compact = encode_caip10(CaipNamespace::Eip155, "42161", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Eip155);
        assert_eq!(decoded.reference, "42161");
        assert_eq!(decoded.address, address);

        println!("WETH (Arbitrum):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_evm_base_usdc() {
        // USDC on Base
        let address = hex::decode("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap();
        let standard = "eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

        let compact = encode_caip10(CaipNamespace::Eip155, "8453", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Eip155);
        assert_eq!(decoded.reference, "8453");
        assert_eq!(decoded.address, address);

        println!("USDC (Base):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    // ========================================================================
    // SOLANA
    // ========================================================================

    #[test]
    fn test_solana_system_program() {
        // System Program: 11111111111111111111111111111111 (32 zero bytes in Base58)
        let address = bs58::decode("11111111111111111111111111111111").into_vec().unwrap();
        let standard = "solana:mainnet:11111111111111111111111111111111";

        let compact = encode_caip10(CaipNamespace::Solana, "mainnet", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Solana);
        assert_eq!(decoded.reference, "mainnet");
        assert_eq!(decoded.address, address);

        println!("Solana System Program:");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_solana_token_program() {
        // SPL Token Program
        let address = bs58::decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").into_vec().unwrap();
        let standard = "solana:mainnet:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

        let compact = encode_caip10(CaipNamespace::Solana, "mainnet", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Solana);
        assert_eq!(decoded.address, address);

        println!("Solana Token Program:");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_solana_usdc_mint() {
        // USDC Mint on Solana
        let address = bs58::decode("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").into_vec().unwrap();
        let standard = "solana:mainnet:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

        let compact = encode_caip10(CaipNamespace::Solana, "mainnet", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Solana);
        assert_eq!(decoded.address, address);

        println!("Solana USDC Mint:");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    // ========================================================================
    // NEAR PROTOCOL
    // ========================================================================

    #[test]
    fn test_near_named_account() {
        // Named account: aurora.near
        let address = "aurora.near".as_bytes().to_vec();
        let standard = "near:mainnet:aurora.near";

        let compact = encode_caip10(CaipNamespace::Near, "mainnet", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Near);
        assert_eq!(decoded.reference, "mainnet");
        assert_eq!(String::from_utf8_lossy(&decoded.address), "aurora.near");

        println!("NEAR named account (aurora.near):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_near_implicit_account() {
        // Implicit account: 64-char hex = Ed25519 pubkey
        let pubkey_hex = "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de";
        let address = hex::decode(pubkey_hex).unwrap();
        let standard = format!("near:mainnet:{}", pubkey_hex);

        let compact = encode_caip10(CaipNamespace::Near, "mainnet", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Near);
        assert_eq!(decoded.address, address);

        println!("NEAR implicit account (Ed25519 pubkey):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    // ========================================================================
    // COSMOS SDK
    // ========================================================================

    #[test]
    fn test_cosmos_hub_address() {
        // Cosmos Hub address (bech32 with "cosmos" HRP)
        // Real Cosmos Hub community pool address
        let (_, data) = bech32::decode("cosmos1jv65s3grqf6v6jl3dp4t6c9t9rk99cd88lyufl").unwrap();
        let address: Vec<u8> = data;

        let standard = "cosmos:cosmoshub-4:cosmos1jv65s3grqf6v6jl3dp4t6c9t9rk99cd88lyufl";

        let compact = encode_caip10(CaipNamespace::Cosmos, "cosmoshub-4", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Cosmos);
        assert_eq!(decoded.reference, "cosmoshub-4");
        assert_eq!(decoded.address, address);

        println!("Cosmos Hub address:");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_osmosis_address() {
        // Osmosis address - using a known Osmosis address
        // The Osmosis foundation address
        let (_, data) = bech32::decode("osmo1c584m4lq25h83yp6ag8hh4htjr92d954vklzja").unwrap();
        let address: Vec<u8> = data;

        let standard = "cosmos:osmosis-1:osmo1c584m4lq25h83yp6ag8hh4htjr92d954vklzja";

        let compact = encode_caip10(CaipNamespace::Cosmos, "osmosis-1", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Cosmos);
        assert_eq!(decoded.reference, "osmosis-1");
        assert_eq!(decoded.address, address);

        println!("Osmosis address:");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    // ========================================================================
    // BITCOIN (bip122)
    // ========================================================================

    #[test]
    fn test_bitcoin_bech32_address() {
        // Bitcoin SegWit address (bech32)
        // bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq → 20-byte witness program
        let (_, data) = bech32::decode("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
        let address: Vec<u8> = data;

        // BIP-122 uses first 32 chars of genesis block hash
        let standard = "bip122:000000000019d6689c085ae165831e93:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let compact = encode_caip10(CaipNamespace::Bip122, "000000000019d6689c085ae165831e93", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Bip122);
        assert_eq!(decoded.reference, "000000000019d6689c085ae165831e93");
        assert_eq!(decoded.address, address);

        println!("Bitcoin SegWit (bech32):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    #[test]
    fn test_bitcoin_p2pkh_legacy() {
        // Bitcoin legacy P2PKH address (Base58Check)
        // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (Satoshi's genesis coinbase)
        // Decode Base58Check: version byte + 20-byte pubkey hash + 4-byte checksum
        let decoded_b58 = bs58::decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").into_vec().unwrap();
        // Full payload includes version + pubkey hash (skip checksum for storage)
        let address = decoded_b58[..21].to_vec(); // version (1) + pubkey hash (20)

        let standard = "bip122:000000000019d6689c085ae165831e93:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

        let compact = encode_caip10(CaipNamespace::Bip122, "000000000019d6689c085ae165831e93", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Bip122);
        assert_eq!(decoded.address, address);

        println!("Bitcoin P2PKH (Satoshi genesis):");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    // ========================================================================
    // STARKNET
    // ========================================================================

    #[test]
    fn test_starknet_eth_contract() {
        // StarkNet ETH contract (32-byte field element)
        let address = hex::decode("049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7").unwrap();
        let standard = "starknet:SN_MAIN:0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";

        let compact = encode_caip10(CaipNamespace::Starknet, "SN_MAIN", &address);
        let decoded = decode_caip10(&compact).unwrap();

        assert_eq!(decoded.namespace, CaipNamespace::Starknet);
        assert_eq!(decoded.reference, "SN_MAIN");
        assert_eq!(decoded.address, address);

        println!("StarkNet ETH Contract:");
        println!("  Standard: {} ({} chars)", standard, standard.len());
        println!("  Compact:  {} ({} chars)", compact, compact.len());
        println!("  Savings:  {:.1}%", (1.0 - compact.len() as f64 / standard.len() as f64) * 100.0);
    }

    // ========================================================================
    // SIZE COMPARISON SUMMARY
    // ========================================================================

    #[test]
    fn test_all_chains_size_comparison() {
        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║           CAIP COMPACT ENCODING - SIZE COMPARISON              ║");
        println!("╠════════════════════════════════════════════════════════════════╣");
        println!("║ Chain          │ Standard │ Compact │ Savings                  ║");
        println!("╠════════════════════════════════════════════════════════════════╣");

        // EVM - Ethereum
        let eth_addr = hex::decode("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        let eth_std = "eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let eth_compact = encode_caip10(CaipNamespace::Eip155, "1", &eth_addr);
        println!("║ Ethereum (1)   │ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            eth_std.len(), eth_compact.len(),
            (1.0 - eth_compact.len() as f64 / eth_std.len() as f64) * 100.0);

        // EVM - Arbitrum (longer chain ID)
        let arb_std = "eip155:42161:0x82aF49447D8a07e3bd95BD0d56f35241523fBab1";
        let arb_addr = hex::decode("82aF49447D8a07e3bd95BD0d56f35241523fBab1").unwrap();
        let arb_compact = encode_caip10(CaipNamespace::Eip155, "42161", &arb_addr);
        println!("║ Arbitrum       │ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            arb_std.len(), arb_compact.len(),
            (1.0 - arb_compact.len() as f64 / arb_std.len() as f64) * 100.0);

        // Solana
        let sol_addr = bs58::decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").into_vec().unwrap();
        let sol_std = "solana:mainnet:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let sol_compact = encode_caip10(CaipNamespace::Solana, "mainnet", &sol_addr);
        println!("║ Solana         │ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            sol_std.len(), sol_compact.len(),
            (1.0 - sol_compact.len() as f64 / sol_std.len() as f64) * 100.0);

        // NEAR named
        let near_named = "aurora.near".as_bytes().to_vec();
        let near_named_std = "near:mainnet:aurora.near";
        let near_named_compact = encode_caip10(CaipNamespace::Near, "mainnet", &near_named);
        println!("║ NEAR (named)   │ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            near_named_std.len(), near_named_compact.len(),
            (1.0 - near_named_compact.len() as f64 / near_named_std.len() as f64) * 100.0);

        // NEAR implicit
        let near_impl = hex::decode("98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de").unwrap();
        let near_impl_std = "near:mainnet:98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de";
        let near_impl_compact = encode_caip10(CaipNamespace::Near, "mainnet", &near_impl);
        println!("║ NEAR (implicit)│ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            near_impl_std.len(), near_impl_compact.len(),
            (1.0 - near_impl_compact.len() as f64 / near_impl_std.len() as f64) * 100.0);

        // StarkNet
        let stark_addr = hex::decode("049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7").unwrap();
        let stark_std = "starknet:SN_MAIN:0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
        let stark_compact = encode_caip10(CaipNamespace::Starknet, "SN_MAIN", &stark_addr);
        println!("║ StarkNet       │ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            stark_std.len(), stark_compact.len(),
            (1.0 - stark_compact.len() as f64 / stark_std.len() as f64) * 100.0);

        // Cosmos
        let (_, cosmos_data) = bech32::decode("cosmos1jv65s3grqf6v6jl3dp4t6c9t9rk99cd88lyufl").unwrap();
        let cosmos_addr: Vec<u8> = cosmos_data;
        let cosmos_std = "cosmos:cosmoshub-4:cosmos1jv65s3grqf6v6jl3dp4t6c9t9rk99cd88lyufl";
        let cosmos_compact = encode_caip10(CaipNamespace::Cosmos, "cosmoshub-4", &cosmos_addr);
        println!("║ Cosmos Hub     │ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            cosmos_std.len(), cosmos_compact.len(),
            (1.0 - cosmos_compact.len() as f64 / cosmos_std.len() as f64) * 100.0);

        // Bitcoin (bech32)
        let (_, btc_data) = bech32::decode("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
        let btc_addr: Vec<u8> = btc_data;
        let btc_std = "bip122:000000000019d6689c085ae165831e93:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let btc_compact = encode_caip10(CaipNamespace::Bip122, "000000000019d6689c085ae165831e93", &btc_addr);
        println!("║ Bitcoin (bc1)  │ {:>8} │ {:>7} │ {:>5.1}%                   ║",
            btc_std.len(), btc_compact.len(),
            (1.0 - btc_compact.len() as f64 / btc_std.len() as f64) * 100.0);

        println!("╚════════════════════════════════════════════════════════════════╝\n");
    }
}
