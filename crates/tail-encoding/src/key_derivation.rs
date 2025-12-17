//! Cross-chain address derivation from public keys.
//!
//! NEAR Protocol supports ed25519 and secp256k1 key types. This module
//! derives canonical addresses on various chains from these key types,
//! enabling "one key, many chains" identity.
//!
//! # Derivation Rules
//!
//! | Key Type    | Chain      | Method |
//! |-------------|------------|--------|
//! | Ed25519     | NEAR       | hex(pubkey) → implicit account |
//! | Ed25519     | Solana     | pubkey directly (same format) |
//! | Secp256k1   | Ethereum   | keccak256(uncompressed[1..65])[12..32] |
//! | Secp256k1   | Bitcoin    | P2PKH, P2SH-P2WPKH, P2WPKH, P2TR |
//!
//! # Example
//!
//! ```
//! use tail_encoding::key_derivation::*;
//! use bitcoin::Network;
//!
//! // Ed25519 pubkey derives same account on NEAR and Solana
//! let ed25519_bytes = [1u8; 32];
//! let pk = PubKey::from_ed25519_bytes(ed25519_bytes).unwrap();
//! let resolved = resolve(&pk, Network::Bitcoin).unwrap();
//!
//! assert!(resolved.solana.is_some());
//! assert!(resolved.near_implicit.is_some());
//! ```

use bitcoin::{Address, CompressedPublicKey, Network, PublicKey as BtcPublicKey};
use bitcoin::secp256k1::{self, Secp256k1};
use ed25519_dalek::VerifyingKey;
use sha3::{Digest, Keccak256};
use thiserror::Error;

// Re-export for convenience
pub use bitcoin::Network as BitcoinNetwork;

// ============================================================================
// CAIP-2 CHAIN ID CONSTANTS
// ============================================================================

// Bitcoin (BIP122 namespace uses genesis block hash prefix)
// https://namespaces.chainagnostic.org/bip122/caip2
pub const CAIP2_BITCOIN_MAINNET: &str = "bip122:000000000019d6689c085ae165831e93";
pub const CAIP2_BITCOIN_TESTNET: &str = "bip122:000000000933ea01ad0ee984209779ba";

// Solana (uses truncated genesis hash)
// https://namespaces.chainagnostic.org/solana/caip2
pub const CAIP2_SOLANA_MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
pub const CAIP2_SOLANA_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
pub const CAIP2_SOLANA_TESTNET: &str = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z";

// Ethereum mainnet
pub const CAIP2_ETHEREUM_MAINNET: &str = "eip155:1";

// NEAR
pub const CAIP2_NEAR_MAINNET: &str = "near:mainnet";
pub const CAIP2_NEAR_TESTNET: &str = "near:testnet";

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("invalid ed25519 public key bytes")]
    InvalidEd25519,

    #[error("invalid secp256k1 public key bytes")]
    InvalidSecp256k1,

    #[error("bitcoin pubkey not compressible")]
    BitcoinCompressedPubkey,
}

// ============================================================================
// PUBLIC KEY TYPES
// ============================================================================

#[derive(Clone, Debug)]
pub enum PubKey {
    Ed25519(VerifyingKey),
    Secp256k1(secp256k1::PublicKey),
}

impl PubKey {
    /// Create from 32-byte Ed25519 public key.
    pub fn from_ed25519_bytes(bytes: [u8; 32]) -> Result<Self, ResolveError> {
        let vk = VerifyingKey::from_bytes(&bytes).map_err(|_| ResolveError::InvalidEd25519)?;
        Ok(Self::Ed25519(vk))
    }

    /// Create from secp256k1 public key bytes.
    /// Accepts compressed (33) or uncompressed (65) SEC1 format.
    pub fn from_secp256k1_bytes(bytes: &[u8]) -> Result<Self, ResolveError> {
        let pk = secp256k1::PublicKey::from_slice(bytes)
            .map_err(|_| ResolveError::InvalidSecp256k1)?;
        Ok(Self::Secp256k1(pk))
    }

    /// Get Ed25519 bytes if this is an Ed25519 key.
    pub fn ed25519_bytes(&self) -> Option<[u8; 32]> {
        match self {
            PubKey::Ed25519(vk) => Some(vk.to_bytes()),
            _ => None,
        }
    }

    /// Get secp256k1 public key reference if this is a secp256k1 key.
    pub fn secp256k1(&self) -> Option<&secp256k1::PublicKey> {
        match self {
            PubKey::Secp256k1(pk) => Some(pk),
            _ => None,
        }
    }
}

// ============================================================================
// ADDRESS TYPES
// ============================================================================

/// Ethereum address with multiple display formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthereumAddresses {
    /// 20 raw bytes.
    pub bytes: [u8; 20],
    /// "0x" + 40 lowercase hex
    pub hex_lower: String,
    /// EIP-55 checksummed
    pub eip55: String,
}

/// Bitcoin addresses in all standard formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinAddresses {
    /// Legacy P2PKH (starts with 1 on mainnet)
    pub p2pkh: String,
    /// Nested SegWit P2SH-P2WPKH (starts with 3 on mainnet)
    pub p2sh_p2wpkh: String,
    /// Native SegWit P2WPKH (bc1q... on mainnet)
    pub p2wpkh: String,
    /// Taproot P2TR (bc1p... on mainnet)
    pub p2tr: String,
}

/// All resolved addresses for a public key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedAddresses {
    /// Ethereum address (secp256k1 only)
    pub ethereum: Option<EthereumAddresses>,
    /// Solana address as Base58 (ed25519 only)
    pub solana: Option<String>,
    /// NEAR implicit account ID (ed25519 only)
    pub near_implicit: Option<String>,
    /// Bitcoin addresses in all formats (secp256k1 only)
    pub bitcoin: Option<BitcoinAddresses>,
}

// ============================================================================
// MAIN RESOLVER
// ============================================================================

/// Resolve all compatible addresses for a public key.
///
/// - Ed25519 → Solana + NEAR implicit
/// - Secp256k1 → Ethereum + Bitcoin (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
pub fn resolve(pubkey: &PubKey, btc_network: Network) -> Result<ResolvedAddresses, ResolveError> {
    let mut out = ResolvedAddresses::default();

    match pubkey {
        PubKey::Ed25519(vk) => {
            let bytes = vk.to_bytes();
            out.solana = Some(solana_address_from_ed25519(bytes));
            out.near_implicit = Some(near_implicit_from_ed25519(bytes));
        }
        PubKey::Secp256k1(pk) => {
            out.ethereum = Some(ethereum_addresses_from_secp256k1(pk));
            out.bitcoin = Some(bitcoin_addresses_from_secp256k1(pk, btc_network)?);
        }
    }

    Ok(out)
}

// ============================================================================
// ETHEREUM (secp256k1)
// ============================================================================

/// Derive Ethereum addresses from secp256k1 public key.
pub fn ethereum_addresses_from_secp256k1(pk: &secp256k1::PublicKey) -> EthereumAddresses {
    // 65 bytes: 0x04 || x(32) || y(32)
    let uncompressed = pk.serialize_uncompressed();
    let hash = keccak256(&uncompressed[1..]); // drop 0x04
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]); // last 20 bytes

    let hex_lower = format!("0x{}", hex::encode(addr));
    let eip55 = to_eip55(&hex_lower);

    EthereumAddresses { bytes: addr, hex_lower, eip55 }
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

/// Convert lowercase hex address to EIP-55 checksummed format.
///
/// Input: "0x" + 40 hex (any case). Output: EIP-55 checksummed.
pub fn to_eip55(addr_hex: &str) -> String {
    let s = addr_hex.strip_prefix("0x").unwrap_or(addr_hex);
    let lower = s.to_ascii_lowercase();

    let mut hasher = Keccak256::new();
    hasher.update(lower.as_bytes());
    let digest = hasher.finalize();

    // For each hex char, uppercase if corresponding nibble >= 8 (for a-f chars).
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

// ============================================================================
// SOLANA (ed25519)
// ============================================================================

/// Derive Solana address from Ed25519 public key.
pub fn solana_address_from_ed25519(pubkey32: [u8; 32]) -> String {
    bs58::encode(pubkey32).into_string()
}

// ============================================================================
// NEAR IMPLICIT (ed25519)
// ============================================================================

/// Derive NEAR implicit account ID from Ed25519 public key.
///
/// NEAR implicit accounts are the 32-byte Ed25519 public key
/// encoded as 64 lowercase hex characters.
pub fn near_implicit_from_ed25519(pubkey32: [u8; 32]) -> String {
    hex::encode(pubkey32)
}

// ============================================================================
// BITCOIN (secp256k1)
// ============================================================================

/// Derive Bitcoin addresses from secp256k1 public key.
///
/// Returns P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR addresses.
pub fn bitcoin_addresses_from_secp256k1(
    pk: &secp256k1::PublicKey,
    network: Network,
) -> Result<BitcoinAddresses, ResolveError> {
    let btc_pk = BtcPublicKey::new(*pk); // always compressed in bitcoin 0.32

    // Get compressed pubkey for SegWit addresses
    let compressed_pk = CompressedPublicKey::try_from(btc_pk)
        .map_err(|_| ResolveError::BitcoinCompressedPubkey)?;

    let p2pkh = Address::p2pkh(btc_pk, network).to_string();
    let p2wpkh = Address::p2wpkh(&compressed_pk, network).to_string();
    let p2sh_p2wpkh = Address::p2shwpkh(&compressed_pk, network).to_string();

    // Taproot P2TR with no script tree (merkle_root = None):
    let secp = Secp256k1::verification_only();
    let xonly = secp256k1::XOnlyPublicKey::from(*pk);
    let p2tr = Address::p2tr(&secp, xonly, None, network).to_string();

    Ok(BitcoinAddresses {
        p2pkh,
        p2sh_p2wpkh,
        p2wpkh,
        p2tr,
    })
}

// ============================================================================
// CAIP-10 HELPERS
// ============================================================================

/// Format CAIP-10 address from CAIP-2 chain ID and account address.
///
/// CAIP-10 format: `{caip2_chain_id}:{account_address}`
///
/// # Example
/// ```
/// use tail_encoding::key_derivation::{caip10, CAIP2_BITCOIN_MAINNET};
///
/// let addr = caip10(CAIP2_BITCOIN_MAINNET, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
/// assert_eq!(addr, "bip122:000000000019d6689c085ae165831e93:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
/// ```
pub fn caip10(chain_id_caip2: &str, account_address: &str) -> String {
    format!("{}:{}", chain_id_caip2, account_address)
}

/// Format CAIP-10 address for EIP-155 (EVM) chains.
///
/// # Example
/// ```
/// use tail_encoding::key_derivation::caip10_eip155;
///
/// let addr = caip10_eip155(1, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
/// assert_eq!(addr, "eip155:1:0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
/// ```
pub fn caip10_eip155(chain_id: u64, eth_hex0x: &str) -> String {
    format!("eip155:{}:{}", chain_id, eth_hex0x)
}

// ============================================================================
// CAIP-10 RESOLUTION (COMPACT ENCODED)
// ============================================================================

use crate::caip::{CaipNamespace, encode_caip10};

/// CAIP-10 formatted addresses for a public key.
#[derive(Clone, Debug, Default)]
pub struct Caip10Addresses {
    /// Ethereum mainnet: eip155:1:0x...
    pub ethereum_mainnet: Option<String>,
    /// Solana mainnet: solana:mainnet:...
    pub solana_mainnet: Option<String>,
    /// NEAR mainnet: near:mainnet:...
    pub near_mainnet: Option<String>,
    /// Bitcoin mainnet: bip122:000000000019d6689c085ae165831e93:...
    pub bitcoin_mainnet: Option<String>,
}

/// Bitcoin mainnet genesis block hash (first 32 chars)
pub const BTC_MAINNET_GENESIS: &str = "000000000019d6689c085ae165831e93";

/// Resolve public key to CAIP-10 formatted addresses.
///
/// Returns compact tail-encoded CAIP-10 strings for all compatible chains.
pub fn resolve_caip10(pubkey: &PubKey) -> Result<Caip10Addresses, ResolveError> {
    let mut out = Caip10Addresses::default();

    match pubkey {
        PubKey::Ed25519(vk) => {
            let bytes = vk.to_bytes();

            // Solana: use the 32-byte pubkey directly
            out.solana_mainnet = Some(encode_caip10(
                CaipNamespace::Solana,
                "mainnet",
                &bytes,
            ));

            // NEAR: use the 32-byte pubkey (displayed as hex)
            out.near_mainnet = Some(encode_caip10(
                CaipNamespace::Near,
                "mainnet",
                &bytes,
            ));
        }
        PubKey::Secp256k1(pk) => {
            // Ethereum: derive 20-byte address
            let eth = ethereum_addresses_from_secp256k1(pk);
            out.ethereum_mainnet = Some(encode_caip10(
                CaipNamespace::Eip155,
                "1",
                &eth.bytes,
            ));

            // Bitcoin P2WPKH: use the witness program (pubkey hash, 20 bytes)
            // For CAIP encoding, we compute the pubkey hash directly
            let btc_pk = BtcPublicKey::new(*pk);
            let compressed_pk = CompressedPublicKey::try_from(btc_pk)
                .map_err(|_| ResolveError::BitcoinCompressedPubkey)?;
            let wpkh = compressed_pk.wpubkey_hash();
            out.bitcoin_mainnet = Some(encode_caip10(
                CaipNamespace::Bip122,
                BTC_MAINNET_GENESIS,
                wpkh.as_ref(),
            ));
        }
    }

    Ok(out)
}

/// Resolve public key to standard CAIP-10 strings (not compact encoded).
pub fn resolve_caip10_standard(pubkey: &PubKey) -> Result<Vec<String>, ResolveError> {
    let mut out = Vec::new();

    match pubkey {
        PubKey::Ed25519(vk) => {
            let bytes = vk.to_bytes();
            let sol_addr = solana_address_from_ed25519(bytes);
            let near_addr = near_implicit_from_ed25519(bytes);

            out.push(format!("solana:mainnet:{}", sol_addr));
            out.push(format!("near:mainnet:{}", near_addr));
        }
        PubKey::Secp256k1(pk) => {
            let eth = ethereum_addresses_from_secp256k1(pk);
            let btc = bitcoin_addresses_from_secp256k1(pk, Network::Bitcoin)?;

            out.push(format!("eip155:1:{}", eth.eip55));
            out.push(format!("bip122:{}:{}", BTC_MAINNET_GENESIS, btc.p2wpkh));
            out.push(format!("bip122:{}:{}", BTC_MAINNET_GENESIS, btc.p2tr));
        }
    }

    Ok(out)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{SecretKey, Secp256k1};

    #[test]
    fn eth_privkey_1_vector() {
        // privkey = 1 => 0x7E5F... (classic known vector)
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 1;
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let eth = ethereum_addresses_from_secp256k1(&pk);
        assert_eq!(eth.hex_lower, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        assert_eq!(eth.eip55, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }

    #[test]
    fn near_implicit_example_from_docs() {
        // Example from NEAR docs: base58 pubkey -> implicit account id
        let base58_pk = "BGCCDDHfysuuVnaNVtEhhqeT4k9Muyem3Kpgq2U1m9HX";
        let bytes = bs58::decode(base58_pk).into_vec().unwrap();
        assert_eq!(bytes.len(), 32);

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);

        let pk = PubKey::from_ed25519_bytes(arr).unwrap();
        let resolved = resolve(&pk, Network::Bitcoin).unwrap();

        assert_eq!(
            resolved.near_implicit.unwrap(),
            "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de"
        );
    }

    #[test]
    fn btc_privkey_1_addresses() {
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 1;
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let btc = bitcoin_addresses_from_secp256k1(&pk, Network::Bitcoin).unwrap();
        assert_eq!(btc.p2pkh, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert!(btc.p2sh_p2wpkh.starts_with('3'));
        assert!(btc.p2wpkh.starts_with("bc1q"));
        assert!(btc.p2tr.starts_with("bc1p"));
    }

    #[test]
    fn solana_ed25519_same_bytes() {
        // Solana uses Ed25519 pubkey directly
        let pubkey = [42u8; 32];
        let sol_addr = solana_address_from_ed25519(pubkey);

        // The Base58 decoded result should be the original bytes
        let decoded = bs58::decode(&sol_addr).into_vec().unwrap();
        assert_eq!(decoded, pubkey.to_vec());
    }

    #[test]
    fn test_resolve_all_ed25519() {
        let pk = PubKey::from_ed25519_bytes([1u8; 32]).unwrap();
        let resolved = resolve(&pk, Network::Bitcoin).unwrap();

        assert!(resolved.solana.is_some());
        assert!(resolved.near_implicit.is_some());
        assert!(resolved.ethereum.is_none());
        assert!(resolved.bitcoin.is_none());
    }

    #[test]
    fn test_resolve_all_secp256k1() {
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 1;
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk_raw = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let pk = PubKey::Secp256k1(pk_raw);
        let resolved = resolve(&pk, Network::Bitcoin).unwrap();

        assert!(resolved.ethereum.is_some());
        assert!(resolved.bitcoin.is_some());
        assert!(resolved.solana.is_none());
        assert!(resolved.near_implicit.is_none());
    }

    #[test]
    fn test_eip55_checksum() {
        // Test known checksummed address
        let input = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359";
        let checksummed = to_eip55(input);
        assert_eq!(checksummed, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    }

    #[test]
    fn test_resolve_caip10() {
        let pk = PubKey::from_ed25519_bytes([1u8; 32]).unwrap();
        let caip = resolve_caip10(&pk).unwrap();

        assert!(caip.solana_mainnet.is_some());
        assert!(caip.near_mainnet.is_some());
        assert!(caip.ethereum_mainnet.is_none());

        // Verify CAIP-10 format works with our decoder
        let sol_compact = caip.solana_mainnet.unwrap();
        let decoded = crate::caip::decode_caip10(&sol_compact).unwrap();
        assert_eq!(decoded.namespace, CaipNamespace::Solana);
        assert_eq!(decoded.reference, "mainnet");
    }

    #[test]
    fn test_resolve_caip10_standard() {
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 1;
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk_raw = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let pk = PubKey::Secp256k1(pk_raw);
        let caip_strings = resolve_caip10_standard(&pk).unwrap();

        assert!(caip_strings.iter().any(|s| s.starts_with("eip155:1:")));
        assert!(caip_strings.iter().any(|s| s.starts_with("bip122:")));
    }

    #[test]
    fn test_caip10_helper() {
        use super::{caip10, CAIP2_BITCOIN_MAINNET, CAIP2_SOLANA_MAINNET};

        // Bitcoin with bech32 address
        let btc_addr = caip10(CAIP2_BITCOIN_MAINNET, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        assert_eq!(
            btc_addr,
            "bip122:000000000019d6689c085ae165831e93:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        );

        // Solana with program address
        let sol_addr = caip10(CAIP2_SOLANA_MAINNET, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        assert_eq!(
            sol_addr,
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        );
    }

    #[test]
    fn test_caip10_eip155_helper() {
        use super::caip10_eip155;

        // Ethereum mainnet
        let eth_addr = caip10_eip155(1, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        assert_eq!(eth_addr, "eip155:1:0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");

        // Polygon (chain ID 137)
        let polygon_addr = caip10_eip155(137, "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270");
        assert_eq!(polygon_addr, "eip155:137:0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270");

        // Base (chain ID 8453)
        let base_addr = caip10_eip155(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        assert_eq!(base_addr, "eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
    }
}
