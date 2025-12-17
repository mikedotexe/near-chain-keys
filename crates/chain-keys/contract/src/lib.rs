//! NEAR Cross-Chain Identity Contract
//!
//! Manages access keys with cross-chain metadata bindings.
//! When a key is added with a chain binding, the contract:
//! 1. Derives the canonical address on that chain
//! 2. Stores the binding in contract state
//! 3. Issues an AddKey promise to add the key to the account

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::LookupMap;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, AccountId, PanicOnDefault, Promise, PublicKey};

mod derivation;

// ============================================================================
// CAIP-2 CHAIN ID CONSTANTS
// ============================================================================

// Bitcoin P2WPKH (SegWit v0)
pub const CAIP2_BITCOIN_MAINNET: &str = "bip122:000000000019d6689c085ae165831e93";
pub const CAIP2_BITCOIN_TESTNET: &str = "bip122:000000000933ea01ad0ee984209779ba";

// Bitcoin P2TR (Taproot, SegWit v1)
pub const CAIP2_BITCOIN_MAINNET_P2TR: &str = "bip122:000000000019d6689c085ae165831e93:p2tr";
pub const CAIP2_BITCOIN_TESTNET_P2TR: &str = "bip122:000000000933ea01ad0ee984209779ba:p2tr";

pub const CAIP2_SOLANA_MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
pub const CAIP2_ETHEREUM_MAINNET: &str = "eip155:1";
pub const CAIP2_NEAR_MAINNET: &str = "near:mainnet";
pub const CAIP2_NEAR_TESTNET: &str = "near:testnet";

// ============================================================================
// TYPES
// ============================================================================

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum Curve {
    Ed25519,
    Secp256k1,
}

/// User-provided metadata as key-value pairs.
/// Flexible structure for tagging keys with arbitrary data.
pub type Metadata = Vec<(String, String)>;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct ChainBinding {
    pub caip2_chain: String,
    pub address: String,
    pub added_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Metadata,
}

/// Key info returned by query methods.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct KeyInfo {
    pub public_key: PublicKey,
    pub address: String,
    pub added_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Metadata,
}

/// Bitcoin keys grouped by network and address type.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(crate = "near_sdk::serde")]
pub struct BitcoinKeys {
    pub mainnet_p2wpkh: Vec<KeyInfo>,
    pub mainnet_p2tr: Vec<KeyInfo>,
    pub testnet_p2wpkh: Vec<KeyInfo>,
    pub testnet_p2tr: Vec<KeyInfo>,
}

// ============================================================================
// CONTRACT
// ============================================================================

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    /// Forward index: key -> chain binding
    key_bindings: LookupMap<PublicKey, ChainBinding>,
    /// Reverse index: caip2_chain -> list of keys
    chain_keys: LookupMap<String, Vec<PublicKey>>,
}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self {
            owner: env::predecessor_account_id(),
            key_bindings: LookupMap::new(b"k"),
            chain_keys: LookupMap::new(b"c"),
        }
    }

    // ========================================================================
    // KEY MANAGEMENT
    // ========================================================================

    /// Add an access key with a cross-chain binding.
    ///
    /// # Arguments
    /// * `public_key` - The public key to add
    /// * `curve` - The curve type (Ed25519 or Secp256k1)
    /// * `caip2_chain` - The CAIP-2 chain identifier (e.g., "eip155:1", "bip122:...:p2tr")
    /// * `metadata` - Optional key-value pairs for tagging (e.g., [["label", "hot wallet"]])
    #[payable]
    pub fn add_key(
        &mut self,
        public_key: PublicKey,
        curve: Curve,
        caip2_chain: String,
        metadata: Option<Metadata>,
    ) -> Promise {
        self.assert_owner();

        // Validate curve matches the key
        self.validate_curve(&public_key, &curve);

        // Derive address for the chain
        let address = self.derive_address(&public_key, &curve, &caip2_chain);

        // Check key doesn't already have a binding
        assert!(
            self.key_bindings.get(&public_key).is_none(),
            "Key already has a chain binding. Use force_delete_key first."
        );

        // Store the binding
        let binding = ChainBinding {
            caip2_chain: caip2_chain.clone(),
            address: address.clone(),
            added_at: env::block_height(),
            metadata: metadata.unwrap_or_default(),
        };
        self.key_bindings.insert(public_key.clone(), binding);

        // Update reverse index
        let mut keys = self.chain_keys.get(&caip2_chain).cloned().unwrap_or_default();
        keys.push(public_key.clone());
        self.chain_keys.insert(caip2_chain.clone(), keys);

        env::log_str(&format!(
            "Adding key with binding: {:?} -> {} on {}",
            public_key, address, caip2_chain
        ));

        // Issue AddKey action
        Promise::new(env::current_account_id()).add_full_access_key(public_key)
    }

    /// Delete a key that has NO chain binding.
    pub fn delete_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();

        assert!(
            self.key_bindings.get(&public_key).is_none(),
            "Key has a chain binding. Use force_delete_key to acknowledge removal."
        );

        env::log_str(&format!("Deleting key without binding: {:?}", public_key));

        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    /// Force delete a key, even if it has a chain binding.
    pub fn force_delete_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();

        if let Some(binding) = self.key_bindings.remove(&public_key) {
            // Remove from reverse index
            if let Some(mut keys) = self.chain_keys.get(&binding.caip2_chain).cloned() {
                keys.retain(|k| k != &public_key);
                if keys.is_empty() {
                    self.chain_keys.remove(&binding.caip2_chain);
                } else {
                    self.chain_keys.insert(binding.caip2_chain.clone(), keys);
                }
            }

            env::log_str(&format!(
                "Removing chain binding: {:?} -> {} on {}",
                public_key, binding.address, binding.caip2_chain
            ));
        }

        env::log_str(&format!("Force deleting key: {:?}", public_key));

        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    // ========================================================================
    // VIEW METHODS
    // ========================================================================

    /// Get binding info for a specific public key.
    pub fn get_pubkey_info(&self, public_key: PublicKey) -> Option<ChainBinding> {
        self.key_bindings.get(&public_key).cloned()
    }

    /// Get all keys registered for a specific CAIP-2 chain.
    pub fn get_keys(&self, caip2_chain: String) -> Vec<KeyInfo> {
        self.chain_keys
            .get(&caip2_chain)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|pk| {
                self.key_bindings.get(&pk).map(|b| KeyInfo {
                    public_key: pk,
                    address: b.address.clone(),
                    added_at: b.added_at,
                    metadata: b.metadata.clone(),
                })
            })
            .collect()
    }

    /// Get all Bitcoin keys, grouped by network and address type.
    pub fn get_bitcoin_keys(&self) -> BitcoinKeys {
        BitcoinKeys {
            mainnet_p2wpkh: self.get_keys(CAIP2_BITCOIN_MAINNET.to_string()),
            mainnet_p2tr: self.get_keys(CAIP2_BITCOIN_MAINNET_P2TR.to_string()),
            testnet_p2wpkh: self.get_keys(CAIP2_BITCOIN_TESTNET.to_string()),
            testnet_p2tr: self.get_keys(CAIP2_BITCOIN_TESTNET_P2TR.to_string()),
        }
    }

    /// Get all keys for a namespace (e.g., "eip155", "solana", "bip122").
    pub fn get_keys_by_namespace(&self, namespace: String) -> Vec<KeyInfo> {
        let prefix = format!("{}:", namespace);
        let mut results = Vec::new();

        // Check known chains for this namespace
        let chains_to_check: Vec<&str> = match namespace.as_str() {
            "bip122" => vec![
                CAIP2_BITCOIN_MAINNET,
                CAIP2_BITCOIN_TESTNET,
                CAIP2_BITCOIN_MAINNET_P2TR,
                CAIP2_BITCOIN_TESTNET_P2TR,
            ],
            "eip155" => vec![CAIP2_ETHEREUM_MAINNET],
            "solana" => vec![CAIP2_SOLANA_MAINNET],
            "near" => vec![CAIP2_NEAR_MAINNET, CAIP2_NEAR_TESTNET],
            _ => vec![],
        };

        for chain in chains_to_check {
            if chain.starts_with(&prefix) {
                results.extend(self.get_keys(chain.to_string()));
            }
        }

        results
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "Only owner can call this method"
        );
    }

    fn validate_curve(&self, pk: &PublicKey, curve: &Curve) {
        let pk_bytes = pk.as_bytes();

        match curve {
            Curve::Ed25519 => {
                assert_eq!(pk_bytes[0], 0, "Curve mismatch: expected Ed25519 key (prefix 0x00)");
            }
            Curve::Secp256k1 => {
                assert_eq!(pk_bytes[0], 1, "Curve mismatch: expected Secp256k1 key (prefix 0x01)");
            }
        }
    }

    fn derive_address(&self, pk: &PublicKey, curve: &Curve, caip2_chain: &str) -> String {
        let pk_bytes = pk.as_bytes();

        match curve {
            Curve::Ed25519 => {
                assert_eq!(pk_bytes.len(), 33, "Invalid Ed25519 key length");
                let key_bytes: [u8; 32] = pk_bytes[1..33].try_into().unwrap();

                if caip2_chain.starts_with("near:") {
                    derivation::derive_near_implicit(&key_bytes)
                } else if caip2_chain.starts_with("solana:") {
                    derivation::derive_solana(&key_bytes)
                } else {
                    env::panic_str(&format!("Ed25519 keys not supported for chain: {}", caip2_chain));
                }
            }
            Curve::Secp256k1 => {
                assert_eq!(pk_bytes.len(), 65, "Invalid Secp256k1 key length");
                let key_xy = &pk_bytes[1..65];

                if caip2_chain.starts_with("eip155:") {
                    let addr = derivation::derive_ethereum(key_xy);
                    derivation::to_eip55(&addr)
                } else if caip2_chain.starts_with("bip122:") {
                    // Parse network and address type from chain ID
                    // Format: bip122:<genesis_hash> or bip122:<genesis_hash>:p2tr
                    let (network, is_p2tr) = parse_bitcoin_chain(caip2_chain);

                    if is_p2tr {
                        derivation::derive_bitcoin_p2tr(key_xy, network)
                    } else {
                        derivation::derive_bitcoin_p2wpkh(key_xy, network)
                    }
                } else {
                    env::panic_str(&format!("Secp256k1 keys not supported for chain: {}", caip2_chain));
                }
            }
        }
    }
}

/// Parse Bitcoin chain ID to extract network and address type.
///
/// Formats:
/// - `bip122:000000000019d6689c085ae165831e93` → (Mainnet, P2WPKH)
/// - `bip122:000000000019d6689c085ae165831e93:p2wpkh` → (Mainnet, P2WPKH)
/// - `bip122:000000000019d6689c085ae165831e93:p2tr` → (Mainnet, P2TR)
fn parse_bitcoin_chain(caip2_chain: &str) -> (derivation::BitcoinNetwork, bool) {
    let is_p2tr = caip2_chain.ends_with(":p2tr");

    // Strip suffix to check network
    let chain_base = caip2_chain
        .strip_suffix(":p2tr")
        .or_else(|| caip2_chain.strip_suffix(":p2wpkh"))
        .unwrap_or(caip2_chain);

    let network = if chain_base == CAIP2_BITCOIN_MAINNET {
        derivation::BitcoinNetwork::Mainnet
    } else if chain_base == CAIP2_BITCOIN_TESTNET {
        derivation::BitcoinNetwork::Testnet
    } else {
        env::panic_str(&format!("Unknown Bitcoin network: {}", caip2_chain));
    };

    (network, is_p2tr)
}
