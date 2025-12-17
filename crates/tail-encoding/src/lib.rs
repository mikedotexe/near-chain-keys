//! # tail-encoding
//!
//! Self-describing encoding where the **tail reveals metadata** about the encoding:
//! - Base system (58, 64, 32) via magic residues
//! - Sign (positive/negative)
//! - Checksum
//!
//! ## Core Insight
//!
//! Different bases have different "vanishing moduli":
//!
//! | Base | Factorization | Property |
//! |------|---------------|----------|
//! | 58   | 2 × 29        | 58 ≡ 0 (mod 29) → last char determines value mod 29 |
//! | 64   | 2^6           | 64 ≡ 6 (mod 29) → doesn't vanish |
//! | 32   | 2^5           | 32 ≡ 3 (mod 29) → doesn't vanish |
//!
//! This enables O(1) base detection from the tail.

pub mod residue;
pub mod encode;
pub mod decode;
pub mod tail_extract;
pub mod layered;
pub mod fraction;
pub mod optimal_base;
pub mod error_correction;
pub mod signature;
pub mod caip;
pub mod key_derivation;

pub use residue::{DetectedBase, detect_base, TailResidue};
pub use encode::{encode_base58, encode_base64, encode_base32, Sign};
pub use decode::{decode, TailMetadata, DecodeError};
pub use tail_extract::{extract_o1, TailExtract, tail_mod_8, tail_mod_29, tail_mod_232};
pub use layered::{extract_layered, LayeredMeta, extract_mod_29, compute_mod_41};
pub use fraction::{Fraction, encode_fraction, decode_fraction, DecodedFraction};
pub use optimal_base::{
    encode_terminating, decode_terminating, DecodedTerminating,
    optimal_supported_base, fraction_digits, terminates_in_base,
};
pub use error_correction::{
    suggest_correction, detect_error, localize_error,
    expected_checksum, compute_expected_residues,
    ErrorDetection, LocalizedError, Correction,
};
pub use signature::{
    Curve, SigFormat, SignatureMeta, DecodedSignature,
    encode_signature, encode_signature_with_pubkey, encode_signature_with_pubkey_and_recovery,
    decode_signature, decode_signature_full, extract_signature_meta,
    ED25519_PUBKEY_SIZE, BLS12_381_PUBKEY_SIZE, ECDSA_COMPRESSED_PUBKEY_SIZE,
};
pub use caip::{
    CaipNamespace, CaipType, Caip2, Caip10, CaipMeta, CaipDecodeError, CaipValidation,
    encode_caip10, encode_caip2, decode_caip10, decode_caip2,
    extract_caip_meta, validate_caip_compact, parse_and_encode_caip10,
};
pub use key_derivation::{
    PubKey, ResolveError, EthereumAddresses, BitcoinAddresses, ResolvedAddresses,
    Caip10Addresses, resolve, resolve_caip10, resolve_caip10_standard,
    ethereum_addresses_from_secp256k1, bitcoin_addresses_from_secp256k1,
    solana_address_from_ed25519, near_implicit_from_ed25519, to_eip55,
    BitcoinNetwork, BTC_MAINNET_GENESIS,
    // CAIP-2 chain ID constants
    CAIP2_BITCOIN_MAINNET, CAIP2_BITCOIN_TESTNET,
    CAIP2_SOLANA_MAINNET, CAIP2_SOLANA_DEVNET, CAIP2_SOLANA_TESTNET,
    CAIP2_ETHEREUM_MAINNET, CAIP2_NEAR_MAINNET, CAIP2_NEAR_TESTNET,
    // CAIP-10 helpers
    caip10, caip10_eip155,
};
