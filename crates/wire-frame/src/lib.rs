//! Binary framing for cross-chain payload routing.
//!
//! Frame layout:
//! ```text
//! [ payload (variable) ][ trailer (34 bytes) ][ tag (8 bytes) ]
//! ```
//!
//! - **Trailer**: namespace (1) + chain_ref (32) + version (1) = 34 bytes
//! - **Tag**: blake3(payload || trailer) truncated to 8 bytes
//!
//! Total fixed overhead: 42 bytes.
//!
//! # Example
//!
//! ```
//! use wire_frame::{Namespace, frame, parse, peek_namespace};
//!
//! // Frame a contract deployment
//! let bytecode = vec![0x60, 0x80, 0x60, 0x40]; // EVM initcode snippet
//! let chain_ref = [0u8; 32]; // mainnet (chain ID 1, padded)
//! let framed = frame(Namespace::Eip155, &chain_ref, &bytecode);
//!
//! // Peek namespace without full parse (O(1) routing)
//! assert_eq!(peek_namespace(&framed), Some(Namespace::Eip155));
//!
//! // Full parse with tag verification
//! let parsed = parse(&framed).unwrap();
//! assert_eq!(parsed.namespace, Namespace::Eip155);
//! assert_eq!(parsed.payload, &bytecode[..]);
//! ```

/// Frame overhead: trailer (34) + tag (8) = 42 bytes.
pub const OVERHEAD: usize = TRAILER_SIZE + TAG_SIZE;
const TRAILER_SIZE: usize = 34;
const TAG_SIZE: usize = 8;

// ============================================================================
// NAMESPACE
// ============================================================================

/// Chain namespace identifiers.
///
/// Matches CAIP namespaces, encoded as single byte for binary efficiency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Namespace {
    /// EIP-155 compatible chains (Ethereum, Polygon, Arbitrum, etc.)
    Eip155 = 0,
    /// BIP-122 Bitcoin-like chains
    Bip122 = 1,
    /// Cosmos SDK chains
    Cosmos = 2,
    /// Solana
    Solana = 3,
    /// Polkadot / Kusama
    Polkadot = 4,
    /// NEAR Protocol
    Near = 5,
    /// StarkNet
    Starknet = 6,
}

impl Namespace {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Eip155),
            1 => Some(Self::Bip122),
            2 => Some(Self::Cosmos),
            3 => Some(Self::Solana),
            4 => Some(Self::Polkadot),
            5 => Some(Self::Near),
            6 => Some(Self::Starknet),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eip155 => "eip155",
            Self::Bip122 => "bip122",
            Self::Cosmos => "cosmos",
            Self::Solana => "solana",
            Self::Polkadot => "polkadot",
            Self::Near => "near",
            Self::Starknet => "starknet",
        }
    }
}

// ============================================================================
// FRAME ENCODING
// ============================================================================

/// Create a framed payload.
///
/// Returns: `payload || trailer || tag`
pub fn frame(namespace: Namespace, chain_ref: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    frame_versioned(namespace, chain_ref, payload, 0)
}

/// Create a framed payload with explicit version.
pub fn frame_versioned(
    namespace: Namespace,
    chain_ref: &[u8; 32],
    payload: &[u8],
    version: u8,
) -> Vec<u8> {
    let trailer = build_trailer(namespace, chain_ref, version);
    let tag = compute_tag(payload, &trailer);

    let mut out = Vec::with_capacity(payload.len() + OVERHEAD);
    out.extend_from_slice(payload);
    out.extend_from_slice(&trailer);
    out.extend_from_slice(&tag);
    out
}

fn build_trailer(namespace: Namespace, chain_ref: &[u8; 32], version: u8) -> [u8; TRAILER_SIZE] {
    let mut trailer = [0u8; TRAILER_SIZE];
    trailer[0] = namespace as u8;
    trailer[1..33].copy_from_slice(chain_ref);
    trailer[33] = version;
    trailer
}

fn compute_tag(payload: &[u8], trailer: &[u8; TRAILER_SIZE]) -> [u8; TAG_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(payload);
    hasher.update(trailer);
    let hash = hasher.finalize();
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&hash.as_bytes()[..TAG_SIZE]);
    tag
}

// ============================================================================
// FRAME PARSING
// ============================================================================

/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Frame too short to contain trailer + tag.
    TooShort { len: usize, min: usize },
    /// Unknown namespace byte.
    UnknownNamespace(u8),
    /// Tag mismatch (integrity check failed).
    BadTag,
}

/// Parsed frame (zero-copy view into original bytes).
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub namespace: Namespace,
    pub chain_ref: &'a [u8; 32],
    pub version: u8,
    pub payload: &'a [u8],
}

/// Parse a framed payload with tag verification.
pub fn parse(data: &[u8]) -> Result<Frame<'_>, ParseError> {
    if data.len() < OVERHEAD {
        return Err(ParseError::TooShort {
            len: data.len(),
            min: OVERHEAD,
        });
    }

    let payload_end = data.len() - OVERHEAD;
    let trailer_start = payload_end;
    let tag_start = data.len() - TAG_SIZE;

    let payload = &data[..payload_end];
    let trailer: &[u8; TRAILER_SIZE] = data[trailer_start..tag_start].try_into().unwrap();
    let tag: &[u8; TAG_SIZE] = data[tag_start..].try_into().unwrap();

    // Verify tag
    let expected_tag = compute_tag(payload, trailer);
    if tag != &expected_tag {
        return Err(ParseError::BadTag);
    }

    // Parse trailer
    let namespace = Namespace::from_u8(trailer[0])
        .ok_or(ParseError::UnknownNamespace(trailer[0]))?;
    let chain_ref: &[u8; 32] = trailer[1..33].try_into().unwrap();
    let version = trailer[33];

    Ok(Frame {
        namespace,
        chain_ref,
        version,
        payload,
    })
}

/// Parse without tag verification (for untrusted quick inspection).
pub fn parse_unchecked(data: &[u8]) -> Result<Frame<'_>, ParseError> {
    if data.len() < OVERHEAD {
        return Err(ParseError::TooShort {
            len: data.len(),
            min: OVERHEAD,
        });
    }

    let payload_end = data.len() - OVERHEAD;
    let trailer_start = payload_end;
    let tag_start = data.len() - TAG_SIZE;

    let payload = &data[..payload_end];
    let trailer: &[u8; TRAILER_SIZE] = data[trailer_start..tag_start].try_into().unwrap();

    let namespace = Namespace::from_u8(trailer[0])
        .ok_or(ParseError::UnknownNamespace(trailer[0]))?;
    let chain_ref: &[u8; 32] = trailer[1..33].try_into().unwrap();
    let version = trailer[33];

    Ok(Frame {
        namespace,
        chain_ref,
        version,
        payload,
    })
}

// ============================================================================
// QUICK ROUTING (O(1))
// ============================================================================

/// Peek namespace from frame without full parse.
///
/// Returns `None` if frame is too short or namespace is unknown.
/// Does NOT verify tag - use for routing only, not trust.
#[inline]
pub fn peek_namespace(data: &[u8]) -> Option<Namespace> {
    if data.len() < OVERHEAD {
        return None;
    }
    let ns_byte = data[data.len() - OVERHEAD];
    Namespace::from_u8(ns_byte)
}

/// Peek chain_ref from frame without full parse.
#[inline]
pub fn peek_chain_ref(data: &[u8]) -> Option<&[u8; 32]> {
    if data.len() < OVERHEAD {
        return None;
    }
    let start = data.len() - OVERHEAD + 1;
    let end = start + 32;
    Some(data[start..end].try_into().unwrap())
}

/// Verify tag without full parse.
#[inline]
pub fn verify_tag(data: &[u8]) -> bool {
    if data.len() < OVERHEAD {
        return false;
    }

    let payload_end = data.len() - OVERHEAD;
    let trailer_start = payload_end;
    let tag_start = data.len() - TAG_SIZE;

    let payload = &data[..payload_end];
    let trailer: &[u8; TRAILER_SIZE] = match data[trailer_start..tag_start].try_into() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let tag: &[u8; TAG_SIZE] = match data[tag_start..].try_into() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let expected = compute_tag(payload, trailer);
    tag == &expected
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let payload = b"hello world";
        let chain_ref = [1u8; 32];

        let framed = frame(Namespace::Near, &chain_ref, payload);

        assert_eq!(framed.len(), payload.len() + OVERHEAD);

        let parsed = parse(&framed).unwrap();
        assert_eq!(parsed.namespace, Namespace::Near);
        assert_eq!(parsed.chain_ref, &chain_ref);
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_peek_namespace() {
        let payload = vec![0u8; 1000];
        let chain_ref = [0u8; 32];

        for ns in [
            Namespace::Eip155,
            Namespace::Bip122,
            Namespace::Solana,
            Namespace::Near,
        ] {
            let framed = frame(ns, &chain_ref, &payload);
            assert_eq!(peek_namespace(&framed), Some(ns));
        }
    }

    #[test]
    fn test_peek_chain_ref() {
        let payload = b"test";
        let chain_ref = [42u8; 32];

        let framed = frame(Namespace::Eip155, &chain_ref, payload);
        assert_eq!(peek_chain_ref(&framed), Some(&chain_ref));
    }

    #[test]
    fn test_verify_tag() {
        let payload = b"contract bytecode here";
        let chain_ref = [0u8; 32];

        let framed = frame(Namespace::Solana, &chain_ref, payload);
        assert!(verify_tag(&framed));

        // Corrupt one byte
        let mut corrupted = framed.clone();
        corrupted[5] ^= 0xff;
        assert!(!verify_tag(&corrupted));
    }

    #[test]
    fn test_bad_tag_rejected() {
        let payload = b"test payload";
        let chain_ref = [0u8; 32];

        let mut framed = frame(Namespace::Near, &chain_ref, payload);

        // Corrupt payload
        framed[0] ^= 0xff;

        let result = parse(&framed);
        assert_eq!(result, Err(ParseError::BadTag));
    }

    #[test]
    fn test_too_short() {
        let short = vec![0u8; 10];
        assert_eq!(
            parse(&short),
            Err(ParseError::TooShort { len: 10, min: OVERHEAD })
        );
        assert_eq!(peek_namespace(&short), None);
    }

    #[test]
    fn test_unknown_namespace() {
        let payload = b"test";
        let mut framed = frame(Namespace::Near, &[0u8; 32], payload);

        // Set namespace to invalid value
        let ns_pos = framed.len() - OVERHEAD;
        framed[ns_pos] = 99;

        // parse() checks tag first, so we get BadTag
        assert_eq!(parse(&framed), Err(ParseError::BadTag));

        // parse_unchecked() skips tag, so we get UnknownNamespace
        assert_eq!(parse_unchecked(&framed), Err(ParseError::UnknownNamespace(99)));
    }

    #[test]
    fn test_versioned() {
        let payload = b"versioned payload";
        let chain_ref = [0u8; 32];

        let framed = frame_versioned(Namespace::Cosmos, &chain_ref, payload, 42);
        let parsed = parse(&framed).unwrap();

        assert_eq!(parsed.version, 42);
    }

    #[test]
    fn test_large_payload() {
        // Simulate a 100KB WASM contract
        let payload = vec![0xDE; 100_000];
        let chain_ref = [0u8; 32];

        let framed = frame(Namespace::Near, &chain_ref, &payload);

        assert_eq!(framed.len(), 100_000 + OVERHEAD);
        assert_eq!(peek_namespace(&framed), Some(Namespace::Near));
        assert!(verify_tag(&framed));

        let parsed = parse(&framed).unwrap();
        assert_eq!(parsed.payload.len(), 100_000);
    }

    #[test]
    fn test_empty_payload() {
        let payload = b"";
        let chain_ref = [0u8; 32];

        let framed = frame(Namespace::Eip155, &chain_ref, payload);
        assert_eq!(framed.len(), OVERHEAD);

        let parsed = parse(&framed).unwrap();
        assert_eq!(parsed.payload.len(), 0);
    }

    #[test]
    fn test_all_namespaces() {
        let namespaces = [
            (Namespace::Eip155, "eip155"),
            (Namespace::Bip122, "bip122"),
            (Namespace::Cosmos, "cosmos"),
            (Namespace::Solana, "solana"),
            (Namespace::Polkadot, "polkadot"),
            (Namespace::Near, "near"),
            (Namespace::Starknet, "starknet"),
        ];

        for (ns, name) in namespaces {
            assert_eq!(ns.as_str(), name);
            assert_eq!(Namespace::from_u8(ns as u8), Some(ns));
        }
    }
}
