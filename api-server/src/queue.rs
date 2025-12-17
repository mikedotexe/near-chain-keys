//! In-memory queue stubs for chain-specific payloads.

use std::collections::VecDeque;
use tokio::sync::Mutex;

use wire_frame::Namespace;

#[derive(Debug)]
pub enum PushError {
    Full { max_len: usize },
}

/// Per-chain message queues (bounded).
///
/// Stores raw bytes internally. Both text and binary payloads
/// are normalized to bytes before queuing.
pub struct ChainQueues {
    max_len: usize,

    ethereum: Mutex<VecDeque<Vec<u8>>>,
    solana: Mutex<VecDeque<Vec<u8>>>,
    bitcoin: Mutex<VecDeque<Vec<u8>>>,
    near: Mutex<VecDeque<Vec<u8>>>,
    cosmos: Mutex<VecDeque<Vec<u8>>>,
    starknet: Mutex<VecDeque<Vec<u8>>>,
    polkadot: Mutex<VecDeque<Vec<u8>>>,
}

impl ChainQueues {
    pub fn new(max_len: usize) -> Self {
        Self {
            max_len,
            ethereum: Mutex::new(VecDeque::new()),
            solana: Mutex::new(VecDeque::new()),
            bitcoin: Mutex::new(VecDeque::new()),
            near: Mutex::new(VecDeque::new()),
            cosmos: Mutex::new(VecDeque::new()),
            starknet: Mutex::new(VecDeque::new()),
            polkadot: Mutex::new(VecDeque::new()),
        }
    }

    pub async fn push(&self, namespace: Namespace, payload: Vec<u8>) -> Result<usize, PushError> {
        let m = match namespace {
            Namespace::Eip155 => &self.ethereum,
            Namespace::Solana => &self.solana,
            Namespace::Bip122 => &self.bitcoin,
            Namespace::Near => &self.near,
            Namespace::Cosmos => &self.cosmos,
            Namespace::Starknet => &self.starknet,
            Namespace::Polkadot => &self.polkadot,
        };

        let mut q = m.lock().await;
        if q.len() >= self.max_len {
            return Err(PushError::Full { max_len: self.max_len });
        }

        q.push_back(payload);
        Ok(q.len())
    }

    pub async fn depths(&self) -> QueueDepths {
        QueueDepths {
            ethereum: self.ethereum.lock().await.len(),
            solana: self.solana.lock().await.len(),
            bitcoin: self.bitcoin.lock().await.len(),
            near: self.near.lock().await.len(),
            cosmos: self.cosmos.lock().await.len(),
            starknet: self.starknet.lock().await.len(),
            polkadot: self.polkadot.lock().await.len(),
        }
    }
}

#[derive(serde::Serialize)]
pub struct QueueDepths {
    pub ethereum: usize,
    pub solana: usize,
    pub bitcoin: usize,
    pub near: usize,
    pub cosmos: usize,
    pub starknet: usize,
    pub polkadot: usize,
}

/// Map tail-encoding CaipNamespace to wire-frame Namespace.
pub fn caip_to_wire(caip: tail_encoding::CaipNamespace) -> Option<Namespace> {
    match caip {
        tail_encoding::CaipNamespace::Eip155 => Some(Namespace::Eip155),
        tail_encoding::CaipNamespace::Bip122 => Some(Namespace::Bip122),
        tail_encoding::CaipNamespace::Cosmos => Some(Namespace::Cosmos),
        tail_encoding::CaipNamespace::Solana => Some(Namespace::Solana),
        tail_encoding::CaipNamespace::Polkadot => Some(Namespace::Polkadot),
        tail_encoding::CaipNamespace::Near => Some(Namespace::Near),
        tail_encoding::CaipNamespace::Starknet => Some(Namespace::Starknet),
        tail_encoding::CaipNamespace::Reserved7 => None,
    }
}
