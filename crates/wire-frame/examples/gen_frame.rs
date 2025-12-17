//! Generate a test wire-frame payload to stdout.
//!
//! Usage:
//!   cargo run -p wire-frame --example gen_frame -- solana
//!   cargo run -p wire-frame --example gen_frame -- near | xxd
//!   cargo run -p wire-frame --example gen_frame -- ethereum | curl -X POST --data-binary @- http://localhost:3000/broadcast/bin

use std::io::Write;
use wire_frame::{frame, Namespace};

fn main() {
    let chain = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: gen_frame <chain>");
        eprintln!("Chains: ethereum, solana, bitcoin, near, cosmos, starknet, polkadot");
        std::process::exit(1);
    });

    let ns = match chain.as_str() {
        "ethereum" | "eip155" => Namespace::Eip155,
        "bitcoin" | "bip122" => Namespace::Bip122,
        "cosmos" => Namespace::Cosmos,
        "solana" => Namespace::Solana,
        "polkadot" => Namespace::Polkadot,
        "near" => Namespace::Near,
        "starknet" => Namespace::Starknet,
        _ => {
            eprintln!("Unknown chain: {}", chain);
            eprintln!("Chains: ethereum, solana, bitcoin, near, cosmos, starknet, polkadot");
            std::process::exit(1);
        }
    };

    let payload = format!("test payload for {}", chain);
    let chain_ref = [0u8; 32]; // mainnet placeholder

    let framed = frame(ns, &chain_ref, payload.as_bytes());

    std::io::stdout().write_all(&framed).unwrap();

    eprintln!(
        "Generated {} byte frame for {} (payload: {} bytes)",
        framed.len(),
        chain,
        payload.len()
    );
}
