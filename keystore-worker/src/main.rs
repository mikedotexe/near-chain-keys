//! TEE worker for chain-keys keystore.
//!
//! Runs inside OutLayer TEE (WASI Preview 1):
//! - Receives requests from stdin (sign or get_address)
//! - Derives keys via HKDF from master secret (env var)
//! - Returns results to stdout
//!
//! Operations:
//! - get_address: Derive and return public key/address for an account+chain
//! - sign: Sign a transaction (requires authorization)

mod derivation;
mod input;
mod output;
mod policy;
mod signing;

use input::WorkerRequest;
use std::io::{self, Read, Write};

fn main() {
    let result = run();
    let output = match result {
        Ok(response) => response,
        Err(e) => output::error_response(0, 0, &e),
    };

    // OutLayer requires explicit flush
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(output.as_bytes());
    let _ = handle.flush();
}

fn run() -> Result<String, String> {
    // 1. Read input from stdin
    let mut input_str = String::new();
    io::stdin()
        .read_to_string(&mut input_str)
        .map_err(|e| format!("Failed to read stdin: {}", e))?;

    // 2. Parse request and dispatch by operation
    let request = input::parse_request(&input_str)?;

    match request {
        WorkerRequest::GetAddress(req) => run_get_address(req),
        WorkerRequest::Sign(req) => run_sign(req),
    }
}

/// Handle get_address operation - derive and return public key.
fn run_get_address(req: input::GetAddressInput) -> Result<String, String> {
    // 1. Validate chain_id format
    policy::validate_chain_id(&req.chain_id)?;

    // 2. Load master secret
    let master_secret = derivation::load_master_secret()?;

    // 3. Derive signing key
    let signing_key = derivation::derive_signing_key(&master_secret, &req.account_id, &req.chain_id);

    // 4. Get public key from signing key
    let public_key = derivation::get_public_key(&signing_key, &req.chain_id)?;

    // 5. Format address (chain-specific)
    let address = derivation::format_address(&public_key, &req.chain_id);

    // 6. Return response
    Ok(output::address_response(
        &req.account_id,
        &req.chain_id,
        &public_key,
        &address,
    ))
}

/// Handle sign operation - sign a transaction.
fn run_sign(input: input::SignInput) -> Result<String, String> {
    // 1. Load master secret from environment
    let master_secret = derivation::load_master_secret()?;

    // 2. Extract chain_id from authorization actions
    let chain_id = input::extract_chain_id(&input)?;

    // 3. Validate policy (chain matches, deadline not passed)
    policy::validate(&input, &chain_id)?;

    // 4. Derive signing key
    let signing_key = derivation::derive_signing_key(
        &master_secret,
        &input.authorization.signer_id,
        &chain_id,
    );

    // 5. Sign based on chain type
    let (public_key, signature) = signing::sign(&signing_key, &chain_id, &input.tx_params)?;

    // 6. Format output
    Ok(output::success_response(
        input.run_id,
        input.auth_id,
        &chain_id,
        &public_key,
        &signature,
    ))
}
