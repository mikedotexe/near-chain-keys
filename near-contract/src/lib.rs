//! NEAR Authorization Contract for TEE Keystore (Trust-Minimized Runner)
//!
//! This contract:
//! 1. Validates signed intents (MultiPayload with 7 signature types)
//! 2. Tracks nonces for replay protection (keyed by public key fingerprint)
//! 3. Stores authorization records
//! 4. Triggers OutLayer TEE execution (anyone can call run())
//! 5. Emits NEP-297 events for relayer/broadcaster integration
//!
//! Trust-minimized: No owner gates for authorization. Secrets protection via OutLayer ACLs.

use defuse_core::payload::multi::MultiPayload;
use near_sdk::base64::Engine as _;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::LookupMap;
use near_sdk::{env, ext_contract, near, AccountId, Gas, NearToken, PanicOnDefault, Promise};

use crate::authorization::{public_key_to_string, verify_intent, KeystoreAction};

mod authorization;

pub use authorization::{
    Authorization, AuthorizationId, AuthorizationStatus, KeystoreIntentMessage,
};

// ============================================================================
// CONSTANTS
// ============================================================================

const GAS_OUTLAYER: Gas = Gas::from_tgas(80);
const GAS_CALLBACK: Gas = Gas::from_tgas(40);

// ============================================================================
// OUTLAYER TYPES
// ============================================================================

/// Source of the WASM code to execute in OutLayer.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeSource {
    GitHub {
        repo: String,
        commit: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        build_target: Option<String>,
    },
    WasmUrl {
        url: String,
        hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        build_target: Option<String>,
    },
}

/// Resource limits for OutLayer execution.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct ResourceLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_execution_seconds: Option<u64>,
}

/// Reference to secrets stored in OutLayer.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct SecretsReference {
    pub profile: String,
    pub account_id: AccountId,
}

/// Response format from OutLayer.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    Text,
    Json,
    Bytes,
}

/// Arguments for OutLayer request_execution.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct RequestExecutionArgs {
    pub code_source: CodeSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_ref: Option<SecretsReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer_account_id: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<near_sdk::serde_json::Value>,
}

// ============================================================================
// EXTERNAL CONTRACTS
// ============================================================================

#[ext_contract(ext_outlayer)]
trait OutLayer {
    fn request_execution(&mut self, args: RequestExecutionArgs) -> near_sdk::serde_json::Value;
}

#[ext_contract(ext_self)]
trait SelfCallbacks {
    fn on_outlayer_complete(&mut self, run_id: u64, auth_id: AuthorizationId) -> bool;
}

// ============================================================================
// NEP-297 EVENTS
// ============================================================================

fn emit_event<T: Serialize>(event: &str, data: T) {
    let log = near_sdk::serde_json::json!({
        "standard": "chain-keys",
        "version": "1.0.0",
        "event": event,
        "data": data
    });
    env::log_str(&format!("EVENT_JSON:{}", log));
}

// ============================================================================
// CONTRACT
// ============================================================================

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    // === CONFIG (set at init, not user-controlled) ===
    /// OutLayer contract to call for TEE execution
    outlayer: AccountId,
    /// Pinned WASM code source (repo+commit or url+hash)
    code_source: CodeSource,
    /// Reference to secrets in OutLayer (profile, account)
    secrets_ref: SecretsReference,
    /// Resource limits for TEE execution
    limits: ResourceLimits,

    // === AUTH STATE ===
    /// Counter for generating authorization IDs
    next_auth_id: AuthorizationId,
    /// Active authorizations by ID
    authorizations: LookupMap<AuthorizationId, Authorization>,
    /// Used nonces: (pk_fingerprint, nonce_bytes) -> ()
    /// Keyed by public key fingerprint for robust replay protection
    used_nonces: LookupMap<(String, [u8; 32]), ()>,

    // === RUN STATE ===
    /// Counter for generating run IDs
    next_run_id: u64,
}

/// Compute a fingerprint of a public key (first 16 bytes of SHA256, hex-encoded).
fn pk_fingerprint(pk_str: &str) -> String {
    let hash = env::sha256(pk_str.as_bytes());
    hex::encode(&hash[..16])
}

#[near]
impl Contract {
    /// Initialize the contract with OutLayer configuration.
    ///
    /// These config values are NOT user-controlled - they define which TEE code
    /// can access which secrets, providing trust-minimization.
    #[init]
    pub fn new(
        outlayer: AccountId,
        code_source: CodeSource,
        secrets_ref: SecretsReference,
        limits: ResourceLimits,
    ) -> Self {
        Self {
            outlayer,
            code_source,
            secrets_ref,
            limits,
            next_auth_id: 1,
            authorizations: LookupMap::new(b"a"),
            used_nonces: LookupMap::new(b"n"),
            next_run_id: 1,
        }
    }

    // ========================================================================
    // AUTHORIZATION
    // ========================================================================

    /// Submit an authorization signed with any supported wallet type.
    ///
    /// Supports 7 signature standards via NEAR Intents MultiPayload:
    /// - NEP-413 (NEAR wallets)
    /// - ERC-191 (Ethereum/MetaMask)
    /// - TIP-191 (Tron)
    /// - Raw Ed25519 (Solana/Phantom)
    /// - WebAuthn (Passkeys)
    /// - TonConnect (TON)
    /// - SEP-53 (Stellar)
    ///
    /// Returns an AuthorizationId that can be used with run().
    pub fn submit_intent(&mut self, multi_payload: MultiPayload) -> AuthorizationId {
        // 1. Verify signature and extract payload
        let verified = verify_intent(multi_payload, &env::current_account_id())
            .unwrap_or_else(|e| env::panic_str(&format!("Intent verification failed: {}", e)));

        // 2. Key nonce by public key fingerprint (not signer_id)
        let pk_str = public_key_to_string(&verified.public_key);
        let pk_fpr = pk_fingerprint(&pk_str);
        let nonce_key = (pk_fpr.clone(), verified.payload.nonce);

        if self.used_nonces.contains_key(&nonce_key) {
            env::panic_str("Nonce has already been used");
        }

        // 3. Mark nonce as used
        self.used_nonces.insert(nonce_key, ());

        // 4. Generate authorization ID
        let auth_id = self.next_auth_id;
        self.next_auth_id += 1;

        // 5. Compute actions hash
        let actions_json = near_sdk::serde_json::to_string(&verified.payload.message.actions)
            .unwrap_or_else(|_| "[]".to_string());
        let actions_hash = env::sha256(actions_json.as_bytes());

        // 6. Store the authorization
        let authorization = Authorization {
            id: auth_id,
            signer_id: verified.payload.signer_id.to_string(),
            public_key: pk_str,
            created_at: env::block_height(),
            deadline: verified.payload.deadline.into_timestamp().timestamp() as u64,
            actions_json,
            status: AuthorizationStatus::Active,
        };

        self.authorizations.insert(auth_id, authorization);

        // 7. Emit NEP-297 event
        emit_event("authorization_created", near_sdk::serde_json::json!({
            "auth_id": auth_id,
            "signer_id": verified.payload.signer_id.to_string(),
            "pk_fingerprint": pk_fpr,
            "actions_hash": hex::encode(&actions_hash)
        }));

        auth_id
    }

    /// Revoke an authorization using a signed payload.
    ///
    /// The payload must contain a RevokeAuthorization action specifying the auth_id.
    /// This ensures the signature commits to the specific authorization being revoked.
    pub fn revoke(&mut self, multi_payload: MultiPayload) {
        // 1. Verify signature
        let verified = verify_intent(multi_payload, &env::current_account_id())
            .unwrap_or_else(|e| env::panic_str(&format!("Revocation verification failed: {}", e)));

        // 2. Extract RevokeAuthorization action from payload
        let auth_id = verified
            .payload
            .message
            .actions
            .iter()
            .find_map(|action| {
                if let KeystoreAction::RevokeAuthorization { auth_id } = action {
                    Some(*auth_id)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| env::panic_str("Payload must contain RevokeAuthorization action"));

        // 3. Load authorization
        let mut auth = self
            .authorizations
            .get(&auth_id)
            .cloned()
            .unwrap_or_else(|| env::panic_str("Authorization not found"));

        // 4. Verify the revoker is the original signer (compare public keys)
        let revoker_pk = public_key_to_string(&verified.public_key);
        if revoker_pk != auth.public_key {
            env::panic_str("Only the original signer can revoke this authorization");
        }

        // 5. Check authorization is active
        if !matches!(auth.status, AuthorizationStatus::Active) {
            env::panic_str("Authorization is not active");
        }

        // 6. Mark as revoked
        auth.status = AuthorizationStatus::Revoked {
            revoked_at: env::block_height(),
        };
        self.authorizations.insert(auth_id, auth);

        // 7. Emit NEP-297 event
        emit_event("authorization_revoked", near_sdk::serde_json::json!({
            "auth_id": auth_id,
            "revoked_by": pk_fingerprint(&revoker_pk)
        }));
    }

    // ========================================================================
    // ADDRESS DISCOVERY (no authorization required)
    // ========================================================================

    /// Get the derived address for an account on a chain.
    ///
    /// This is the first step in the UX flow - users need to know their address
    /// before they can fund it. No authorization required since this is public
    /// information (deterministically derived from account_id + chain_id).
    ///
    /// Caller must attach a small deposit to cover OutLayer execution costs.
    #[payable]
    pub fn get_address(&mut self, account_id: AccountId, chain_id: String) -> Promise {
        let deposit = env::attached_deposit();
        if deposit == NearToken::from_yoctonear(0) {
            env::panic_str("Attach deposit for OutLayer execution");
        }

        // Build minimal input for get_address operation
        let input_data = near_sdk::serde_json::json!({
            "operation": "get_address",
            "account_id": account_id.to_string(),
            "chain_id": chain_id
        });

        let args = RequestExecutionArgs {
            code_source: self.code_source.clone(),
            resource_limits: Some(self.limits.clone()),
            input_data: Some(input_data.to_string()),
            secrets_ref: Some(self.secrets_ref.clone()),
            response_format: Some(ResponseFormat::Json),
            payer_account_id: Some(env::predecessor_account_id()),
            params: None,
        };

        // Call OutLayer - result returned directly (no callback state to update)
        ext_outlayer::ext(self.outlayer.clone())
            .with_attached_deposit(deposit)
            .with_static_gas(GAS_OUTLAYER)
            .request_execution(args)
    }

    // ========================================================================
    // EXECUTION (anyone can call)
    // ========================================================================

    /// Trigger TEE execution for an authorization.
    ///
    /// Anyone can call this method - the authorization controls what gets executed.
    /// Caller must attach deposit to pay for OutLayer execution.
    ///
    /// tx_params: Transaction parameters passed to TEE (not stored on-chain).
    /// The TEE validates tx_params against the authorization policy.
    #[payable]
    pub fn run(&mut self, auth_id: AuthorizationId, tx_params: Vec<u8>) -> Promise {
        // 1. Load and validate authorization
        let auth = self
            .authorizations
            .get(&auth_id)
            .cloned()
            .unwrap_or_else(|| env::panic_str("Authorization not found"));

        match auth.status {
            AuthorizationStatus::Active => {}
            AuthorizationStatus::Consumed { .. } => {
                env::panic_str("Authorization already consumed")
            }
            AuthorizationStatus::Revoked { .. } => {
                env::panic_str("Authorization has been revoked")
            }
            AuthorizationStatus::Expired => {
                env::panic_str("Authorization has expired")
            }
        }

        // 2. Check deadline
        let current_time_secs = env::block_timestamp() / 1_000_000_000;
        if auth.deadline > 0 && current_time_secs > auth.deadline {
            // Mark as expired
            let mut auth_mut = auth.clone();
            auth_mut.status = AuthorizationStatus::Expired;
            self.authorizations.insert(auth_id, auth_mut);
            env::panic_str("Authorization has expired");
        }

        // 3. Caller pays for execution
        let payer = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        if deposit == NearToken::from_yoctonear(0) {
            env::panic_str("Attach deposit for OutLayer execution");
        }

        // 4. Generate run ID
        let run_id = self.next_run_id;
        self.next_run_id += 1;

        // 5. Build input_data from authorization + tx_params
        // Contract constructs this - caller cannot widen policy
        let input_data = near_sdk::serde_json::json!({
            "run_id": run_id,
            "auth_id": auth_id,
            "authorization": {
                "signer_id": auth.signer_id,
                "public_key": auth.public_key,
                "actions": auth.actions_json,
                "deadline": auth.deadline
            },
            "tx_params": near_sdk::base64::engine::general_purpose::STANDARD.encode(&tx_params)
        });

        // 6. Build OutLayer request
        let args = RequestExecutionArgs {
            code_source: self.code_source.clone(),
            resource_limits: Some(self.limits.clone()),
            input_data: Some(input_data.to_string()),
            secrets_ref: Some(self.secrets_ref.clone()),
            response_format: Some(ResponseFormat::Json),
            payer_account_id: Some(payer.clone()),
            params: None,
        };

        // 7. Emit run_started event
        emit_event("run_started", near_sdk::serde_json::json!({
            "run_id": run_id,
            "auth_id": auth_id,
            "payer": payer.to_string()
        }));

        // 8. Call OutLayer
        ext_outlayer::ext(self.outlayer.clone())
            .with_attached_deposit(deposit)
            .with_static_gas(GAS_OUTLAYER)
            .request_execution(args)
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(GAS_CALLBACK)
                    .on_outlayer_complete(run_id, auth_id),
            )
    }

    /// Callback from OutLayer execution.
    #[private]
    pub fn on_outlayer_complete(&mut self, run_id: u64, auth_id: AuthorizationId) -> bool {
        let result = match env::promise_result(0) {
            near_sdk::PromiseResult::Successful(bytes) => bytes,
            _ => {
                emit_event("run_failed", near_sdk::serde_json::json!({
                    "run_id": run_id,
                    "auth_id": auth_id,
                    "error": "OutLayer execution failed"
                }));
                return false;
            }
        };

        // Parse result (treat as untrusted)
        let result_json: near_sdk::serde_json::Value =
            near_sdk::serde_json::from_slice(&result).unwrap_or(near_sdk::serde_json::Value::Null);

        // Mark authorization as consumed
        if let Some(mut auth) = self.authorizations.get(&auth_id).cloned() {
            auth.status = AuthorizationStatus::Consumed {
                consumed_at: env::block_height(),
            };
            self.authorizations.insert(auth_id, auth);
        }

        // Emit run_completed event (relayer/broadcaster watches this)
        emit_event("run_completed", near_sdk::serde_json::json!({
            "run_id": run_id,
            "auth_id": auth_id,
            "result": result_json
        }));

        true
    }

    // ========================================================================
    // VIEWS
    // ========================================================================

    /// Check if a nonce has been used for a given public key fingerprint.
    pub fn is_nonce_used(&self, pk_fingerprint: String, nonce: [u8; 32]) -> bool {
        self.used_nonces.contains_key(&(pk_fingerprint, nonce))
    }

    /// Get an authorization by ID.
    pub fn get_authorization(&self, auth_id: AuthorizationId) -> Option<Authorization> {
        self.authorizations.get(&auth_id).cloned()
    }

    /// Get contract configuration (for verification).
    pub fn get_config(&self) -> near_sdk::serde_json::Value {
        near_sdk::serde_json::json!({
            "outlayer": self.outlayer.to_string(),
            "code_source": self.code_source,
            "secrets_ref": self.secrets_ref,
            "limits": self.limits
        })
    }
}
