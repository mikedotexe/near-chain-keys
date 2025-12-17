//! HTTP route handlers for the multi-chain router.

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use tail_encoding::extract_caip_meta;
use wire_frame::{peek_namespace, verify_tag, Namespace};

use crate::queue::{caip_to_wire, ChainQueues, PushError, QueueDepths};

pub type AppState = Arc<ChainQueues>;

// ============================================================================
// RESPONSE TYPES
// ============================================================================

#[derive(serde::Serialize)]
pub struct BroadcastResponse {
    pub chain: String,
    pub queue_position: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_size: Option<usize>,
}

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(serde::Serialize)]
pub struct HealthResponse {
    pub status: String,
}

// ============================================================================
// TEXT ENDPOINT (CAIP-compact)
// ============================================================================

/// POST /broadcast
///
/// Accepts CAIP-compact encoded payload (text body).
/// Extracts chain from tail character in O(1).
pub async fn broadcast(
    State(queues): State<AppState>,
    payload: String,
) -> Result<Json<BroadcastResponse>, (StatusCode, Json<ErrorResponse>)> {
    // O(1) extract namespace from tail character
    let meta = extract_caip_meta(&payload).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid payload: could not extract CAIP metadata from tail".to_string(),
            }),
        )
    })?;

    let namespace = caip_to_wire(meta.namespace).ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: format!("Unsupported namespace: {:?}", meta.namespace),
            }),
        )
    })?;

    // Convert to bytes and queue
    let bytes = payload.into_bytes();
    let position = push_to_queue(&queues, namespace, bytes).await?;

    Ok(Json(BroadcastResponse {
        chain: namespace.as_str().to_string(),
        queue_position: position,
        payload_size: None,
    }))
}

// ============================================================================
// BINARY ENDPOINT (wire-frame)
// ============================================================================

/// POST /broadcast/bin
///
/// Accepts binary wire-frame payload (application/octet-stream).
/// Peeks namespace from trailer in O(1), verifies tag.
pub async fn broadcast_bin(
    State(queues): State<AppState>,
    body: Bytes,
) -> Result<Json<BroadcastResponse>, (StatusCode, Json<ErrorResponse>)> {
    // O(1) peek namespace from trailer
    let namespace = peek_namespace(&body).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid frame: could not extract namespace from trailer".to_string(),
            }),
        )
    })?;

    // Verify tag (cheap blake3)
    if !verify_tag(&body) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid frame: tag verification failed".to_string(),
            }),
        ));
    }

    let payload_size = body.len();
    let position = push_to_queue(&queues, namespace, body.to_vec()).await?;

    Ok(Json(BroadcastResponse {
        chain: namespace.as_str().to_string(),
        queue_position: position,
        payload_size: Some(payload_size),
    }))
}

// ============================================================================
// SHARED HELPERS
// ============================================================================

async fn push_to_queue(
    queues: &ChainQueues,
    namespace: Namespace,
    payload: Vec<u8>,
) -> Result<usize, (StatusCode, Json<ErrorResponse>)> {
    queues.push(namespace, payload).await.map_err(|e| match e {
        PushError::Full { max_len } => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!("Queue full (max_len={}) for namespace {:?}", max_len, namespace),
            }),
        ),
    })
}

// ============================================================================
// UTILITY ENDPOINTS
// ============================================================================

/// GET /health
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// GET /queues
pub async fn queues(State(queues): State<AppState>) -> Json<QueueDepths> {
    Json(queues.depths().await)
}
