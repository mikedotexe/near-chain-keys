//! High-throughput multi-chain router with O(1) tail-based routing.

mod queue;
mod routes;

use axum::{
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc};

use queue::ChainQueues;
use routes::{broadcast, broadcast_bin, health, queues};

#[tokio::main]
async fn main() {
    let state = Arc::new(ChainQueues::new(100_000));

    let app = Router::new()
        .route("/broadcast", post(broadcast))
        .route("/broadcast/bin", post(broadcast_bin))
        .route("/health", get(health))
        .route("/queues", get(queues))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Starting server on http://{}", addr);
    println!();
    println!("Endpoints:");
    println!("  POST /broadcast      - CAIP-compact text payload");
    println!("  POST /broadcast/bin  - Binary wire-frame payload");
    println!("  GET  /health         - Liveness check");
    println!("  GET  /queues         - Queue depths per chain");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
