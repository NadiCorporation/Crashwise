pub mod routes;
pub mod state;

pub use routes::create_router;
pub use state::AppState;
use std::net::SocketAddr;
use tracing::info;

pub async fn run_server(state: AppState, addr: SocketAddr) -> anyhow::Result<()> {
    let app = create_router(state);
    info!("CrashWise Server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
