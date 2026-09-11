use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use crashwise_core::models::{Campaign, CampaignStatus, CampaignTarget, CrashRecord, FuzzerEngine, TelemetrySnapshot};
use futures::stream::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/api/campaigns", get(list_campaigns))
        .route("/api/campaigns/start", post(start_campaign))
        .route("/api/campaigns/stop-all", post(stop_all_campaigns))
        .route("/api/campaigns/:id/stop", post(stop_campaign))
        .route("/api/crashes", get(list_crashes))
        .route("/api/v1/telemetry/stream", get(telemetry_stream))
        .route("/api/telemetry/stream", get(telemetry_stream))
        .route("/api/logs/stream", get(logs_stream))
        .with_state(state)
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "engine": "CrashWise Next-Gen (Operation Megabits)",
        "version": "0.2.0-dev"
    }))
}

async fn list_campaigns(State(state): State<AppState>) -> Result<Json<Vec<Campaign>>, StatusCode> {
    state
        .db
        .list_campaigns()
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Debug, Deserialize)]
pub struct StartCampaignRequest {
    pub target_repo: String,
    pub target_name: String,
    pub target_subdir: Option<String>,
    pub fuzzer_engine: Option<FuzzerEngine>,
    pub timeout_seconds: Option<u64>,
}

async fn start_campaign(
    State(state): State<AppState>,
    Json(payload): Json<StartCampaignRequest>,
) -> Result<Json<Campaign>, StatusCode> {
    let target = CampaignTarget {
        repo_url: payload.target_repo,
        name: payload.target_name,
        subdir: payload.target_subdir,
        clone_depth: 1,
        commit_hash: None,
    };

    let campaign = Campaign::new(
        target,
        payload.fuzzer_engine.unwrap_or(FuzzerEngine::Libfuzzer),
        payload.timeout_seconds.unwrap_or(300),
        5,
    );

    state
        .db
        .insert_campaign(&campaign)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = state.logs_tx.send(format!(
        "[{}] Campaign {} for '{}' created and queued for execution.",
        chrono::Utc::now().to_rfc3339(),
        campaign.id,
        campaign.target.name
    ));

    Ok(Json(campaign))
}

async fn stop_campaign(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    state
        .db
        .update_campaign_status(id, CampaignStatus::Cancelled)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = state.logs_tx.send(format!(
        "[{}] Campaign {} force-stopped by operator.",
        chrono::Utc::now().to_rfc3339(),
        id
    ));

    Ok(Json(serde_json::json!({
        "ok": true,
        "campaign_id": id,
        "message": format!("Campaign {} cancelled successfully", id)
    })))
}

async fn stop_all_campaigns(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let campaigns = state
        .db
        .list_campaigns()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut stopped_count = 0;
    for c in campaigns {
        if c.status == CampaignStatus::Running || c.status == CampaignStatus::Pending {
            let _ = state.db.update_campaign_status(c.id, CampaignStatus::Cancelled);
            stopped_count += 1;
        }
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "stopped_count": stopped_count,
        "message": format!("Force stopped {} active campaign(s)", stopped_count)
    })))
}

async fn list_crashes(State(state): State<AppState>) -> Result<Json<Vec<CrashRecord>>, StatusCode> {
    state
        .db
        .list_crashes(None)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn telemetry_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = std::result::Result<Event, Infallible>>> {
    let db = state.db.clone();
    let stream = async_stream::stream! {
        loop {
            let campaigns = db.list_campaigns().unwrap_or_default();
            let crashes = db.list_crashes(None).unwrap_or_default();
            let active_count = campaigns.iter().filter(|c| c.status == CampaignStatus::Running).count();

            let snapshot = TelemetrySnapshot {
                active_campaigns: active_count,
                execs_per_sec: if active_count > 0 { 15200 } else { 0 },
                total_executions: 14626989,
                unique_edges: 818,
                crashes_found: crashes.len(),
                uptime_seconds: 120,
                timestamp: chrono::Utc::now(),
            };

            let data = serde_json::to_string(&snapshot).unwrap_or_default();
            yield Ok(Event::default().data(data));
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn logs_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = std::result::Result<Event, Infallible>>> {
    let rx = state.logs_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(line) => {
            let payload = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "line": line,
                "level": "INFO"
            });
            Some(Ok(Event::default().data(payload.to_string())))
        }
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
