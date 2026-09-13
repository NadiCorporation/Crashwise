//! Adversarial & Stress Verification Test Suite for crashwise-server (Milestone 6)
//!
//! Evaluates:
//! 1. REST API endpoints: /health, /api/campaigns, /api/campaigns/start, /api/campaigns/stop-all, /api/campaigns/:id/stop, /api/crashes.
//! 2. Malformed payloads: invalid JSON, missing fields, corrupted UUIDs.
//! 3. Server-Sent Events (SSE): /api/telemetry/stream and /api/logs/stream.
//! 4. High-concurrency burst requests across endpoints with in-memory SQLite state.

use crashwise_core::config::CrashwiseConfig;
use crashwise_core::db::Database;
use crashwise_core::models::{Campaign, CampaignStatus, CampaignTarget, CrashRecord, FuzzerEngine, TelemetrySnapshot};
use crashwise_server::{create_router, AppState};
use futures::future::join_all;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

async fn spawn_test_server() -> (SocketAddr, AppState) {
    let db = Database::open_in_memory().expect("Failed to open in-memory SQLite database");
    let config = CrashwiseConfig::default();
    let state = AppState::new(db, config);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral test port");
    let addr = listener.local_addr().expect("Failed to get local address");
    let router = create_router(state.clone());

    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    (addr, state)
}

async fn send_raw_http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("Failed to connect to test server");

    let req = if let Some(b) = body {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    };

    stream
        .write_all(req.as_bytes())
        .await
        .expect("Failed to write request");

    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .await
        .expect("Failed to read response");

    let response_str = String::from_utf8_lossy(&response_bytes).to_string();

    let parts: Vec<&str> = response_str.splitn(2, "\r\n\r\n").collect();
    let header_part = parts.first().copied().unwrap_or_default();
    let body_part = parts.get(1).copied().unwrap_or_default();

    let status_line = header_part.lines().next().unwrap_or_default();
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    (status_code, header_part.to_string(), body_part.to_string())
}

#[tokio::test]
async fn test_server_health_check_endpoint() {
    let (addr, _state) = spawn_test_server().await;

    let (status, _headers, body) = send_raw_http(addr, "GET", "/health", None).await;
    assert_eq!(status, 200, "Health check must return 200 OK");

    let json: serde_json::Value =
        serde_json::from_str(&body).expect("Health check body must be valid JSON");
    assert_eq!(json["status"], "ok");
    assert!(json["engine"].as_str().unwrap().contains("CrashWise"));
    assert_eq!(json["version"], "0.2.0-dev");
}

#[tokio::test]
async fn test_server_campaign_lifecycle_rest_api() {
    let (addr, state) = spawn_test_server().await;

    // 1. Initially empty campaigns
    let (status, _, body) = send_raw_http(addr, "GET", "/api/campaigns", None).await;
    assert_eq!(status, 200);
    let campaigns: Vec<Campaign> = serde_json::from_str(&body).expect("Expected Campaign list");
    assert!(campaigns.is_empty(), "Campaigns must be initially empty");

    // 2. Start new campaign
    let start_payload = serde_json::json!({
        "target_repo": "https://github.com/DaveGamble/cJSON",
        "target_name": "cJSON",
        "target_subdir": "src",
        "fuzzer_engine": "libfuzzer",
        "timeout_seconds": 120
    })
    .to_string();

    let (status, _, body) =
        send_raw_http(addr, "POST", "/api/campaigns/start", Some(&start_payload)).await;
    assert_eq!(status, 200);
    let created: Campaign = serde_json::from_str(&body).expect("Expected created Campaign JSON");
    assert_eq!(created.target.name, "cJSON");
    assert_eq!(created.target.repo_url, "https://github.com/DaveGamble/cJSON");
    assert_eq!(created.status, CampaignStatus::Pending);

    let campaign_id = created.id;

    // 3. Verify campaign now present in GET /api/campaigns
    let (status, _, body) = send_raw_http(addr, "GET", "/api/campaigns", None).await;
    assert_eq!(status, 200);
    let campaigns: Vec<Campaign> = serde_json::from_str(&body).expect("Expected Campaign list");
    assert_eq!(campaigns.len(), 1);
    assert_eq!(campaigns[0].id, campaign_id);

    // 4. Stop campaign via POST /api/campaigns/:id/stop
    let stop_path = format!("/api/campaigns/{campaign_id}/stop");
    let (status, _, body) = send_raw_http(addr, "POST", &stop_path, None).await;
    assert_eq!(status, 200);
    let stop_json: serde_json::Value = serde_json::from_str(&body).expect("Expected JSON response");
    assert_eq!(stop_json["ok"], true);
    assert_eq!(stop_json["campaign_id"], campaign_id.to_string());

    // 5. Verify status updated to Cancelled in database
    let db_campaigns = state.db.list_campaigns().expect("Failed querying DB");
    assert_eq!(db_campaigns[0].status, CampaignStatus::Cancelled);
}

#[tokio::test]
async fn test_server_stop_all_campaigns_bulk() {
    let (addr, state) = spawn_test_server().await;

    // Create 3 campaigns directly or via API
    for target in &["cJSON", "zlib", "libpng"] {
        let payload = serde_json::json!({
            "target_repo": format!("https://github.com/mock/{target}"),
            "target_name": target,
            "timeout_seconds": 60
        })
        .to_string();
        let (status, _, _) =
            send_raw_http(addr, "POST", "/api/campaigns/start", Some(&payload)).await;
        assert_eq!(status, 200);
    }

    let campaigns = state.db.list_campaigns().unwrap();
    assert_eq!(campaigns.len(), 3);

    // Stop all campaigns
    let (status, _, body) = send_raw_http(addr, "POST", "/api/campaigns/stop-all", None).await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["stopped_count"], 3);

    // Verify all 3 are cancelled
    let updated = state.db.list_campaigns().unwrap();
    for c in updated {
        assert_eq!(c.status, CampaignStatus::Cancelled);
    }
}

#[tokio::test]
async fn test_server_malformed_requests_and_edge_cases() {
    let (addr, _state) = spawn_test_server().await;

    // 1. Malformed JSON syntax
    let (status, _, _) = send_raw_http(
        addr,
        "POST",
        "/api/campaigns/start",
        Some("{\"target_repo\": INVALID_JSON"),
    )
    .await;
    assert!(
        status == 400 || status == 422,
        "Malformed JSON must return 400 Bad Request or 422 Unprocessable Entity, got {status}"
    );

    // 2. Missing required fields (missing target_repo and target_name)
    let (status, _, _) =
        send_raw_http(addr, "POST", "/api/campaigns/start", Some("{\"timeout\": 30}")).await;
    assert!(
        status == 400 || status == 422,
        "Missing fields must return 400/422, got {status}"
    );

    // 3. Invalid UUID in path
    let (status, _, _) =
        send_raw_http(addr, "POST", "/api/campaigns/not-a-valid-uuid/stop", None).await;
    assert!(
        status == 400 || status == 404,
        "Invalid UUID parameter must return 400 or 404, got {status}"
    );

    // 4. Non-existent path
    let (status, _, _) = send_raw_http(addr, "GET", "/api/non_existent_endpoint", None).await;
    assert_eq!(status, 404, "Unknown endpoint must return 404 Not Found");

    // 5. Stopping a random non-existent UUID (should succeed idempotently)
    let random_id = Uuid::new_v4();
    let (status, _, body) = send_raw_http(
        addr,
        "POST",
        &format!("/api/campaigns/{random_id}/stop"),
        None,
    )
    .await;
    assert_eq!(status, 200, "Stopping unknown UUID should be idempotent 200 OK");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["ok"], true);
}

#[tokio::test]
async fn test_server_crashes_list_endpoint() {
    let (addr, state) = spawn_test_server().await;

    // 1. Initially empty
    let (status, _, body) = send_raw_http(addr, "GET", "/api/crashes", None).await;
    assert_eq!(status, 200);
    let crashes: Vec<CrashRecord> = serde_json::from_str(&body).unwrap();
    assert!(crashes.is_empty());

    // 2. Insert parent campaign and test crash record into DB
    let target = CampaignTarget {
        repo_url: "https://github.com/mock/cJSON".to_string(),
        name: "cJSON".to_string(),
        subdir: None,
        clone_depth: 1,
        commit_hash: None,
    };
    let campaign = Campaign::new(target, FuzzerEngine::Libfuzzer, 60, 1);
    let campaign_id = campaign.id;
    state.db.insert_campaign(&campaign).expect("Failed inserting parent campaign");

    let crash_id = Uuid::new_v4();
    let record = CrashRecord {
        id: crash_id,
        campaign_id,
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "abcd1234deadbeef".to_string(),
        stack_trace: "==123==ERROR: AddressSanitizer: heap-buffer-overflow".to_string(),
        input_path: PathBuf::from("/tmp/crash_seed.bin"),
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: Some("--- a/cJSON.c\n+++ b/cJSON.c\n".to_string()),
        poc_c_code: Some("int main(void) { return 0; }".to_string()),
        verified: true,
        found_at: chrono::Utc::now(),
    };

    state.db.insert_crash(&record).expect("Failed inserting test crash");

    // 3. Query GET /api/crashes
    let (status, _, body) = send_raw_http(addr, "GET", "/api/crashes", None).await;
    assert_eq!(status, 200);
    let crashes: Vec<CrashRecord> = serde_json::from_str(&body).unwrap();
    assert_eq!(crashes.len(), 1);
    assert_eq!(crashes[0].id, crash_id);
    assert_eq!(crashes[0].crash_type, "heap-buffer-overflow");
    assert_eq!(crashes[0].cwe_id, Some("CWE-122".to_string()));
    assert_eq!(crashes[0].cvss_score, Some(8.8));
    assert!(crashes[0].verified);
}

#[tokio::test]
async fn test_server_telemetry_sse_stream() {
    let (addr, _state) = spawn_test_server().await;

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("Failed to connect to SSE stream");

    let req = "GET /api/telemetry/stream HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut received_event = false;

    // Read SSE frames until we get a data line
    for _ in 0..20 {
        let mut line = String::new();
        let timeout_res = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await;
        if let Ok(Ok(n)) = timeout_res {
            if n == 0 {
                break;
            }
            if let Some(json_str) = line.strip_prefix("data:") {
                let json_trimmed = json_str.trim();
                if let Ok(snapshot) = serde_json::from_str::<TelemetrySnapshot>(json_trimmed) {
                    assert_eq!(snapshot.active_campaigns, 0);
                    assert_eq!(snapshot.crashes_found, 0);
                    assert_eq!(snapshot.uptime_seconds, 120);
                    received_event = true;
                    break;
                }
            }
        } else {
            break;
        }
    }

    assert!(received_event, "Must receive at least one valid TelemetrySnapshot over SSE");
}

#[tokio::test]
async fn test_server_logs_sse_stream_broadcast() {
    let (addr, state) = spawn_test_server().await;

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("Failed to connect to logs SSE stream");

    let req = "GET /api/logs/stream HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(stream);

    // Give SSE handler a moment to subscribe
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send log event via broadcast channel
    let test_msg = "ADVERSARIAL_CRITICAL_CORPUS_EXPANSION_FOUND";
    let _ = state.logs_tx.send(test_msg.to_string());

    let mut received_log = false;
    for _ in 0..20 {
        let mut line = String::new();
        let timeout_res = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await;
        if let Ok(Ok(n)) = timeout_res {
            if n == 0 {
                break;
            }
            if let Some(json_str) = line.strip_prefix("data:") {
                let json_trimmed = json_str.trim();
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_trimmed) {
                    if v["line"].as_str() == Some(test_msg) {
                        assert_eq!(v["level"], "INFO");
                        received_log = true;
                        break;
                    }
                }
            }
        } else {
            break;
        }
    }

    assert!(received_log, "Must receive broadcasted log message over logs SSE stream");
}

#[tokio::test]
async fn test_server_high_concurrency_burst_stress() {
    let (addr, _state) = spawn_test_server().await;

    // Burst 60 concurrent requests across different endpoints
    let mut handles = Vec::new();
    for i in 0..60 {
        let endpoint = match i % 3 {
            0 => "/health",
            1 => "/api/campaigns",
            _ => "/api/crashes",
        };

        handles.push(tokio::spawn(async move {
            let (status, _, _) = send_raw_http(addr, "GET", endpoint, None).await;
            assert_eq!(status, 200);
        }));
    }

    let results = join_all(handles).await;
    for res in results {
        assert!(res.is_ok(), "Concurrent request task must not panic or abort");
    }
}
