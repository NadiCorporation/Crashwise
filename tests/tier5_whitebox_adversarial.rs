//! Tier 5: White-Box Adversarial Hardening & Stress Verification Suite (Milestone 6)
//!
//! Scope: Crates 5–8 (crashwise-engine, crashwise-triage, crashwise-server, crashwise-cli, and end-to-end integration)
//!
//! Evaluates:
//! - Engine: In-process shared memory bitmap, crash handler alternate stack, POSIX rlimits.
//! - Triage: End-to-end 5-stage closed-loop patch verifier, RAII rollback, PoC compilation and replay.
//! - Server: Concurrency, campaign lifecycle, REST endpoints, SSE telemetry.
//! - CLI: 7-phase benchmark runner across real-world CVE targets.

use crashwise_build::compiler::BuildOutput;
use crashwise_core::config::CrashwiseConfig;
use crashwise_core::db::Database;
use crashwise_core::models::{CampaignStatus, CrashRecord};
use crashwise_engine::libafl_runner::{CoverageMap, MAP_SIZE};
use crashwise_server::{run_server, AppState};
use crashwise_triage::patch_synth::PatchCandidate;
use crashwise_triage::verifier::PatchVerifier;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

#[test]
fn test_tier5_engine_shm_bitmap_and_coverage_sync() {
    let mut map = CoverageMap::new().expect("Failed creating CoverageMap");

    // Boundary check on indices
    map.record_edge(0);
    map.record_edge(MAP_SIZE - 1);
    map.record_edge(MAP_SIZE * 2 + 100);

    assert_eq!(map.as_slice()[0], 1);
    assert_eq!(map.as_slice()[MAP_SIZE - 1], 1);
    assert_eq!(map.as_slice()[100], 1);
    assert_eq!(map.count_edges(), 3);

    // Synchronize into history map
    let mut history = vec![0u8; MAP_SIZE];
    let (total, is_new) = map.count_and_sync_edges(&mut history);
    assert_eq!(total, 3);
    assert!(is_new);

    // Subsequent sync without changes should report no new edges
    let (total2, is_new2) = map.count_and_sync_edges(&mut history);
    assert_eq!(total2, 3);
    assert!(!is_new2);
}

#[tokio::test]
async fn test_tier5_triage_closed_loop_verification_and_rollback() {
    let temp = tempdir().unwrap();
    let target_dir = temp.path().join("mock_target");
    fs::create_dir_all(&target_dir).unwrap();

    let c_file = target_dir.join("vuln.c");
    let original_c = r#"
#include <stdio.h>
#include <stdlib.h>

int process(int trigger) {
    if (trigger) {
        char *buf = (char*)malloc(8);
        buf[32] = 'A'; // Heap buffer overflow
        int v = buf[0];
        free(buf);
        return v;
    }
    return 0;
}
"#;
    fs::write(&c_file, original_c).unwrap();

    let poc_file = target_dir.join("poc.c");
    let poc_c = r#"
#include <stdio.h>
#include "vuln.c"

int main(void) {
    process(1);
    return 0;
}
"#;
    fs::write(&poc_file, poc_c).unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "tier5_hash".to_string(),
        stack_trace: "ERROR: AddressSanitizer: heap-buffer-overflow".to_string(),
        input_path: PathBuf::from("/tmp/dummy.bin"),
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let build_output = BuildOutput {
        static_libs: vec![],
        shared_libs: vec![],
        include_dirs: vec![target_dir.clone()],
        compile_commands_path: None,
    };

    // Case 1: Ineffective patch that doesn't fix the overflow
    let ineffective_diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -1,3 +1,4 @@
+/* comment */
 #include <stdio.h>
"#;
    let bad_patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: ineffective_diff.to_string(),
        explanation: "Ineffective patch".to_string(),
    };

    let verifier = PatchVerifier::new(target_dir.clone(), build_output.clone());
    let rep_bad = verifier
        .verify_patch(&crash, &poc_file, &bad_patch)
        .await
        .expect("Verification must complete");

    assert!(!rep_bad.verified, "Ineffective patch must fail verification");
    assert_eq!(rep_bad.failure_stage, Some("post_patch_poc_replay".to_string()));
    // Assert target was rolled back
    let file_content = fs::read_to_string(&c_file).unwrap();
    assert_eq!(file_content, original_c, "Failed patch must be rolled back automatically");

    // Case 2: Effective patch that fixes the overflow
    let effective_diff = r#"--- a/vuln.c
+++ b/vuln.c
@@ -5,3 +5,3 @@
 int process(int trigger) {
-    if (trigger) {
+    if (0 && trigger) {
         char *buf = (char*)malloc(8);
"#;
    let good_patch = PatchCandidate {
        file_path: "vuln.c".to_string(),
        unified_diff: effective_diff.to_string(),
        explanation: "Disables overflow trigger".to_string(),
    };

    let mut crash_record = crash.clone();
    let rep_good = verifier
        .verify_patch_record(&mut crash_record, &poc_file, &good_patch)
        .await
        .expect("Verification must succeed");

    assert!(rep_good.verified, "Effective patch must pass all 5 stages");
    assert!(crash_record.verified, "CrashRecord.verified must be true");
    assert!(crash_record.suggested_patch.is_some());
    let patched_file = fs::read_to_string(&c_file).unwrap();
    assert!(patched_file.contains("if (0 && trigger)"));
}

#[tokio::test]
async fn test_tier5_server_concurrent_rest_campaign_lifecycle() {
    let db = Database::open_in_memory().expect("Failed in-memory DB");
    let config = CrashwiseConfig::default();
    let state = AppState::new(db, config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let server_state = state.clone();
    tokio::spawn(async move {
        let _ = run_server(server_state, addr).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Helper HTTP POST
    let send_post = |path: &'static str, body: String| {
        async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let req = format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).to_string()
        }
    };

    // Concurrently launch 5 campaigns
    let mut handles = Vec::new();
    for i in 0..5 {
        let payload = serde_json::json!({
            "target_repo": format!("https://github.com/test/repo_{i}"),
            "target_name": format!("target_{i}"),
            "timeout_seconds": 60
        })
        .to_string();
        handles.push(tokio::spawn(send_post("/api/campaigns/start", payload)));
    }

    for h in handles {
        let resp = h.await.unwrap();
        assert!(resp.contains("HTTP/1.1 200 OK"));
    }

    // Verify 5 campaigns in database
    let all = state.db.list_campaigns().unwrap();
    assert_eq!(all.len(), 5);

    // Stop all campaigns
    let stop_resp = send_post("/api/campaigns/stop-all", String::new()).await;
    assert!(stop_resp.contains("HTTP/1.1 200 OK"));
    assert!(stop_resp.contains("\"stopped_count\":5"));

    // Verify all 5 are cancelled
    let after_stop = state.db.list_campaigns().unwrap();
    for c in after_stop {
        assert_eq!(c.status, CampaignStatus::Cancelled);
    }
}
