use chrono::Utc;
use crashwise_core::db::{classify_compiler_error, Database};
use crashwise_core::models::{AgentFeedbackRecord, Campaign, CampaignStatus, CampaignTarget, CrashRecord, FuzzerEngine};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use uuid::Uuid;

#[test]
fn test_m6_sql_injection_and_escaping_resistance() {
    let db = Database::open_in_memory().expect("Failed to open in-memory DB");

    // Payloads containing quotes, SQL keywords, subqueries, comments, escape chars
    let injection_targets = [
        "cJSON'; DROP TABLE agent_feedback_memory; --",
        "zlib' OR '1'='1",
        "libpng\" UNION SELECT * FROM sqlite_master --",
        "sqlite3'/*comment*/--",
        "target\x00with_null",
        "target\\n\\r\\t'\"`",
    ];

    let injection_diagnostics = [
        "error: undeclared identifier 'x'; DROP TABLE campaigns; --",
        "error: ' OR 1=1; SELECT * FROM harnesses; /* */",
        "fatal: error: \"\"; DROP TABLE crashes; --",
        "error: \x1b[31;1mANSI_RED\x1b[0m; DELETE FROM agent_feedback_memory WHERE 1=1;",
    ];

    let code_payload = r#"
        #include "safe.h"
        // '; DROP TABLE users; --
        int main() {
            const char *msg = "'; DROP TABLE campaigns; --";
            return 0;
        }
    "#;

    for (i, target) in injection_targets.iter().enumerate() {
        let diag = injection_diagnostics[i % injection_diagnostics.len()];
        let id = db.record_resolved_fix(
            None,
            target,
            diag,
            code_payload,
            "// resolved\nint safe = 1;",
        ).expect("Insertion of injection payload should not fail");

        // Verify tables still exist
        assert!(db.table_exists("agent_feedback_memory").unwrap());
        assert!(db.table_exists("campaigns").unwrap());
        assert!(db.table_exists("crashes").unwrap());
        assert!(db.table_exists("harnesses").unwrap());
        assert!(db.table_exists("fuzz_runs").unwrap());

        // Query back using the exact malicious target
        let results = db.query_similar_compiler_fixes(diag, Some(target), 5)
            .expect("Query with malicious target failed");
        assert!(!results.is_empty());
        assert_eq!(results[0].id, id);
        assert_eq!(results[0].target_name, *target);
        assert_eq!(results[0].compiler_diagnostic.as_deref(), Some(diag));
        assert_eq!(results[0].original_code.as_deref(), Some(code_payload));
    }
}

#[test]
fn test_m6_foreign_keys_and_cascading_deletions() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("cascade_test_{}.db", Uuid::new_v4()));
    let db = Database::open(&db_path).expect("Failed to open DB");

    let campaign_id = Uuid::new_v4();
    let campaign = Campaign {
        id: campaign_id,
        target: CampaignTarget {
            name: "test_cascade_target".to_string(),
            repo_url: "https://example.com/repo.git".to_string(),
            subdir: None,
            clone_depth: 1,
            commit_hash: None,
        },
        engine: FuzzerEngine::Libfuzzer,
        status: CampaignStatus::Running,
        timeout_seconds: 3600,
        max_iterations: 100,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.insert_campaign(&campaign).expect("Insert campaign failed");

    // Insert a crash associated with campaign
    let crash_id = Uuid::new_v4();
    let crash = CrashRecord {
        id: crash_id,
        campaign_id,
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "abcd1234deadbeef".to_string(),
        stack_trace: "main.c:10:5 in vulnerable_func".to_string(),
        input_path: PathBuf::from("/tmp/crash_input"),
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: Some("diff --git a/ b/".to_string()),
        poc_c_code: Some("int main() {}".to_string()),
        verified: true,
        found_at: Utc::now(),
    };
    db.insert_crash(&crash).expect("Insert crash failed");

    // Insert feedback record associated with campaign
    let fix_id = db.record_resolved_fix(
        Some(campaign_id),
        "test_cascade_target",
        "error: type mismatch",
        "int x = \"bad\";",
        "const char *x = \"good\";",
    ).expect("Insert feedback failed");

    // Verify relations exist
    let crashes_before = db.list_crashes(Some(campaign_id)).expect("list crashes");
    assert_eq!(crashes_before.len(), 1);

    let fixes_before = db.query_similar_compiler_fixes("type mismatch", Some("test_cascade_target"), 5)
        .expect("query fixes");
    assert_eq!(fixes_before.len(), 1);
    assert_eq!(fixes_before[0].campaign_id, Some(campaign_id));

    // Delete the campaign directly in SQLite to test ON DELETE CASCADE & ON DELETE SET NULL
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open raw conn");
        conn.execute("PRAGMA foreign_keys = ON;", []).expect("enable fk");
        let deleted = conn.execute("DELETE FROM campaigns WHERE id = ?1", rusqlite::params![campaign_id.to_string()])
            .expect("delete campaign");
        assert_eq!(deleted, 1);
    }

    // Crashes must be deleted by cascade
    let crashes_after = db.list_crashes(Some(campaign_id)).expect("list crashes after");
    assert!(crashes_after.is_empty());

    // Feedback record must SURVIVE, but campaign_id must be SET NULL
    let fixes_after = db.query_similar_compiler_fixes("type mismatch", Some("test_cascade_target"), 5)
        .expect("query fixes after");
    assert_eq!(fixes_after.len(), 1);
    assert_eq!(fixes_after[0].id, fix_id);
    assert_eq!(fixes_after[0].campaign_id, None, "campaign_id must be SET NULL by foreign key rule");

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_m6_boundary_and_extreme_inputs_similarity_ranking() {
    let db = Database::open_in_memory().expect("Failed to open in-memory DB");

    // 1. Completely empty database calls
    let r_empty = db.query_similar_compiler_fixes("", None, 0).unwrap();
    assert!(r_empty.is_empty());
    let ex_empty = db.query_harness_exemplars(None, 0).unwrap();
    assert!(ex_empty.is_empty());
    let tok_empty = db.query_coverage_tokens(None, 0).unwrap();
    assert!(tok_empty.is_empty());

    // 2. Insert records with extreme scores and edge categories
    let rec_nan = AgentFeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "target_extreme".to_string(),
        feedback_type: "resolved_fix".to_string(),
        compiler_diagnostic: Some("error: punctuation only !@#$%^&*()_+=-`~".to_string()),
        error_category: Some("custom_error".to_string()),
        original_code: Some("".to_string()),
        resolved_code: Some("".to_string()),
        coverage_tokens: None,
        success_count: 0,
        failure_count: 100,
        score: -5.0, // negative score
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.insert_feedback_record(&rec_nan).expect("insert negative score");

    let rec_high_score = AgentFeedbackRecord {
        id: Uuid::new_v4(),
        campaign_id: None,
        target_name: "target_extreme".to_string(),
        feedback_type: "resolved_fix".to_string(),
        compiler_diagnostic: Some("error: punctuation only !@#$%^&*()_+=-`~".to_string()),
        error_category: Some("custom_error".to_string()),
        original_code: Some("".to_string()),
        resolved_code: Some("".to_string()),
        coverage_tokens: None,
        success_count: 50,
        failure_count: 0,
        score: 5.0, // higher score
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.insert_feedback_record(&rec_high_score).expect("insert high score");

    // Query with punctuation diagnostic and limit = 1
    let results = db.query_similar_compiler_fixes("!@#$%^&*()", Some("target_extreme"), 1)
        .expect("Query failed");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, rec_high_score.id, "Higher score must rank first");

    // 3. Test huge diagnostic with repeated tokens (> 50,000 characters)
    let repeating_diag = format!("error: missing_token_{} ", "keyword ".repeat(5000));
    let fix_id = db.record_resolved_fix(
        None,
        "target_stress",
        &repeating_diag,
        "bad();",
        "good();",
    ).expect("Insert huge diagnostic");

    let queried = db.query_similar_compiler_fixes("keyword missing_token_0", Some("target_stress"), 5)
        .expect("Query huge diagnostic");
    assert!(!queried.is_empty());
    assert_eq!(queried[0].id, fix_id);

    // 4. Test classify_compiler_error exhaustiveness
    assert_eq!(classify_compiler_error("fatal error: cJSON.h: No such file or directory"), "missing_header");
    assert_eq!(classify_compiler_error("error: 'sqlite3_open' undeclared"), "undefined_symbol");
    assert_eq!(classify_compiler_error("error: cannot convert 'int*' to 'char*'"), "type_mismatch");
    assert_eq!(classify_compiler_error("error: too few arguments to function 'inflate'"), "argument_mismatch");
    assert_eq!(classify_compiler_error("error: expected ';' before 'return'"), "syntax_error");
    assert_eq!(classify_compiler_error("error: redefinition of 'struct gz_header'"), "redefinition");
    assert_eq!(classify_compiler_error("some arbitrary compiler warning: unknown attribute"), "compiler_error");
}

#[test]
fn test_m6_high_concurrency_stress() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("concurrency_stress_{}.db", Uuid::new_v4()));
    let db = Arc::new(Database::open(&db_path).expect("Failed to open DB"));

    let num_threads = 12;
    let ops_per_thread = 40;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for t_idx in 0..num_threads {
        let db_clone = Arc::clone(&db);
        let b_clone = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            b_clone.wait();
            for i in 0..ops_per_thread {
                // Interleave writes and reads
                let diag = format!("error: undefined reference to 'symbol_{}_{}'", t_idx, i);
                let target = if i % 2 == 0 { "target_even" } else { "target_odd" };
                let rec_id = db_clone.record_resolved_fix(
                    None,
                    target,
                    &diag,
                    "code_before();",
                    "code_after();",
                ).expect("Thread write failed");

                // Immediate read
                let queried = db_clone.query_similar_compiler_fixes(&diag, Some(target), 3)
                    .expect("Thread read failed");
                assert!(!queried.is_empty());
                assert!(queried.iter().any(|r| r.id == rec_id));
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }

    // Both queries return all 480 records because fallback includes other targets up to limit,
    // but the target-matching records must rank FIRST due to the +5.0 target boost.
    let all_even = db.query_similar_compiler_fixes("symbol", Some("target_even"), 1000)
        .expect("Query all even");
    let all_odd = db.query_similar_compiler_fixes("symbol", Some("target_odd"), 1000)
        .expect("Query all odd");
    assert_eq!(all_even.len(), num_threads * ops_per_thread);
    assert_eq!(all_odd.len(), num_threads * ops_per_thread);

    // Verify first 240 records in all_even are indeed target_even
    let half = (num_threads * ops_per_thread) / 2;
    for rec in &all_even[..half] {
        assert_eq!(rec.target_name, "target_even", "Target matches must rank ahead of non-target fallbacks");
    }
    // Verify first 240 records in all_odd are indeed target_odd
    for rec in &all_odd[..half] {
        assert_eq!(rec.target_name, "target_odd", "Target matches must rank ahead of non-target fallbacks");
    }

    let _ = std::fs::remove_file(&db_path);
}
