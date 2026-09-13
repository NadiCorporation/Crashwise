use crashwise_core::db::Database;
use crashwise_core::models::AgentFeedbackRecord;
use chrono::Utc;
use std::sync::{Arc, Barrier};
use std::thread;
use uuid::Uuid;

#[test]
fn test_concurrent_access_shared_database() {
    let db = Arc::new(Database::open_in_memory().expect("Failed to open in-memory DB"));

    let num_threads = 10;
    let records_per_thread = 50;
    let barrier = Arc::new(Barrier::new(num_threads * 2));
    let mut handles = Vec::new();

    // 10 Writer threads
    for t_idx in 0..num_threads {
        let db_clone = Arc::clone(&db);
        let b_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b_clone.wait();
            for i in 0..records_per_thread {
                let diag = format!("error: undeclared identifier 'func_{}_{}' in target_A", t_idx, i);
                let res = db_clone.record_resolved_fix(
                    None,
                    "target_A",
                    &diag,
                    "bad_code();",
                    "good_code();",
                );
                assert!(res.is_ok(), "Insert failed: {:?}", res.err());
            }
        }));
    }

    // 10 Reader threads
    for _ in 0..num_threads {
        let db_clone = Arc::clone(&db);
        let b_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b_clone.wait();
            for _ in 0..records_per_thread {
                let fixes = db_clone.query_similar_compiler_fixes(
                    "error: undeclared identifier 'func_0_0'",
                    Some("target_A"),
                    5,
                );
                assert!(fixes.is_ok(), "Query failed: {:?}", fixes.err());
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }

    // Total records should be num_threads * records_per_thread = 500
    let results = db
        .query_similar_compiler_fixes("undeclared", Some("target_A"), 1000)
        .expect("Final query failed");
    assert_eq!(results.len(), num_threads * records_per_thread);
}

#[test]
fn test_concurrent_connections_to_same_file() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("test_concurrency_{}.db", Uuid::new_v4()));

    // Open first connection to initialize schema
    {
        let _init_db = Database::open(&db_path).expect("Init DB failed");
    }

    let num_threads = 8;
    let records_per_thread = 30;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for t_idx in 0..num_threads {
        let path_clone = db_path.clone();
        let b_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            // Each thread opens its own separate SQLite connection to the same file!
            let db = Database::open(&path_clone).expect("Failed to open connection");
            b_clone.wait();
            let mut failed_inserts = 0;
            for i in 0..records_per_thread {
                let diag = format!("error: undefined symbol 'sym_{}_{}'", t_idx, i);
                match db.record_resolved_fix(None, "target_B", &diag, "foo", "bar") {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Thread {} insert failed with: {:?}", t_idx, e);
                        failed_inserts += 1;
                    }
                }
            }
            failed_inserts
        }));
    }

    let mut total_failures = 0;
    for h in handles {
        total_failures += h.join().expect("Thread panicked");
    }

    println!("Total concurrent separate connection write failures: {}", total_failures);
    let _ = std::fs::remove_file(&db_path);

    // If SQLite lacks busy_timeout in WAL mode, concurrent separate connections will lock
    assert_eq!(
        total_failures, 0,
        "Separate concurrent SQLite connections failed with lock errors because busy_timeout is not configured!"
    );
}

#[test]
fn test_edge_case_strings_and_injections() {
    let db = Database::open_in_memory().expect("Failed to open in-memory DB");

    // Test SQL injections
    let injection_diag = "'; DROP TABLE agent_feedback_memory; -- ' OR 1=1; /* */";
    let injection_code = "\"\"\"; DROP TABLE campaigns; --";
    let _fix_id = db
        .record_resolved_fix(None, "target_inject", injection_diag, injection_code, "safe_code();")
        .expect("SQL injection payload broke insertion");

    assert!(db.table_exists("agent_feedback_memory").unwrap());

    // Test Unicode, Emoji, and CJK
    let unicode_diag = "错误：未声明的标识符 '🚀_rocket_💥' 在 main.c:42:10";
    let unicode_orig = "let 🔥 = \"🔥\"; // العربية / русский / 中文";
    let unicode_fix = "const char *safe = \"🛡️\";";
    let u_id = db
        .record_resolved_fix(None, "target_unicode_🎯", unicode_diag, unicode_orig, unicode_fix)
        .expect("Unicode payload failed");

    // Query back
    let results = db
        .query_similar_compiler_fixes(unicode_diag, Some("target_unicode_🎯"), 5)
        .expect("Query failed for unicode");
    assert!(!results.is_empty());
    assert_eq!(results[0].id, u_id);

    // Test Huge diagnostic (100KB)
    let huge_diag = "error: ".to_string() + &"x".repeat(100_000);
    let huge_id = db
        .record_resolved_fix(None, "target_huge", &huge_diag, "code", "fixed")
        .expect("Huge diagnostic insertion failed");
    let huge_res = db
        .query_similar_compiler_fixes("error: xxxxx", Some("target_huge"), 1)
        .expect("Query huge failed");
    assert!(!huge_res.is_empty());
    assert_eq!(huge_res[0].id, huge_id);

    // Test Malformed diagnostics with zero alphanumeric chars
    let punct_diag = "!@#$%^&*()_+{}|:\"<>?~`-=[]\\;',./";
    let punct_id = db
        .record_resolved_fix(None, "target_punct", punct_diag, "orig", "fix")
        .expect("Punctuation diagnostic failed");
    let punct_res = db
        .query_similar_compiler_fixes(punct_diag, Some("target_punct"), 1)
        .expect("Query punctuation failed");
    assert!(!punct_res.is_empty());
    assert_eq!(punct_res[0].id, punct_id);
}

#[test]
fn test_query_score_ranking_and_volume_performance() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Insert 1000 records with varying scores, categories, and targets
    let targets = ["target_alpha", "target_beta", "target_gamma"];
    for i in 0..1000 {
        let target = targets[i % 3];
        let diag = if i % 2 == 0 {
            format!("error: incompatible type in assignment 'var_{}'", i)
        } else {
            format!("error: undeclared identifier 'sym_{}'", i)
        };
        let rec = AgentFeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: target.to_string(),
            feedback_type: "resolved_fix".to_string(),
            compiler_diagnostic: Some(diag),
            error_category: Some(if i % 2 == 0 { "type_mismatch".to_string() } else { "undefined_symbol".to_string() }),
            original_code: Some(format!("bad_{}();", i)),
            resolved_code: Some(format!("good_{}();", i)),
            coverage_tokens: None,
            success_count: (i % 10) as u32,
            failure_count: 0,
            score: (i as f32) / 100.0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_feedback_record(&rec).unwrap();
    }

    let start = std::time::Instant::now();
    let query_res = db
        .query_similar_compiler_fixes("error: incompatible type in assignment 'var_998'", Some("target_alpha"), 5)
        .expect("Query failed");
    let elapsed = start.elapsed();
    println!("Query similar compiler fixes over 1,000 records took {:?}", elapsed);

    assert_eq!(query_res.len(), 5);
    // Highest scored record for target_alpha with type_mismatch should be top
    assert_eq!(query_res[0].target_name, "target_alpha");
    assert_eq!(query_res[0].error_category.as_deref(), Some("type_mismatch"));
}
