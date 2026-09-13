use crashwise_core::models::CrashRecord;
use crashwise_triage::asan::{AsanParser, StackFrame};
use std::fs;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn test_asan_extract_source_location() {
    let log = r#"
=================================================================
==31415==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000030 at pc 0x0000004012ab bp 0x7fff5fbff820 sp 0x7fff5fbff818
READ of size 1 at 0x602000000030 thread T0
    #0 0x4012aa in parse_json_object /home/user/project/src/parser.c:342
    #1 0x402345 in main /home/user/project/src/main.c:45
    #2 0x7ffff7a05b96 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
=================================================================
"#;

    let loc = AsanParser::extract_source_location(log);
    assert_eq!(loc, Some(("/home/user/project/src/parser.c".to_string(), 342)));

    let all_locs = AsanParser::extract_all_source_locations(log);
    assert_eq!(all_locs.len(), 2);
    assert_eq!(all_locs[0], ("/home/user/project/src/parser.c".to_string(), 342));
    assert_eq!(all_locs[1], ("/home/user/project/src/main.c".to_string(), 45));
}

#[test]
fn test_asan_parse_stack_frames() {
    let log = r#"
    #0 0x401000 in vuln_copy /src/buffer.c:120
    #1 0x402000 in uninstrumented_stub
    #2 0x403000 in entrypoint /src/entry.c:15
"#;

    let frames = AsanParser::parse_stack_frames(log);
    assert_eq!(frames.len(), 3);

    assert_eq!(
        frames[0],
        StackFrame {
            frame_num: 0,
            address: "0x401000".to_string(),
            function: "vuln_copy".to_string(),
            source_file: Some("/src/buffer.c".to_string()),
            line_number: Some(120),
        }
    );

    assert_eq!(
        frames[1],
        StackFrame {
            frame_num: 1,
            address: "0x402000".to_string(),
            function: "uninstrumented_stub".to_string(),
            source_file: None,
            line_number: None,
        }
    );

    assert_eq!(
        frames[2],
        StackFrame {
            frame_num: 2,
            address: "0x403000".to_string(),
            function: "entrypoint".to_string(),
            source_file: Some("/src/entry.c".to_string()),
            line_number: Some(15),
        }
    );
}

#[test]
fn test_asan_detect_various_sanitizer_violations() {
    // AddressSanitizer ERROR
    let out1 = "==123==ERROR: AddressSanitizer: heap-use-after-free on address 0x6000000000";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out1),
        Some("heap-use-after-free".to_string())
    );

    // AddressSanitizer SUMMARY
    let out2 = "SUMMARY: AddressSanitizer: stack-buffer-overflow /src/test.c:12 in foo";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out2),
        Some("AddressSanitizer: stack-buffer-overflow".to_string())
    );

    // UndefinedBehaviorSanitizer
    let out3 = "calc.c:88:5: runtime error: shift exponent 64 is too large for 64-bit type";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out3),
        Some("UndefinedBehaviorSanitizer: shift exponent 64 is too large for 64-bit type".to_string())
    );

    // MemorySanitizer
    let out4 = "==456==ERROR: MemorySanitizer: use-of-uninitialized-value";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out4),
        Some("MemorySanitizer: use-of-uninitialized-value".to_string())
    );

    // LeakSanitizer
    let out5 = "==789==ERROR: LeakSanitizer: detected memory leaks";
    assert_eq!(
        AsanParser::detect_sanitizer_violation(out5),
        Some("LeakSanitizer: detected".to_string())
    );

    // Clean execution
    let clean = "All tests passed.\nProcess terminated normally.\n";
    assert_eq!(AsanParser::detect_sanitizer_violation(clean), None);
}

#[test]
fn test_asan_is_clean_execution_criteria() {
    assert!(AsanParser::is_clean_execution("Success: 100 tests passed", Some(0)));
    assert!(!AsanParser::is_clean_execution("Success", Some(1)));
    assert!(!AsanParser::is_clean_execution("Success", None));
    assert!(!AsanParser::is_clean_execution("==1==ERROR: AddressSanitizer: SEGV", Some(0)));
    assert!(!AsanParser::is_clean_execution("runtime error: division by zero", Some(0)));
    assert!(!AsanParser::is_clean_execution("Assertion failed: ptr != NULL", Some(134)));
}

#[test]
fn test_parse_asan_log_initial_state() {
    let temp = tempdir().unwrap();
    let crash_file = temp.path().join("crash.bin");
    fs::write(&crash_file, b"trigger payload").unwrap();

    let log = r#"
==54321==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
    #0 0x401000 in vuln_func /src/vuln.c:42
    #1 0x402000 in main /src/main.c:10
"#;
    let campaign_id = Uuid::new_v4();
    let record: CrashRecord = AsanParser::parse_asan_log(campaign_id, log, &crash_file)
        .expect("Failed to parse ASan log");

    assert_eq!(record.campaign_id, campaign_id);
    assert_eq!(record.crash_type, "heap-buffer-overflow");
    assert_eq!(record.cwe_id, Some("CWE-122".to_string()));
    assert_eq!(record.cvss_score, Some(8.8));
    assert!(!record.stack_hash.is_empty());
    assert!(!record.verified, "Must not be verified before 5-stage closed-loop verification");
}
