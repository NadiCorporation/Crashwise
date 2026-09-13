use crashwise_core::models::CrashRecord;
use crashwise_triage::poc_gen::{PocCompiler, PocGenerator};
use crashwise_triage::poc_runner::PocRunner;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn test_poc_generation_embeds_exact_seed_bytes() {
    let temp = tempdir().unwrap();
    let seed_path = temp.path().join("crash.seed");
    let payload = vec![0x41, 0x42, 0x43, 0x00, 0xFF, 0xFE];
    fs::write(&seed_path, &payload).unwrap();

    let crash = CrashRecord {
        id: Uuid::new_v4(),
        campaign_id: Uuid::new_v4(),
        crash_type: "heap-buffer-overflow".to_string(),
        stack_hash: "hash123".to_string(),
        stack_trace: "".to_string(),
        input_path: seed_path,
        cwe_id: Some("CWE-122".to_string()),
        cvss_score: Some(8.8),
        suggested_patch: None,
        poc_c_code: None,
        verified: false,
        found_at: chrono::Utc::now(),
    };

    let poc_code = PocGenerator::generate_standalone_poc(
        &crash,
        "#include <assert.h>",
        "assert(poc_payload[0] == 'A');",
    );

    assert!(poc_code.contains("0x41, 0x42, 0x43, 0x00, 0xff, 0xfe"));
    assert!(poc_code.contains("Auto-Generated Standalone PoC Reproducer by CrashWise"));
    assert!(poc_code.contains("int main(int argc, char **argv)"));
    assert!(poc_code.contains("assert(poc_payload[0] == 'A');"));
}

#[tokio::test]
async fn test_poc_compiler_and_runner_heap_buffer_overflow() {
    let temp = tempdir().unwrap();

    let vuln_c = r#"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    volatile char *buf = (char*)malloc(8);
    // Write at offset 32 to guarantee ASan redzone violation
    buf[32] = 'X';
    free((void*)buf);
    return 0;
}
"#;
    let compiler = PocCompiler::new();
    let bin = compiler
        .compile_source(vuln_c, temp.path(), "vuln_poc")
        .await
        .expect("Failed to compile vulnerable PoC with ASan");

    assert!(bin.exists());

    let runner = PocRunner::new();
    let run_res = runner.run(&bin).await.expect("Failed to execute PoC binary");

    assert!(!run_res.clean_execution);
    assert!(run_res.reproduced_crash);
    assert!(
        run_res.stderr.contains("AddressSanitizer: heap-buffer-overflow")
            || run_res.violation_type.is_some()
    );
}

#[tokio::test]
async fn test_poc_compiler_and_runner_clean_execution() {
    let temp = tempdir().unwrap();

    let clean_c = r#"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *x = (int*)malloc(sizeof(int));
    *x = 42;
    printf("[+] Value: %d (patch verified)\n", *x);
    free(x);
    return 0;
}
"#;
    let compiler = PocCompiler::new();
    let bin = compiler
        .compile_source(clean_c, temp.path(), "clean_poc")
        .await
        .expect("Failed to compile clean PoC with ASan");

    let runner = PocRunner::new();
    let run_res = runner.run(&bin).await.expect("Failed to execute clean binary");

    assert!(run_res.clean_execution);
    assert!(!run_res.reproduced_crash);
    assert_eq!(run_res.exit_code, Some(0));
    assert!(run_res.stdout.contains("patch verified"));
}

#[tokio::test]
async fn test_poc_runner_timeout() {
    let temp = tempdir().unwrap();

    let infinite_loop_c = r#"
#include <unistd.h>
int main(void) {
    while (1) {
        usleep(10000);
    }
    return 0;
}
"#;
    let compiler = PocCompiler::new();
    let bin = compiler
        .compile_source(infinite_loop_c, temp.path(), "timeout_poc")
        .await
        .expect("Failed to compile infinite loop C code");

    let runner = PocRunner::new().with_timeout(Duration::from_millis(500));
    let run_res = runner.run(&bin).await.expect("Failed to run binary");

    assert!(run_res.timed_out);
    assert!(!run_res.clean_execution);
    assert!(!run_res.reproduced_crash);
    assert_eq!(run_res.violation_type, Some("Timeout".to_string()));
}
