//! Adversarial & Stress Verification Test Suite for crashwise-cli (Milestone 6)
//!
//! Evaluates:
//! 1. CLI binary subcommands: version, info, doctor, scan, triage, reproduce.
//! 2. Error handling: non-existent paths, corrupt logs, uncompilable PoCs.
//! 3. Benchmark runner 7-phase execution and JSON report generation across CVE targets.

use crashwise_cli::benchmark::{BenchmarkOptions, BenchmarkRunner};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_adversarial_cli_metadata_subcommands() {
    let bin_path = env!("CARGO_BIN_EXE_crashwise");

    // 1. Version command
    let out_ver = Command::new(bin_path)
        .arg("version")
        .output()
        .expect("Failed executing crashwise version");
    assert!(out_ver.status.success());
    let stdout_ver = String::from_utf8_lossy(&out_ver.stdout);
    assert!(stdout_ver.contains("0.2.0-dev"));

    // 2. Info command
    let out_info = Command::new(bin_path)
        .arg("info")
        .output()
        .expect("Failed executing crashwise info");
    assert!(out_info.status.success());
    let stdout_info = String::from_utf8_lossy(&out_info.stdout);
    assert!(stdout_info.contains("CrashWise Next-Gen Security Engine"));
    assert!(stdout_info.contains("LLM Provider:"));

    // 3. Doctor command
    let out_doc = Command::new(bin_path)
        .arg("doctor")
        .output()
        .expect("Failed executing crashwise doctor");
    assert!(out_doc.status.success());
    let stdout_doc = String::from_utf8_lossy(&out_doc.stdout);
    assert!(stdout_doc.contains("Clang compiler"));
    assert!(stdout_doc.contains("CMake build tool"));
}

#[test]
fn test_adversarial_cli_scan_edge_cases() {
    let bin_path = env!("CARGO_BIN_EXE_crashwise");

    // 1. Non-existent path returns error exit code (1)
    let out_nonexistent = Command::new(bin_path)
        .arg("scan")
        .arg("/nonexistent/directory/path/that/cannot/exist")
        .output()
        .expect("Failed executing crashwise scan");
    assert_eq!(out_nonexistent.status.code(), Some(1));
    let stderr_nonexistent = String::from_utf8_lossy(&out_nonexistent.stderr);
    assert!(stderr_nonexistent.contains("does not exist"));

    // 2. Empty directory returns 0 functions cleanly
    let temp = tempdir().unwrap();
    let out_empty = Command::new(bin_path)
        .arg("scan")
        .arg(temp.path())
        .output()
        .expect("Failed executing crashwise scan on empty dir");
    assert!(out_empty.status.success());
    let stdout_empty = String::from_utf8_lossy(&out_empty.stdout);
    assert!(stdout_empty.contains("Discovered Functions: 0"));

    // 3. Directory with C source code returns accurate function count
    let c_code = r#"
#include <stdio.h>
int function_one(void) { return 1; }
int function_two(int a, int b) { return a + b; }
void function_three(void) { printf("hello\n"); }
"#;
    fs::write(temp.path().join("test.c"), c_code).unwrap();
    let out_c = Command::new(bin_path)
        .arg("scan")
        .arg(temp.path())
        .output()
        .expect("Failed executing crashwise scan on C code");
    assert!(out_c.status.success());
    let stdout_c = String::from_utf8_lossy(&out_c.stdout);
    assert!(stdout_c.contains("Discovered Functions: 3"));
    assert!(stdout_c.contains("function_one"));
    assert!(stdout_c.contains("function_two"));
    assert!(stdout_c.contains("function_three"));
}

#[test]
fn test_adversarial_cli_triage_and_reproduce_subcommands() {
    let bin_path = env!("CARGO_BIN_EXE_crashwise");
    let temp = tempdir().unwrap();

    // 1. Triage on non-sanitizer / empty file falls back to Unknown-Crash
    let empty_log = temp.path().join("empty.log");
    fs::write(&empty_log, "normal log with no crash").unwrap();

    let out_bad_triage = Command::new(bin_path)
        .arg("triage")
        .arg(&empty_log)
        .output()
        .expect("Failed executing triage on clean log");
    assert!(out_bad_triage.status.success());
    let stdout_bad = String::from_utf8_lossy(&out_bad_triage.stdout);
    assert!(stdout_bad.contains("Unknown-Crash"));

    // 2. Triage on valid ASan log generates standalone poc.c
    let asan_log = temp.path().join("asan.log");
    let asan_text = r#"
==999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 4 at 0x602000000010 thread T0
    #0 0x401234 in cJSON_ParseWithLength /src/cJSON.c:1042
    #1 0x402567 in main /src/main.c:20
"#;
    fs::write(&asan_log, asan_text).unwrap();

    let poc_out = temp.path().join("generated_poc.c");
    let out_good_triage = Command::new(bin_path)
        .arg("triage")
        .arg(&asan_log)
        .arg("--output")
        .arg(&poc_out)
        .output()
        .expect("Failed executing triage on ASan log");
    assert!(out_good_triage.status.success());
    let stdout_good = String::from_utf8_lossy(&out_good_triage.stdout);
    assert!(stdout_good.contains("heap-buffer-overflow"));
    assert!(stdout_good.contains("CWE-122"));
    assert!(poc_out.exists(), "generated_poc.c must be created");

    let poc_content = fs::read_to_string(&poc_out).unwrap();
    assert!(poc_content.contains("Auto-Generated Standalone PoC"));

    // 3. Reproduce clean C file
    let clean_c = temp.path().join("clean_poc.c");
    fs::write(&clean_c, "#include <stdio.h>\nint main(void) { printf(\"OK\\n\"); return 0; }\n").unwrap();

    let out_reproduce = Command::new(bin_path)
        .arg("reproduce")
        .arg(&clean_c)
        .output()
        .expect("Failed executing reproduce subcommand");
    assert!(out_reproduce.status.success());
    let stdout_reproduce = String::from_utf8_lossy(&out_reproduce.stdout);
    assert!(stdout_reproduce.contains("Clean execution (no crash)"));
}

#[tokio::test]
async fn test_adversarial_cli_benchmark_runner_offline_cjson() {
    let temp = tempdir().unwrap();
    let report_path = temp.path().join("cjson_bench_report.json");

    let options = BenchmarkOptions {
        target: "cjson".to_string(),
        timeout: 1,
        iterations: 1,
        output: Some(report_path.clone()),
        format: "json".to_string(),
        offline: true,
        targets_dir: Some(temp.path().join("targets")),
        verbose: false,
    };

    let report = BenchmarkRunner::run(options)
        .await
        .expect("BenchmarkRunner::run must succeed for cjson target");

    assert_eq!(report.summary.total_targets, 1);
    assert_eq!(report.summary.passed_targets, 1);
    assert_eq!(report.summary.failed_targets, 0);
    assert_eq!(report.targets[0].target, "cjson");
    assert_eq!(report.targets[0].cve, "CVE-2019-1010239");
    assert_eq!(report.targets[0].status, "PASSED");
    assert!(report.targets[0].triage_accuracy);
    assert!(report.targets[0].poc_reproduced);
    assert!(report.targets[0].patch_verified);
    assert!(report.targets[0].regression_passed);

    // Verify report written to disk
    assert!(report_path.exists(), "Report JSON must be written to disk");
    let json_data = fs::read_to_string(&report_path).unwrap();
    assert!(json_data.contains("CVE-2019-1010239"));
}
