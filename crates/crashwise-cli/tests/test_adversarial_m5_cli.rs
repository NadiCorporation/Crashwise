use crashwise_cli::benchmark::{BenchmarkOptions, BenchmarkReport, BenchmarkRunner};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[tokio::test]
async fn test_cli_benchmark_extreme_timeouts() {
    // 1. Zero timeout must be rejected with Err
    let opt_zero = BenchmarkOptions {
        target: "cjson".to_string(),
        timeout: 0,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: None,
        verbose: false,
    };
    let res_zero = BenchmarkRunner::run(opt_zero).await;
    assert!(res_zero.is_err());
    assert!(res_zero.unwrap_err().to_string().contains("greater than 0"));

    // 2. Ultra-short timeout (1s) should succeed with valid report
    let temp = tempdir().unwrap();
    let opt_one = BenchmarkOptions {
        target: "cjson".to_string(),
        timeout: 1,
        iterations: 1,
        output: None,
        format: "json".to_string(),
        offline: true,
        targets_dir: Some(temp.path().join("targets")),
        verbose: false,
    };
    let res_one = BenchmarkRunner::run(opt_one).await;
    assert!(res_one.is_ok(), "1s timeout benchmark should complete cleanly");
    let report = res_one.unwrap();
    assert_eq!(report.summary.passed_targets, 1);
    assert_eq!(report.summary.total_targets, 1);
}

#[tokio::test]
async fn test_cli_benchmark_case_insensitive_and_whitespace_targets() {
    let temp = tempdir().unwrap();
    let targets_dir = temp.path().join("targets");

    // Case 1: UPPERCASE target name
    let opt_upper = BenchmarkOptions {
        target: "CJSON".to_string(),
        timeout: 1,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir.clone()),
        verbose: false,
    };
    let res_upper = BenchmarkRunner::run(opt_upper).await;
    assert!(res_upper.is_ok(), "Uppercase target name 'CJSON' must be accepted");

    // Case 2: Target name with whitespace
    let opt_space = BenchmarkOptions {
        target: "  zlib  ".to_string(),
        timeout: 1,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir.clone()),
        verbose: false,
    };
    let res_space = BenchmarkRunner::run(opt_space).await;
    assert!(res_space.is_ok(), "Target name with leading/trailing spaces must be accepted");

    // Case 3: 'ALL' uppercase
    let opt_all = BenchmarkOptions {
        target: "ALL".to_string(),
        timeout: 1,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir.clone()),
        verbose: false,
    };
    let res_all = BenchmarkRunner::run(opt_all).await;
    assert!(res_all.is_ok(), "'ALL' target spec must be accepted");
    assert_eq!(res_all.unwrap().summary.total_targets, 4);
}

#[tokio::test]
async fn test_cli_benchmark_json_schema_completeness() {
    let temp = tempdir().unwrap();
    let report_file = temp.path().join("schema_test.json");

    let opt = BenchmarkOptions {
        target: "cjson".to_string(),
        timeout: 1,
        iterations: 1,
        output: Some(report_file.clone()),
        format: "json".to_string(),
        offline: true,
        targets_dir: Some(temp.path().join("targets")),
        verbose: false,
    };

    let report = BenchmarkRunner::run(opt).await.expect("Runner should succeed");
    assert!(report_file.exists());

    let json_text = fs::read_to_string(&report_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_text).expect("Must be valid JSON");

    // Verify top-level fields
    assert!(parsed.get("benchmark_version").is_some());
    assert!(parsed.get("timestamp").is_some());
    assert!(parsed.get("summary").is_some());
    assert!(parsed.get("targets").is_some());

    // Verify summary fields
    let summary = parsed.get("summary").unwrap();
    assert_eq!(summary["total_targets"], 1);
    assert_eq!(summary["passed_targets"], 1);
    assert_eq!(summary["failed_targets"], 0);
    assert_eq!(summary["success_rate"], 100.0);
    assert!(summary["avg_throughput_execs_sec"].as_f64().unwrap() > 1000.0);

    // Verify target fields
    let target = &parsed["targets"][0];
    assert_eq!(target["target"], "cjson");
    assert_eq!(target["cve"], "CVE-2019-1010239");
    assert_eq!(target["status"], "PASSED");
    assert_eq!(target["poc_reproduced"], true);
    assert_eq!(target["patch_verified"], true);
    assert_eq!(target["regression_passed"], true);
    assert_eq!(target["cwe_id"], "CWE-122");
    assert_eq!(target["cvss_score"], 8.8);

    // Verify round-trip deserialization into BenchmarkReport
    let roundtrip: BenchmarkReport = serde_json::from_str(&json_text).expect("Deserialization round-trip failed");
    assert_eq!(roundtrip.benchmark_version, report.benchmark_version);
    assert_eq!(roundtrip.summary.total_targets, report.summary.total_targets);
}

#[tokio::test]
async fn test_cli_binary_exit_codes_and_error_handling() {
    let cargo_bin = env!("CARGO_BIN_EXE_crashwise");

    // Case 1: Invalid target returns exit code 2
    let out_inv_target = Command::new(cargo_bin)
        .args(["benchmark", "--target", "totally_bogus_target"])
        .output()
        .expect("Failed to run binary");
    assert_eq!(out_inv_target.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out_inv_target.stderr);
    assert!(stderr.contains("Invalid target 'totally_bogus_target'"));

    // Case 2: Zero timeout returns exit code 2
    let out_zero_timeout = Command::new(cargo_bin)
        .args(["benchmark", "--timeout", "0"])
        .output()
        .expect("Failed to run binary");
    assert_eq!(out_zero_timeout.status.code(), Some(2));
    let stderr2 = String::from_utf8_lossy(&out_zero_timeout.stderr);
    assert!(stderr2.contains("greater than 0"));

    // Case 3: Scan on nonexistent path returns exit code 1
    let out_scan = Command::new(cargo_bin)
        .args(["scan", "/nonexistent/path/123"])
        .output()
        .expect("Failed to run binary");
    assert_eq!(out_scan.status.code(), Some(1));
    let stderr3 = String::from_utf8_lossy(&out_scan.stderr);
    assert!(stderr3.contains("does not exist"));

    // Case 4: Reproduce on nonexistent file returns exit code 1
    let out_repro = Command::new(cargo_bin)
        .args(["reproduce", "/nonexistent/poc.c"])
        .output()
        .expect("Failed to run binary");
    assert_eq!(out_repro.status.code(), Some(1));

    // Case 5: Triage on nonexistent log returns exit code 1
    let out_triage = Command::new(cargo_bin)
        .args(["triage", "/nonexistent/log.txt"])
        .output()
        .expect("Failed to run binary");
    assert_eq!(out_triage.status.code(), Some(1));

    // Case 6: Verify on nonexistent paths returns exit code 1
    let out_verify = Command::new(cargo_bin)
        .args(["verify", "/nonexistent/target", "/nonexistent/poc.c", "/nonexistent/patch"])
        .output()
        .expect("Failed to run binary");
    assert_eq!(out_verify.status.code(), Some(1));
}
