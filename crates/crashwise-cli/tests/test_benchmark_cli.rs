use crashwise_cli::benchmark::{BenchmarkOptions, BenchmarkReport, BenchmarkRunner};
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_benchmark_runner_single_target_cjson_offline() {
    let temp = tempdir().unwrap();
    let targets_dir = temp.path().join("targets");

    let options = BenchmarkOptions {
        target: "cjson".to_string(),
        timeout: 2,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir),
        verbose: false,
    };

    let report = BenchmarkRunner::run(options).await.expect("Benchmark run failed");
    assert_eq!(report.summary.total_targets, 1);
    assert_eq!(report.summary.passed_targets, 1);
    assert_eq!(report.summary.failed_targets, 0);
    assert_eq!(report.summary.success_rate, 100.0);

    let target = &report.targets[0];
    assert_eq!(target.target, "cjson");
    assert_eq!(target.cve, "CVE-2019-1010239");
    assert_eq!(target.status, "PASSED");
    assert!(target.poc_reproduced);
    assert!(target.patch_verified);
    assert!(target.regression_passed);
    assert!(target.triage_accuracy);
    assert!(target.throughput_execs_sec > 1000.0);
}

#[tokio::test]
async fn test_benchmark_runner_zlib_offline() {
    let temp = tempdir().unwrap();
    let targets_dir = temp.path().join("targets");

    let options = BenchmarkOptions {
        target: "zlib".to_string(),
        timeout: 2,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir),
        verbose: false,
    };

    let report = BenchmarkRunner::run(options).await.expect("Benchmark run failed");
    if let Some(t) = report.targets.first() {
        if let Some(ref r) = t.failure_reason {
            println!("ZLIB FAILURE REASON: {}", r);
        }
    }
    assert_eq!(report.summary.passed_targets, 1);

    let target = &report.targets[0];
    assert_eq!(target.target, "zlib");
    assert_eq!(target.cve, "CVE-2022-37434");
    assert_eq!(target.status, "PASSED");
    assert!(target.poc_reproduced);
    assert!(target.patch_verified);
    assert!(target.regression_passed);
}

#[tokio::test]
async fn test_benchmark_runner_libpng_offline() {
    let temp = tempdir().unwrap();
    let targets_dir = temp.path().join("targets");

    let options = BenchmarkOptions {
        target: "libpng".to_string(),
        timeout: 2,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir),
        verbose: false,
    };

    let report = BenchmarkRunner::run(options).await.expect("Benchmark run failed");
    assert_eq!(report.summary.passed_targets, 1);

    let target = &report.targets[0];
    assert_eq!(target.target, "libpng");
    assert_eq!(target.cve, "CVE-2019-7317");
    assert_eq!(target.status, "PASSED");
    assert!(target.poc_reproduced);
    assert!(target.patch_verified);
}

#[tokio::test]
async fn test_benchmark_runner_sqlite3_offline() {
    let temp = tempdir().unwrap();
    let targets_dir = temp.path().join("targets");

    let options = BenchmarkOptions {
        target: "sqlite3".to_string(),
        timeout: 2,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir),
        verbose: false,
    };

    let report = BenchmarkRunner::run(options).await.expect("Benchmark run failed");
    if let Some(t) = report.targets.first() {
        if let Some(ref r) = t.failure_reason {
            println!("SQLITE3 FAILURE REASON: {}", r);
        }
    }
    assert_eq!(report.summary.passed_targets, 1);

    let target = &report.targets[0];
    assert_eq!(target.target, "sqlite3");
    assert_eq!(target.cve, "CVE-2022-35737");
    assert_eq!(target.status, "PASSED");
    assert!(target.poc_reproduced);
    assert!(target.patch_verified);
}

#[tokio::test]
async fn test_benchmark_runner_output_file_generation() {
    let temp = tempdir().unwrap();
    let targets_dir = temp.path().join("targets");
    let out_file = temp.path().join("nested").join("results.json");

    let options = BenchmarkOptions {
        target: "cjson".to_string(),
        timeout: 2,
        iterations: 1,
        output: Some(out_file.clone()),
        format: "json".to_string(),
        offline: true,
        targets_dir: Some(targets_dir),
        verbose: false,
    };

    let report = BenchmarkRunner::run(options).await.expect("Benchmark run failed");
    assert!(out_file.exists());

    let file_content = fs::read_to_string(&out_file).unwrap();
    let parsed: BenchmarkReport = serde_json::from_str(&file_content).unwrap();
    assert_eq!(parsed.summary.total_targets, report.summary.total_targets);
    assert_eq!(parsed.targets[0].cve, "CVE-2019-1010239");
}

#[tokio::test]
async fn test_benchmark_runner_zero_timeout_rejected() {
    let options = BenchmarkOptions {
        target: "cjson".to_string(),
        timeout: 0,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: None,
        verbose: false,
    };

    let result = BenchmarkRunner::run(options).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("greater than 0"));
}

#[tokio::test]
async fn test_benchmark_runner_invalid_target_rejected() {
    let options = BenchmarkOptions {
        target: "invalid_pkg_123".to_string(),
        timeout: 10,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: None,
        verbose: false,
    };

    let result = BenchmarkRunner::run(options).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Invalid target"));
}

#[tokio::test]
async fn test_benchmark_all_targets_offline() {
    let temp = tempdir().unwrap();
    let targets_dir = temp.path().join("targets");

    let options = BenchmarkOptions {
        target: "all".to_string(),
        timeout: 2,
        iterations: 1,
        output: None,
        format: "table".to_string(),
        offline: true,
        targets_dir: Some(targets_dir),
        verbose: false,
    };

    let report = BenchmarkRunner::run(options).await.expect("Benchmark run failed");
    assert_eq!(report.summary.total_targets, 4);
    assert_eq!(report.summary.passed_targets, 4);
    assert_eq!(report.summary.failed_targets, 0);
    assert_eq!(report.summary.success_rate, 100.0);
    assert!(report.summary.avg_throughput_execs_sec > 1500.0);

    for target in &report.targets {
        assert_eq!(target.status, "PASSED");
        assert!(target.poc_reproduced);
        assert!(target.patch_verified);
    }
}
