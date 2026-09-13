use crashwise_engine::libafl_runner::{
    __afl_area_ptr, __sanitizer_cov_trace_pc_guard, __sanitizer_cov_trace_pc_guard_init,
    CoverageMap, ExecutionOutcome, InProcessEngine, Mutator, MAP_SIZE,
};
use crashwise_engine::FuzzRunner;
use serial_test::serial;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Test target simulating a binary parser with branch coverage.
fn sample_parser(data: &[u8]) -> i32 {
    if data.len() < 4 {
        return 0;
    }
    if data[0] == b'C' {
        unsafe {
            let mut g1: u32 = 10;
            __sanitizer_cov_trace_pc_guard(&mut g1);
        }
        if data[1] == b'R' {
            unsafe {
                let mut g2: u32 = 20;
                __sanitizer_cov_trace_pc_guard(&mut g2);
            }
            if data[2] == b'A' {
                unsafe {
                    let mut g3: u32 = 30;
                    __sanitizer_cov_trace_pc_guard(&mut g3);
                }
                if data[3] == b'W' {
                    unsafe {
                        let mut g4: u32 = 40;
                        __sanitizer_cov_trace_pc_guard(&mut g4);
                    }
                }
            }
        }
    }
    0
}

#[test]
#[serial]
fn test_coverage_bitmap_allocation_and_hooks() {

    let mut map = CoverageMap::new().expect("Failed allocating shared memory coverage map");
    assert_eq!(map.as_slice().len(), MAP_SIZE);

    // Initial state must be completely zeroed
    assert_eq!(map.count_edges(), 0);

    // Verify global __afl_area_ptr points to the mapped area
    unsafe {
        let ptr = std::ptr::read_volatile(&raw const __afl_area_ptr);
        assert_eq!(ptr, map.as_mut_ptr());
    }


    // Verify trace-pc-guard hook
    unsafe {
        let mut guard: u32 = 42;
        __sanitizer_cov_trace_pc_guard(&mut guard);
    }
    assert_eq!(map.count_edges(), 1);
    assert_eq!(map.as_slice()[42], 1);

    // Clear bitmap
    map.clear();
    assert_eq!(map.count_edges(), 0);
    assert_eq!(map.as_slice()[42], 0);

    // Verify trace-pc-guard-init
    let mut guards = [0u32; 8];
    unsafe {
        __sanitizer_cov_trace_pc_guard_init(guards.as_mut_ptr(), guards.as_mut_ptr().add(guards.len()));
    }
    for (i, &g) in guards.iter().enumerate() {
        assert_eq!(g, (i + 1) as u32);
    }
}

#[test]
#[serial]
fn test_libafl_feedback_integration() {
    let temp = TempDir::new().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");
    assert!(engine.verify_libafl_feedback());
}

#[test]
fn test_mutator_behavior() {
    let mut mutator = Mutator::new(42);
    let original = b"HELLO_WORLD_TEST_SEED".to_vec();

    let mut mutated_count = 0;
    for _ in 0..100 {
        let mut copy = original.clone();
        mutator.mutate(&mut copy, 64);
        if copy != original {
            mutated_count += 1;
        }
    }

    // At least 95 out of 100 mutations must alter the input
    assert!(mutated_count >= 95, "Mutator failed to produce diverse mutations: {}/100", mutated_count);
}

#[test]
#[serial]
fn test_inprocess_crash_handling_and_recovery() {
    let temp = TempDir::new().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    // Target that raises SIGSEGV on specific input
    let target = |data: &[u8]| -> i32 {
        if data.starts_with(b"CRASH_TEST_PAYLOAD") {
            unsafe {
                libc::raise(libc::SIGSEGV);
            }
        }
        0
    };

    // 1. Clean input
    let clean_res = engine.execute_single(b"NORMAL_INPUT", target);
    match clean_res {
        ExecutionOutcome::Ok { return_code, .. } => {
            assert_eq!(return_code, 0);
        }
        _ => panic!("Expected clean execution outcome"),
    }

    // 2. Crashing input
    let crash_res = engine.execute_single(b"CRASH_TEST_PAYLOAD_WITH_DATA", target);
    match crash_res {
        ExecutionOutcome::Crash { signal, crash_record } => {
            assert_eq!(signal, libc::SIGSEGV);
            assert!(crash_record.signal_name.contains("SIGSEGV"));
            assert!(crash_record.saved_path.is_some());

            let saved_path = crash_record.saved_path.unwrap();
            assert!(saved_path.exists());
            let saved_content = std::fs::read(&saved_path).unwrap();
            assert_eq!(saved_content, b"CRASH_TEST_PAYLOAD_WITH_DATA");
        }
        _ => panic!("Expected crash outcome for crashing payload"),
    }

    // 3. Post-crash resilience: verify engine continues executing cleanly after crash!
    let resume_res = engine.execute_single(b"CLEAN_AFTER_CRASH", target);
    match resume_res {
        ExecutionOutcome::Ok { return_code, .. } => {
            assert_eq!(return_code, 0);
        }
        _ => panic!("Engine failed to resume execution after crash"),
    }
}

#[test]
#[serial]
fn test_single_core_throughput_benchmark_exceeds_1500_execs() {
    let temp = TempDir::new().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    engine.add_seed(b"CRAW".to_vec());
    engine.add_seed(b"SEED_START".to_vec());

    println!("\n=== Starting LibAFL In-Process Throughput Benchmark ===");
    let benchmark_start = Instant::now();

    // Run for either 15,000 executions or 2 seconds
    let stats = engine.fuzz_target(Some(15_000), Some(Duration::from_secs(2)), sample_parser);

    let _total_elapsed = benchmark_start.elapsed();
    println!("Benchmark Complete:");
    println!("  Total Executions:   {}", stats.total_execs);
    println!("  Elapsed Time:       {:.4}s", stats.elapsed.as_secs_f64());
    println!("  Throughput:         {:.2} execs/sec", stats.execs_per_sec);
    println!("  Cumulative Edges:   {}", stats.total_edges);
    println!("  Corpus Size:        {}", stats.new_edge_finds);
    println!("=======================================================\n");


    // Acceptance Criterion: Execution throughput > 1,500 execs/sec on single core
    assert!(
        stats.execs_per_sec > 1500.0,
        "Throughput criterion failed: {:.2} execs/sec <= 1500.0 execs/sec",
        stats.execs_per_sec
    );
    assert!(stats.total_execs >= 1500, "Insufficient executions completed: {}", stats.total_execs);
}

#[test]
#[serial]
fn test_fuzz_runner_inprocess_integration() {

    let temp = TempDir::new().unwrap();
    let corpus_dir = temp.path().join("corpus");
    let crashes_dir = temp.path().join("crashes");

    let runner = FuzzRunner::new(2);
    let result = runner.run_inprocess_fuzz(&corpus_dir, &crashes_dir, Some(3000), sample_parser)
        .expect("run_inprocess_fuzz failed");

    assert_eq!(result.exit_status, Some(0));
    assert!(result.total_execs.unwrap() >= 3000);
    assert!(result.execs_per_sec.unwrap() > 1500.0);
    assert!(result.output_logs.contains("Throughput:"));
}
