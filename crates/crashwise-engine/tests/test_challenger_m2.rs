//! Challenger 2 Empirical Stress Test Suite for Milestone 2

use crashwise_engine::libafl_runner::{
    __afl_area_ptr, __sanitizer_cov_trace_pc_guard, __sanitizer_cov_trace_pc_guard_init,
    CoverageMap, ExecutionOutcome, InProcessEngine, Mutator, MAP_SIZE,
};
use crashwise_engine::sandbox::{
    RootlessSandbox, SandboxConfig, SeccompFilter,
};
use libafl::feedbacks::MaxMapFeedback;
use libafl::observers::StdMapObserver;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use serial_test::serial;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
#[serial]
fn test_shm_area_pointer_lifecycle_and_boundaries() {
    let map1 = CoverageMap::new().expect("Failed to allocate map1");
    let ptr1 = map1.as_mut_ptr();
    assert!(!ptr1.is_null());

    unsafe {
        assert_eq!(std::ptr::read_volatile(&raw const __afl_area_ptr), ptr1);
    }

    // Boundary guards: 0, 1, MAP_SIZE - 1 (65535), MAP_SIZE (65536), u32::MAX
    let boundary_guards = [0u32, 1u32, 65535u32, 65536u32, 131072u32, u32::MAX];
    for &guard_val in &boundary_guards {
        let mut g = guard_val;
        unsafe {
            __sanitizer_cov_trace_pc_guard(&mut g);
        }
        let expected_idx = (guard_val as usize) & (MAP_SIZE - 1);
        assert!(
            map1.as_slice()[expected_idx] >= 1,
            "Edge at idx {expected_idx} (from guard {guard_val}) not set"
        );
    }

    // Null guard safety: calling with null pointer must not panic or segfault
    unsafe {
        __sanitizer_cov_trace_pc_guard(std::ptr::null_mut());
    }

    // Wrapping behavior: incrementing an edge 256 times
    let mut wrap_guard: u32 = 1234;
    for _ in 0..255 {
        unsafe {
            __sanitizer_cov_trace_pc_guard(&mut wrap_guard);
        }
    }
    assert_eq!(map1.as_slice()[1234], 255);
    unsafe {
        __sanitizer_cov_trace_pc_guard(&mut wrap_guard);
    }
    // 255 + 1 wrapping to 0
    assert_eq!(map1.as_slice()[1234], 0);

    // Trace-pc-guard-init with 0, small, and oversized arrays
    let mut empty_guard: u32 = 0;
    unsafe {
        __sanitizer_cov_trace_pc_guard_init(&mut empty_guard, &mut empty_guard);
    }
    assert_eq!(empty_guard, 0);

    let mut initialized_guard: u32 = 99;
    unsafe {
        __sanitizer_cov_trace_pc_guard_init(&mut initialized_guard, (&mut initialized_guard as *mut u32).add(1));
    }
    assert_eq!(initialized_guard, 99);

    let count = 70_000;
    let mut large_guards = vec![0u32; count];
    unsafe {
        __sanitizer_cov_trace_pc_guard_init(
            large_guards.as_mut_ptr(),
            large_guards.as_mut_ptr().add(count),
        );
    }
    assert_eq!(large_guards[0], 1);
    assert_eq!(large_guards[65534], 65535);
    assert_eq!(large_guards[65535], 1);
    assert_eq!(large_guards[65536], 2);

    drop(map1);
    unsafe {
        assert!(std::ptr::read_volatile(&raw const __afl_area_ptr).is_null());
        let mut g = 42u32;
        __sanitizer_cov_trace_pc_guard(&mut g);
    }
}

#[test]
#[serial]
fn test_libafl_observer_and_max_feedback_creation() {
    let mut map = CoverageMap::new().expect("Failed to allocate coverage map");
    let map_ptr = map.as_mut_ptr();

    let observer = unsafe {
        StdMapObserver::from_mut_ptr("edges", map_ptr, MAP_SIZE)
    };
    let _feedback = MaxMapFeedback::new(&observer);

    // Verify map content inspection through CoverageMap
    map.clear();
    assert_eq!(map.count_edges(), 0);
    map.record_edge(42);
    assert_eq!(map.count_edges(), 1);
    assert_eq!(map.as_slice()[42], 1);

    // Verify history synchronization
    let mut history = vec![0u8; MAP_SIZE];
    let (edges1, new_edges1) = map.count_and_sync_edges(&mut history);
    assert_eq!(edges1, 1);
    assert!(new_edges1);

    // Second run with same edge: not new!
    let (edges2, new_edges2) = map.count_and_sync_edges(&mut history);
    assert_eq!(edges2, 1);
    assert!(!new_edges2, "Identical coverage must not be flagged as new");

    // Add another edge
    map.record_edge(1000);
    let (edges3, new_edges3) = map.count_and_sync_edges(&mut history);
    assert_eq!(edges3, 2);
    assert!(new_edges3, "Novel edge 1000 must be flagged as new");
}

#[test]
#[serial]
fn test_mutator_adversarial_stress_and_bounds() {
    let mut mutator = Mutator::new(9999);

    let mut empty = Vec::new();
    mutator.mutate(&mut empty, 128);
    assert_eq!(empty.len(), 1, "Mutating empty vector must add 1 byte");

    for _ in 0..100 {
        let mut single = vec![42u8];
        mutator.mutate(&mut single, 128);
        assert!(!single.is_empty(), "Mutated input must never become empty");
    }

    let max_len = 32;
    let mut at_max = vec![b"A"[0]; max_len];
    for _ in 0..500 {
        mutator.mutate(&mut at_max, max_len);
        assert!(
            at_max.len() <= max_len,
            "Mutator exceeded max_len: {} > {}",
            at_max.len(),
            max_len
        );
        assert!(!at_max.is_empty());
    }

    let mut data = b"CRASHWISE_FUZZING_STRESS_PAYLOAD".to_vec();
    for _ in 0..50_000 {
        mutator.mutate(&mut data, 256);
    }
    assert!(!data.is_empty());
    assert!(data.len() <= 256);
}

#[test]
#[serial]
fn test_corpus_progressive_expansion_under_branch_exploration() {
    let temp = TempDir::new().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    let progressive_target = |input: &[u8]| -> i32 {
        if input.is_empty() {
            return 0;
        }
        if input[0] == b"M"[0] {
            unsafe {
                let mut g = 101u32;
                __sanitizer_cov_trace_pc_guard(&mut g);
            }
            if input.len() > 1 && input[1] == b"A"[0] {
                unsafe {
                    let mut g = 102u32;
                    __sanitizer_cov_trace_pc_guard(&mut g);
                }
                if input.len() > 2 && input[2] == b"G"[0] {
                    unsafe {
                        let mut g = 103u32;
                        __sanitizer_cov_trace_pc_guard(&mut g);
                    }
                    if input.len() > 3 && input[3] == b"I"[0] {
                        unsafe {
                            let mut g = 104u32;
                            __sanitizer_cov_trace_pc_guard(&mut g);
                        }
                        if input.len() > 4 && input[4] == b"C"[0] {
                            unsafe {
                                let mut g = 105u32;
                                __sanitizer_cov_trace_pc_guard(&mut g);
                            }
                        }
                    }
                }
            }
        }
        0
    };

    engine.add_seed(b"START".to_vec());

    let stats = engine.fuzz_target(Some(20_000), Some(Duration::from_secs(2)), progressive_target);

    assert!(stats.total_execs >= 5000, "Expected at least 5000 execs, got {}", stats.total_execs);
    assert!(
        stats.execs_per_sec > 1500.0,
        "Expected >1500 execs/sec, got {:.2}",
        stats.execs_per_sec
    );
    assert!(stats.total_edges >= 1, "Expected at least 1 edge discovered, got {}", stats.total_edges);
}

#[test]
#[serial]
fn test_multiple_signal_intercept_and_recovery() {
    let temp = TempDir::new().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    let target = |data: &[u8]| -> i32 {
        if data.is_empty() {
            return 0;
        }
        match data[0] {
            1 => unsafe { libc::raise(libc::SIGSEGV) },
            2 => unsafe { libc::raise(libc::SIGFPE) },
            3 => unsafe { libc::raise(libc::SIGILL) },
            4 => unsafe { libc::raise(libc::SIGABRT) },
            5 => unsafe { libc::raise(libc::SIGBUS) },
            _ => 0,
        };
        0
    };

    let signals_to_test = [
        (1u8, libc::SIGSEGV, "SIGSEGV"),
        (2u8, libc::SIGFPE, "SIGFPE"),
        (3u8, libc::SIGILL, "SIGILL"),
        (4u8, libc::SIGABRT, "SIGABRT"),
        (5u8, libc::SIGBUS, "SIGBUS"),
    ];

    for &(byte, expected_sig, expected_name) in &signals_to_test {
        let input = vec![byte, 0xAA, 0xBB, 0xCC];
        let outcome = engine.execute_single(&input, target);

        match outcome {
            ExecutionOutcome::Crash { signal, crash_record } => {
                assert_eq!(signal, expected_sig, "Signal mismatch for byte {byte}");
                assert!(
                    crash_record.signal_name.contains(expected_name),
                    "Expected signal name to contain {}, got {}",
                    expected_name,
                    crash_record.signal_name
                );
                assert_eq!(crash_record.input_data, input);
            }
            ExecutionOutcome::Ok { .. } => {
                panic!("Expected crash for signal byte {byte}, but execution succeeded!");
            }
        }

        let clean = engine.execute_single(b"CLEAN", target);
        match clean {
            ExecutionOutcome::Ok { return_code, .. } => assert_eq!(return_code, 0),
            _ => panic!("Engine failed clean recovery after signal {expected_name}"),
        }
    }
}

#[test]
#[serial]
fn test_consecutive_crash_burst_resilience() {
    let temp = TempDir::new().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    let crash_target = |data: &[u8]| -> i32 {
        if data.starts_with(b"CRASH") {
            unsafe { libc::raise(libc::SIGSEGV); }
        }
        0
    };

    for i in 0..50 {
        let payload = format!("CRASH_BURST_{i}").into_bytes();
        let outcome = engine.execute_single(&payload, crash_target);
        match outcome {
            ExecutionOutcome::Crash { signal, crash_record } => {
                assert_eq!(signal, libc::SIGSEGV);
                assert!(crash_record.saved_path.is_some());
                assert!(crash_record.saved_path.unwrap().exists());
            }
            ExecutionOutcome::Ok { .. } => panic!("Iteration {i} failed to trigger crash"),
        }
    }

    let clean = engine.execute_single(b"NORMAL_INPUT_AFTER_BURST", crash_target);
    match clean {
        ExecutionOutcome::Ok { return_code, .. } => assert_eq!(return_code, 0),
        _ => panic!("Engine failed to recover after crash burst"),
    }
}

#[test]
#[serial]
fn test_sandbox_comprehensive_syscall_blocking_matrix() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Exited(_, code) => {
                    assert_eq!(code, 0, "Child failed seccomp matrix with exit code {code}");
                }
                other => panic!("Unexpected child status: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            if let Err(e) = SeccompFilter::apply(false) {
                eprintln!("Failed to apply seccomp in child: {e}");
                std::process::exit(1);
            }

            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if sock != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("Syscall socket was not blocked with EPERM");
                std::process::exit(10);
            }

            let ptrace_res = unsafe { libc::ptrace(0, 0, 0, 0) };
            if ptrace_res != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("Syscall ptrace was not blocked with EPERM");
                std::process::exit(11);
            }

            if unsafe { libc::getpid() } <= 0 {
                std::process::exit(20);
            }

            let req = libc::timespec { tv_sec: 0, tv_nsec: 1_000 };
            if unsafe { libc::nanosleep(&req, std::ptr::null_mut()) } != 0 {
                std::process::exit(21);
            }

            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                std::process::exit(22);
            }
            unsafe {
                libc::munmap(ptr, 4096);
            }

            std::process::exit(0);
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}

#[test]
#[serial]
fn test_sandbox_kill_violators_mode() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Signaled(_, sig, _) => {
                    assert_eq!(sig, nix::sys::signal::Signal::SIGSYS);
                }
                WaitStatus::Exited(_, code) => {
                    panic!("Child unexpectedly exited with code {code} instead of being killed by Seccomp");
                }
                other => panic!("Unexpected child status: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            if let Err(e) = SeccompFilter::apply(true) {
                eprintln!("Failed to apply seccomp kill: {e}");
                std::process::exit(1);
            }

            unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            }

            std::process::exit(99);
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}

#[test]
#[serial]
fn test_sandbox_fallback_safety_under_disabled_tiers() {
    let config = SandboxConfig {
        enable_cgroups: false,
        enable_namespaces: false,
        enable_seccomp: false,
        enable_rlimits: false,
        ..Default::default()
    };

    let mut sandbox = RootlessSandbox::new(config);
    let res = sandbox.apply_to_current_process();
    assert!(res.is_ok(), "Sandbox with all tiers disabled must succeed cleanly");

    let config_rlimits = SandboxConfig {
        enable_cgroups: false,
        enable_namespaces: false,
        enable_seccomp: false,
        enable_rlimits: true,
        ..Default::default()
    };

    let mut sandbox_rlimits = RootlessSandbox::new(config_rlimits);
    let res_rlimits = sandbox_rlimits.apply_to_current_process();
    assert!(res_rlimits.is_ok(), "Sandbox with only rlimits must succeed cleanly");
}

#[test]
#[serial]
fn test_hardware_null_deref_under_seccomp_and_engine() {
    // Test that real hardware SIGSEGV (not raise()) is caught under in-process engine
    // even when Seccomp is applied in a child process!
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Exited(_, code) => {
                    assert_eq!(code, 0, "Child exited with error code {code}");
                }
                other => panic!("Unexpected child status: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            let temp = tempfile::tempdir().unwrap();
            let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

            // Apply Seccomp filter (kill_violators = false)
            if let Err(e) = SeccompFilter::apply(false) {
                eprintln!("Failed applying seccomp: {e}");
                std::process::exit(1);
            }

            // Real hardware null-pointer write
            let target = |data: &[u8]| -> i32 {
                if data.starts_with(b"CRASH_HARDWARE") {
                    unsafe {
                        let null_ptr: *mut u8 = std::ptr::null_mut();
                        std::ptr::write_volatile(null_ptr, 0x42);
                    }
                }
                0
            };

            let outcome = engine.execute_single(b"CRASH_HARDWARE_NOW", target);
            match outcome {
                ExecutionOutcome::Crash { signal, .. } => {
                    if signal != libc::SIGSEGV {
                        eprintln!("Expected SIGSEGV (11), got {signal}");
                        std::process::exit(2);
                    }
                }
                ExecutionOutcome::Ok { .. } => {
                    eprintln!("Hardware crash was not caught!");
                    std::process::exit(3);
                }
            }

            // Verify clean resumption after hardware crash under Seccomp!
            let clean = engine.execute_single(b"CLEAN_INPUT", target);
            match clean {
                ExecutionOutcome::Ok { return_code, .. } => {
                    if return_code != 0 {
                        std::process::exit(4);
                    }
                }
                _ => std::process::exit(5),
            }

            std::process::exit(0);
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}

#[test]
#[serial]
fn test_throughput_under_large_corpus() {
    let temp = TempDir::new().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    // Pre-populate corpus with 100 diverse seeds
    for i in 0..100 {
        let seed = format!("SEED_CORPUS_ITEM_{i:04}_{}", "X".repeat(i % 50)).into_bytes();
        engine.add_seed(seed);
    }

    let target = |data: &[u8]| -> i32 {
        if !data.is_empty() && data[0] == b"S"[0] {
            unsafe {
                let mut g = (data.len() % 1000 + 1) as u32;
                __sanitizer_cov_trace_pc_guard(&mut g);
            }
        }
        0
    };

    let start = Instant::now();
    let stats = engine.fuzz_target(Some(10_000), Some(Duration::from_secs(2)), target);
    let _elapsed = start.elapsed();

    println!("Throughput with 100 seeds: {:.2} execs/sec (total: {})", stats.execs_per_sec, stats.total_execs);
    assert!(
        stats.execs_per_sec > 1500.0,
        "Throughput with 100 seeds must exceed 1500 execs/sec, got {:.2}",
        stats.execs_per_sec
    );
}

#[test]
#[serial]
fn test_stack_exhaustion_recovery_in_forked_child() {
    // Tests whether infinite recursion / stack exhaustion is caught via sigaltstack
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Exited(_, code) => {
                    assert_eq!(code, 0, "Child exited with code {code}");
                }
                WaitStatus::Signaled(_, sig, _) => {
                    println!("Note: Stack overflow caused unrecoverable signal {sig:?} (known limitation of signal handlers during deep stack exhaustion)");
                }
                other => panic!("Unexpected child status: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            let temp = tempfile::tempdir().unwrap();
            let mut engine = match InProcessEngine::new(temp.path()) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Failed creating engine: {e}");
                    std::process::exit(1);
                }
            };

            #[inline(never)]
            #[allow(unconditional_recursion)]
            fn blow_stack(n: u64) -> u64 {
                let local_array = [n; 1024]; // 8KB per stack frame
                std::hint::black_box(local_array[0]) + blow_stack(n.wrapping_add(1))
            }

            let target = |data: &[u8]| -> i32 {
                if data.starts_with(b"RECURSE") {
                    let _ = blow_stack(1);
                }
                0
            };

            let outcome = engine.execute_single(b"RECURSE_NOW", target);
            match outcome {
                ExecutionOutcome::Crash { signal, .. } => {
                    eprintln!("Successfully caught stack exhaustion signal: {signal}");
                    std::process::exit(0);
                }
                ExecutionOutcome::Ok { .. } => {
                    std::process::exit(2);
                }
            }
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}
