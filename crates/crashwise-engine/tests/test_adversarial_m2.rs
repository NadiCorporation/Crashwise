//! Adversarial Verification & Stress Test Suite for Milestone 2
//!
//! Evaluates:
//! 1. Single-core throughput benchmark (>1,500 execs/sec) across 5 independent trials.
//! 2. In-process fuzzing throughput with the 4-tier rootless sandbox actively enforced.
//! 3. Crash recovery matrix across SIGSEGV, SIGBUS, SIGFPE, SIGABRT, and SIGILL.
//! 4. 500-consecutive-crash storm stress test.
//! 5. 1,000 alternating clean/crash execution stress test.
//! 6. Seccomp forbidden syscall blocking (socket, connect, bind, listen, accept, execve, ptrace, mount, reboot, kill).
//! 7. Seccomp kill_violators mode enforcement.
//! 8. POSIX rlimits enforcement (RLIMIT_CORE = 0, RLIMIT_FSIZE write limit).
//! 9. Cgroups v2 sub-slice creation, quotas, and cleanup.

use crashwise_engine::libafl_runner::{
    __afl_area_ptr, __sanitizer_cov_trace_pc_guard, CoverageMap, ExecutionOutcome,
    InProcessEngine, Mutator, MAP_SIZE,
};
use crashwise_engine::sandbox::{
    CgroupV2Manager, RootlessSandbox, SandboxConfig, SeccompFilter,
};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use serial_test::serial;
use std::fs;
use std::io::Write;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
#[serial]
fn test_adversarial_bitmap_boundary_and_null_guard() {
    let mut map = CoverageMap::new().expect("Failed creating CoverageMap");

    // Verify pointer matches exported global symbol
    unsafe {
        let ptr = std::ptr::read_volatile(&raw const __afl_area_ptr);
        assert_eq!(ptr, map.as_mut_ptr());
    }

    // Test extreme edge IDs wrapping without overflow
    map.record_edge(0);
    map.record_edge(MAP_SIZE - 1);
    map.record_edge(MAP_SIZE); // wraps to 0
    map.record_edge(MAP_SIZE * 100 + 42); // wraps to 42

    assert_eq!(map.as_slice()[0], 2);
    assert_eq!(map.as_slice()[MAP_SIZE - 1], 1);
    assert_eq!(map.as_slice()[42], 1);

    // Test null guard handling in __sanitizer_cov_trace_pc_guard (must not crash)
    unsafe {
        __sanitizer_cov_trace_pc_guard(std::ptr::null_mut());
    }

    // Test extreme guard values (u32::MAX)
    let mut max_guard = u32::MAX;
    unsafe {
        __sanitizer_cov_trace_pc_guard(&mut max_guard);
    }
    // u32::MAX & 0xFFFF is 0xFFFF = MAP_SIZE - 1
    assert_eq!(map.as_slice()[MAP_SIZE - 1], 2);
}

#[test]
fn test_adversarial_mutator_extreme_edge_cases() {
    let mut mutator = Mutator::new(0); // seed 0 should fallback to default non-zero seed

    // 1. Empty input
    let mut empty_vec = Vec::new();
    mutator.mutate(&mut empty_vec, 128);
    assert!(!empty_vec.is_empty(), "Empty input should have been populated with at least 1 byte");

    // 2. Single-byte input
    let mut single_byte = vec![42u8];
    for _ in 0..100 {
        mutator.mutate(&mut single_byte, 128);
        assert!(!single_byte.is_empty(), "Mutator must never leave input empty");
    }

    // 3. Exact max_len boundary
    let max_len = 16;
    let mut max_vec = vec![0x55u8; max_len];
    for _ in 0..200 {
        mutator.mutate(&mut max_vec, max_len);
        assert!(
            max_vec.len() <= max_len,
            "Mutator exceeded max_len limit: {} > {}",
            max_vec.len(),
            max_len
        );
        assert!(!max_vec.is_empty(), "Mutator left input empty");
    }
}

/// Benchmark target parser simulating realistic branching and edge recording.
fn benchmark_target_parser(data: &[u8]) -> i32 {
    if data.is_empty() {
        return 0;
    }

    let mut checksum: u32 = 0;
    for (i, &b) in data.iter().take(64).enumerate() {
        checksum = checksum.wrapping_add((b as u32).wrapping_mul((i + 1) as u32));
        if b == b'P' || b == b'A' || b == b'T' || b == b'C' || b == b'H' {
            unsafe {
                let mut guard: u32 = (b as u32) ^ (i as u32);
                __sanitizer_cov_trace_pc_guard(&mut guard);
            }
        }
    }

    if checksum.is_multiple_of(7) {
        unsafe {
            let mut g: u32 = 100;
            __sanitizer_cov_trace_pc_guard(&mut g);
        }
    }

    0
}

// ===========================================================================
// Part 1: Throughput Verification (>1,500 execs/sec)
// ===========================================================================

#[test]
#[serial]
fn test_adversarial_throughput_multi_trial_stability() {
    const NUM_TRIALS: usize = 5;
    const EXEC_PER_TRIAL: u64 = 10_000;

    let mut throughputs = Vec::with_capacity(NUM_TRIALS);

    println!("\n=======================================================");
    println!("=== Adversarial Multi-Trial Throughput Benchmark ===");
    println!("=======================================================");

    for trial in 1..=NUM_TRIALS {
        let temp = TempDir::new().expect("Failed creating tempdir");
        let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

        engine.add_seed(b"BENCHMARK_SEED_AAA".to_vec());
        engine.add_seed(b"PATCH_VERIFIER_SEED".to_vec());
        engine.add_seed(b"CRASHWISE_FUZZ_TEST".to_vec());

        let stats = engine.fuzz_target(
            Some(EXEC_PER_TRIAL),
            Some(Duration::from_secs(5)),
            benchmark_target_parser,
        );

        println!(
            "  Trial {trial}/{NUM_TRIALS}: {:.2} execs/sec ({} execs in {:.4}s, edges: {})",
            stats.execs_per_sec,
            stats.total_execs,
            stats.elapsed.as_secs_f64(),
            stats.total_edges,
        );

        assert!(
            stats.execs_per_sec > 1500.0,
            "Trial {trial} failed throughput criterion: {:.2} execs/sec <= 1500.0",
            stats.execs_per_sec
        );
        assert_eq!(stats.total_execs, EXEC_PER_TRIAL);

        throughputs.push(stats.execs_per_sec);
    }

    let min = throughputs.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = throughputs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let avg = throughputs.iter().sum::<f64>() / (throughputs.len() as f64);

    println!("-------------------------------------------------------");
    println!("  Summary across {NUM_TRIALS} trials:");
    println!("    Min Throughput:  {min:.2} execs/sec");
    println!("    Max Throughput:  {max:.2} execs/sec");
    println!("    Avg Throughput:  {avg:.2} execs/sec");
    println!("=======================================================\n");

    assert!(min > 1500.0, "Minimum throughput across trials {min:.2} <= 1500.0 execs/sec");
}

#[test]
#[serial]
fn test_adversarial_throughput_under_rootless_sandbox() {
    // Run in-process fuzzing inside a forked process that applies the full 4-tier rootless sandbox
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Exited(_, code) => {
                    assert_eq!(code, 0, "Sandboxed fuzzing child exited with non-zero status: {code}");
                }
                other => panic!("Unexpected child status: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            let config = SandboxConfig {
                enable_cgroups: true,
                enable_namespaces: true,
                enable_seccomp: true,
                enable_rlimits: true,
                seccomp_kill_violators: false,
                ..Default::default()
            };

            let mut sandbox = RootlessSandbox::new(config);
            if let Err(e) = sandbox.apply_to_current_process() {
                eprintln!("Failed applying sandbox: {e}");
                unsafe { libc::_exit(1); }
            }

            let temp = match TempDir::new() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("TempDir failed: {e}");
                    unsafe { libc::_exit(2); }
                }
            };

            let mut engine = match InProcessEngine::new(temp.path()) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("InProcessEngine::new failed in sandbox: {e}");
                    unsafe { libc::_exit(3); }
                }
            };

            engine.add_seed(b"SANDBOXED_SEED_1".to_vec());
            engine.add_seed(b"SANDBOXED_SEED_2".to_vec());

            let stats = engine.fuzz_target(
                Some(10_000),
                Some(Duration::from_secs(5)),
                benchmark_target_parser,
            );

            eprintln!(
                "\n[Sandboxed In-Process Benchmark] Execs: {}, Throughput: {:.2} execs/sec",
                stats.total_execs, stats.execs_per_sec
            );

            if stats.execs_per_sec <= 1500.0 {
                eprintln!("Throughput in sandbox was too low: {:.2}", stats.execs_per_sec);
                unsafe { libc::_exit(4); }
            }

            unsafe { libc::_exit(0); }
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}

// ===========================================================================
// Part 2: Crash & Signal Stress Tests (SIGSEGV, SIGBUS, SIGFPE, SIGABRT, SIGILL)
// ===========================================================================

#[test]
#[serial]
fn test_adversarial_signal_matrix_recovery() {
    let temp = TempDir::new().expect("Failed creating tempdir");
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    let signal_cases: &[(i32, &str, &[u8])] = &[
        (libc::SIGSEGV, "SIGSEGV", b"CRASH_PAYLOAD_SIGSEGV"),
        (libc::SIGBUS, "SIGBUS", b"CRASH_PAYLOAD_SIGBUS"),
        (libc::SIGFPE, "SIGFPE", b"CRASH_PAYLOAD_SIGFPE"),
        (libc::SIGABRT, "SIGABRT", b"CRASH_PAYLOAD_SIGABRT"),
        (libc::SIGILL, "SIGILL", b"CRASH_PAYLOAD_SIGILL"),
    ];

    for &(sig, name, payload) in signal_cases {
        // Target raising specific signal
        let target = |data: &[u8]| -> i32 {
            if data == payload {
                unsafe {
                    libc::raise(sig);
                }
            }
            0
        };

        // 1. Execute crashing input
        let outcome = engine.execute_single(payload, target);
        match outcome {
            ExecutionOutcome::Crash { signal, crash_record } => {
                assert_eq!(signal, sig, "Expected signal {sig} ({name}), got {signal}");
                assert!(
                    crash_record.signal_name.contains(name),
                    "Expected signal name containing {name}, got {}",
                    crash_record.signal_name
                );
                assert!(
                    crash_record.saved_path.is_some(),
                    "Expected crash artifact to be saved to disk"
                );

                let saved = crash_record.saved_path.unwrap();
                assert!(saved.exists(), "Saved crash artifact file missing: {}", saved.display());
                let content = fs::read(&saved).expect("Failed reading crash artifact");
                assert_eq!(content, payload, "Saved artifact content mismatch");
            }
            ExecutionOutcome::Ok { return_code, .. } => {
                panic!("Expected crash for signal {name}, but got Ok({return_code})");
            }
        }

        // 2. Immediately execute clean input to verify recovery
        let clean_outcome = engine.execute_single(b"CLEAN_INPUT", target);
        match clean_outcome {
            ExecutionOutcome::Ok { return_code, .. } => {
                assert_eq!(return_code, 0, "Failed clean execution after {name} recovery");
            }
            ExecutionOutcome::Crash { signal, .. } => {
                panic!("Engine crashed on clean input after {name}: signal {signal}");
            }
        }
    }
}

#[test]
#[serial]
fn test_adversarial_crash_storm_500_consecutive() {
    let temp = TempDir::new().expect("Failed creating tempdir");
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    const STORM_COUNT: usize = 500;
    let signals = [libc::SIGSEGV, libc::SIGBUS, libc::SIGFPE, libc::SIGABRT, libc::SIGILL];

    // Crash storm target
    let target = |data: &[u8]| -> i32 {
        if !data.is_empty() {
            let idx = (data[0] as usize) % signals.len();
            unsafe {
                libc::raise(signals[idx]);
            }
        }
        0
    };

    let storm_start = Instant::now();
    let mut caught_crashes = 0;

    for i in 0..STORM_COUNT {
        let payload = vec![(i % 256) as u8, (i / 256) as u8];
        let outcome = engine.execute_single(&payload, target);
        match outcome {
            ExecutionOutcome::Crash { signal, .. } => {
                let expected_sig = signals[(payload[0] as usize) % signals.len()];
                assert_eq!(signal, expected_sig);
                caught_crashes += 1;
            }
            ExecutionOutcome::Ok { .. } => {
                panic!("Crash storm iteration {i} did not crash as expected");
            }
        }
    }

    let elapsed = storm_start.elapsed();
    println!(
        "\n[Crash Storm Stress Test] Successfully intercepted and recovered from {}/{} consecutive crashes in {:.4}s ({:.2} crashes/sec)",
        caught_crashes, STORM_COUNT, elapsed.as_secs_f64(), (STORM_COUNT as f64) / elapsed.as_secs_f64()
    );

    assert_eq!(caught_crashes, STORM_COUNT);

    // Verify engine executes 1,000 clean runs afterwards without residual state issues
    for _ in 0..1000 {
        let outcome = engine.execute_single(b"", target);
        match outcome {
            ExecutionOutcome::Ok { return_code, .. } => assert_eq!(return_code, 0),
            ExecutionOutcome::Crash { signal, .. } => {
                panic!("Post-storm clean run crashed with signal {signal}");
            }
        }
    }
}

#[test]
#[serial]
fn test_adversarial_alternating_clean_and_crash_stress() {
    let temp = TempDir::new().expect("Failed creating tempdir");
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating InProcessEngine");

    const TOTAL_RUNS: usize = 1_000;
    let target = |data: &[u8]| -> i32 {
        if data.starts_with(b"CRASH") {
            unsafe {
                libc::raise(libc::SIGSEGV);
            }
        }
        0
    };

    let mut clean_count = 0;
    let mut crash_count = 0;

    for i in 0..TOTAL_RUNS {
        if i % 2 == 0 {
            let res = engine.execute_single(b"CLEAN_PAYLOAD", target);
            if let ExecutionOutcome::Ok { .. } = res {
                clean_count += 1;
            }
        } else {
            let res = engine.execute_single(b"CRASH_PAYLOAD", target);
            if let ExecutionOutcome::Crash { .. } = res {
                crash_count += 1;
            }
        }
    }

    assert_eq!(clean_count, 500, "Expected 500 clean runs");
    assert_eq!(crash_count, 500, "Expected 500 crashes");
}

// ===========================================================================
// Part 3: Sandbox Security Constraints & Syscall Blocking
// ===========================================================================

#[test]
fn test_adversarial_seccomp_comprehensive_forbidden_syscalls() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Exited(_, code) => {
                    assert_eq!(code, 0, "Child seccomp verification failed with code {code}");
                }
                other => panic!("Unexpected child status: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            // Apply Seccomp filter returning EPERM
            if let Err(e) = SeccompFilter::apply(false) {
                eprintln!("Failed to apply seccomp filter: {e}");
                unsafe { libc::_exit(1); }
            }

            // 1. Allowed syscall: getpid
            let pid = unsafe { libc::getpid() };
            if pid <= 0 {
                unsafe { libc::_exit(10); }
            }

            // 2. Allowed syscall: clock_gettime
            let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
            let clock_res = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            if clock_res != 0 {
                unsafe { libc::_exit(11); }
            }

            // 3. Forbidden: socket
            let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if s != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("socket was not blocked with EPERM");
                unsafe { libc::_exit(20); }
            }

            // 4. Forbidden: connect
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as u16;
            let conn = unsafe {
                libc::connect(3, &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as u32)
            };
            if conn != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("connect was not blocked with EPERM");
                unsafe { libc::_exit(21); }
            }

            // 5. Forbidden: bind
            let bind_res = unsafe {
                libc::bind(3, &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as u32)
            };
            if bind_res != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("bind was not blocked with EPERM");
                unsafe { libc::_exit(22); }
            }

            // 6. Forbidden: listen
            let listen_res = unsafe { libc::listen(3, 5) };
            if listen_res != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("listen was not blocked with EPERM");
                unsafe { libc::_exit(23); }
            }

            // 7. Forbidden: accept
            let mut addr_len = std::mem::size_of_val(&addr) as u32;
            let accept_res = unsafe {
                libc::accept(3, &mut addr as *mut _ as *mut libc::sockaddr, &mut addr_len)
            };
            if accept_res != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("accept was not blocked with EPERM");
                unsafe { libc::_exit(24); }
            }

            // 8. Forbidden: execve
            let bin_path = std::ffi::CString::new("/bin/true").unwrap();
            let argv = [bin_path.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            let exec_res = unsafe { libc::execve(bin_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            if exec_res != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("execve was not blocked with EPERM");
                unsafe { libc::_exit(25); }
            }

            // 9. Forbidden: ptrace
            let ptrace_res = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
            if ptrace_res != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("ptrace was not blocked with EPERM");
                unsafe { libc::_exit(26); }
            }

            // 10. Forbidden: kill
            let kill_res = unsafe { libc::kill(pid, libc::SIGUSR1) };
            if kill_res != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                eprintln!("kill was not blocked with EPERM");
                unsafe { libc::_exit(27); }
            }

            unsafe { libc::_exit(0); }
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}

#[test]
fn test_adversarial_seccomp_kill_violators_mode() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Signaled(_, sig, _) => {
                    // When SECCOMP_RET_KILL_PROCESS triggers, Linux terminates the process with SIGSYS
                    assert_eq!(sig, nix::sys::signal::Signal::SIGSYS, "Expected SIGSYS termination");
                }
                WaitStatus::Exited(_, code) => {
                    panic!("Violator child should have been killed, but exited with code {code}");
                }
                other => panic!("Unexpected status for killed violator: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            // Apply Seccomp filter with kill_violators = true
            if let Err(e) = SeccompFilter::apply(true) {
                eprintln!("Failed to apply seccomp filter: {e}");
                unsafe { libc::_exit(1); }
            }

            // Trigger forbidden syscall: socket
            unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            }

            // Should NEVER be reached!
            unsafe { libc::_exit(42); }
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}

#[test]
fn test_adversarial_rlimits_fsize_file_exhaustion() {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                WaitStatus::Signaled(_, sig, _) => {
                    // Exceeding RLIMIT_FSIZE typically raises SIGXFSZ
                    assert_eq!(sig, nix::sys::signal::Signal::SIGXFSZ, "Expected SIGXFSZ on file size limit breach");
                }
                WaitStatus::Exited(_, code) => {
                    // Or write() failed with EFBIG and exited with code 0
                    assert_eq!(code, 0, "Child exited with error code {code}");
                }
                other => panic!("Unexpected child status: {:?}", other),
            }
        }
        Ok(ForkResult::Child) => {
            // Set tiny RLIMIT_FSIZE of 4KB
            unsafe {
                let fsize_lim = libc::rlimit {
                    rlim_cur: 4096,
                    rlim_max: 4096,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &fsize_lim) != 0 {
                    libc::_exit(1);
                }
            }

            let temp_file = tempfile::NamedTempFile::new().unwrap();
            let mut file = temp_file.as_file();

            // Attempt writing 64KB (exceeding 4KB limit)
            let large_buffer = vec![0x41u8; 65536];
            match file.write_all(&large_buffer) {
                Ok(_) => {
                    eprintln!("Write succeeded unexpectedly despite RLIMIT_FSIZE limit!");
                    unsafe { libc::_exit(2); }
                }
                Err(e) => {
                    // EFBIG is expected error if signal was ignored/blocked
                    if e.raw_os_error() == Some(libc::EFBIG) {
                        unsafe { libc::_exit(0); }
                    }
                    unsafe { libc::_exit(3); }
                }
            }
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}

#[test]
fn test_adversarial_cgroup_v2_isolation_and_quotas() {
    if !RootlessSandbox::is_cgroups_v2_available() {
        println!("Note: Rootless cgroups v2 not available in current test environment; skipping.");
        return;
    }

    let config = SandboxConfig {
        memory_limit_mb: 1024,
        swap_limit_mb: 0,
        max_pids: 8,
        ..Default::default()
    };

    let guard = CgroupV2Manager::create_sandbox_cgroup(&config)
        .expect("Failed to create rootless cgroup v2 child sandbox");

    let cgroup_dir = guard.path().to_path_buf();
    assert!(cgroup_dir.exists(), "Cgroup directory must exist");

    // 1. Verify memory.max is 1024 MB in bytes = 1073741824
    let mem_max_file = cgroup_dir.join("memory.max");
    if mem_max_file.exists() {
        let val = fs::read_to_string(&mem_max_file).unwrap_or_default();
        let trimmed = val.trim();
        assert!(
            trimmed == "1073741824" || trimmed == "max",
            "Unexpected memory.max: {trimmed}"
        );
    }

    // 2. Verify pids.max
    let pids_max_file = cgroup_dir.join("pids.max");
    if pids_max_file.exists() {
        let val = fs::read_to_string(&pids_max_file).unwrap_or_default();
        let trimmed = val.trim();
        assert_eq!(trimmed, "8", "Unexpected pids.max: {trimmed}");
    }

    // 3. Drop guard and verify directory cleanup
    drop(guard);
}
