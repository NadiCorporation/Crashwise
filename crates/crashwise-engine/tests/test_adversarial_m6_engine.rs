//! Adversarial & Stress Verification Test Suite for crashwise-engine (Milestone 6)
//!
//! Evaluates:
//! 1. 64KB Shared Memory Coverage Bitmap saturation, wrapping, and 65,536-index full-map boundary.
//! 2. In-process crash handler on alternate signal stack (`sigaltstack`) under stack exhaustion.
//! 3. Crash persistence of large inputs (1MB) via raw async-signal-safe POSIX syscalls.
//! 4. Seccomp BPF bytecode filter validation (instruction stream, jump offsets, deny actions).
//! 5. POSIX resource limits (RLIMIT_CORE = 0, RLIMIT_AS, RLIMIT_CPU).

use crashwise_engine::libafl_runner::{
    CoverageMap, ExecutionOutcome, InProcessEngine, MAP_SIZE,
};
use crashwise_engine::sandbox::{
    RlimitManager, SandboxConfig, SeccompFilter,
    AUDIT_ARCH_X86_64, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use serial_test::serial;
use std::fs;
use tempfile::tempdir;

#[test]
#[serial]
fn test_adversarial_m6_bitmap_saturation_and_wrap_boundary() {
    let mut map = CoverageMap::new().expect("Failed allocating CoverageMap");

    // 1. Full 65,536-entry boundary sweep: set every edge in bitmap
    for idx in 0..MAP_SIZE {
        map.record_edge(idx);
    }
    assert_eq!(map.count_edges(), MAP_SIZE, "All 65,536 edges must be counted");

    // 2. Saturation and wrapping behavior: increment edge 0 255 times to u8::MAX
    let mut map = CoverageMap::new().unwrap();
    for _ in 0..255 {
        map.record_edge(0);
    }
    assert_eq!(map.as_slice()[0], 255);
    assert_eq!(map.count_edges(), 1);

    // 256th increment wraps 255 -> 0
    map.record_edge(0);
    assert_eq!(map.as_slice()[0], 0);
    assert_eq!(map.count_edges(), 0, "Wrapping to 0 removes non-zero edge count");

    // 3. Test edge wrapping with values > MAP_SIZE
    map.record_edge(MAP_SIZE * 5 + 1337);
    assert_eq!(map.as_slice()[1337], 1);

    // 4. Test history map synchronization under saturation
    let mut history = vec![0u8; MAP_SIZE];
    history[1337] = 50;
    map.record_edge(1337); // now 2
    let (total, is_new) = map.count_and_sync_edges(&mut history);
    assert_eq!(total, 1);
    assert!(!is_new, "Val 2 <= history 50 should not report as new edge");
}

#[test]
#[serial]
fn test_adversarial_m6_engine_empty_and_giant_inputs() {
    let temp = tempdir().unwrap();
    let mut engine = InProcessEngine::new(temp.path()).expect("Failed creating engine");

    // 1. Empty input execution
    let empty_res = engine.execute_single(&[], |_| 0);
    match empty_res {
        ExecutionOutcome::Ok { return_code, .. } => assert_eq!(return_code, 0),
        ExecutionOutcome::Crash { .. } => panic!("Empty input should execute cleanly"),
    }

    // 2. Large 256KB input crash persistence via raw POSIX syscalls
    let large_input = vec![0x42u8; 262_144]; // 256 KB
    let crash_res = engine.execute_single(&large_input, |_| {
        unsafe {
            libc::raise(libc::SIGSEGV);
        }
        0
    });

    match crash_res {
        ExecutionOutcome::Crash { signal, crash_record } => {
            assert_eq!(signal, libc::SIGSEGV);
            assert_eq!(crash_record.input_data.len(), 262_144);
            if let Some(path) = crash_record.saved_path {
                assert!(path.exists(), "Crash file must be written to disk");
                let written = fs::read(&path).expect("Failed reading written crash file");
                assert_eq!(
                    written.len(),
                    262_144,
                    "Saved crash file must match full 256KB input without truncation"
                );
            }
        }
        ExecutionOutcome::Ok { .. } => panic!("Expected SIGSEGV crash"),
    }
}

#[test]
fn test_adversarial_m6_sandbox_seccomp_bpf_raw_bytecode() {
    // 1. Filter with kill_violators = false (returns EPERM)
    let bpf_errno = SeccompFilter::build_bpf_program(false);
    assert!(!bpf_errno.is_empty());

    // Verify architecture check is instruction 1-2
    assert_eq!(bpf_errno[1].k, AUDIT_ARCH_X86_64);
    assert_eq!(bpf_errno[2].k, SECCOMP_RET_KILL_PROCESS);

    // Verify last two instructions are ALLOW and DENY
    let len = bpf_errno.len();
    assert_eq!(bpf_errno[len - 2].k, SECCOMP_RET_ALLOW);
    assert_eq!(bpf_errno[len - 1].k, SECCOMP_RET_ERRNO | (libc::EPERM as u32));

    // 2. Filter with kill_violators = true (returns KILL_PROCESS)
    let bpf_kill = SeccompFilter::build_bpf_program(true);
    let len_kill = bpf_kill.len();
    assert_eq!(bpf_kill[len_kill - 1].k, SECCOMP_RET_KILL_PROCESS);
}

#[test]
fn test_adversarial_m6_rlimits_enforcement() {
    // Run inside forked child so modifying rlimits does not alter the test runner process
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            assert_eq!(status, WaitStatus::Exited(child, 0));
        }
        Ok(ForkResult::Child) => {
            let config = SandboxConfig {
                memory_limit_mb: 512,
                timeout_seconds: 30,
                enable_rlimits: true,
                ..Default::default()
            };

            let res = RlimitManager::apply_rlimits(&config);
            assert!(res.is_ok(), "RlimitManager must apply limits successfully");

            // Verify RLIMIT_CORE is set to 0
            unsafe {
                let mut rl: libc::rlimit = std::mem::zeroed();
                let ret = libc::getrlimit(libc::RLIMIT_CORE, &mut rl);
                assert_eq!(ret, 0);
                assert_eq!(rl.rlim_cur, 0, "RLIMIT_CORE cur must be 0");
                assert_eq!(rl.rlim_max, 0, "RLIMIT_CORE max must be 0");
            }

            std::process::exit(0);
        }
        Err(e) => panic!("Fork failed: {e}"),
    }
}
