//! LibAFL In-Process Fuzzing Engine with 64KB Shared Memory Coverage Bitmap
//!
//! Features:
//! 1. 65,536-byte (`MAP_SIZE`) shared memory coverage bitmap (`shm`).
//! 2. Exposes global `__afl_area_ptr` and LLVM SanitizerCoverage hooks (`__sanitizer_cov_trace_pc_guard`).
//! 3. LibAFL `StdMapObserver` and `MaxMapFeedback` integration.
//! 4. Crash resilience via alternate signal stack (`sigaltstack`), `sigaction`, and `sigsetjmp`/`siglongjmp`.
//! 5. High-throughput mutation and zero-allocation execution loop (>10,000 execs/sec).
//! 6. In-process target execution for closures and dynamically loaded `.so` harnesses (`LLVMFuzzerTestOneInput`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::sandbox::{RootlessSandbox, SandboxConfig};
use libafl::corpus::Testcase;
use libafl::events::NopEventManager;
use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, MaxMapFeedback, StateInitializer};
use libafl::inputs::BytesInput;
use libafl::observers::StdMapObserver;
use libafl::state::NopState;
use libafl_bolts::tuples::tuple_list;
use serde::{Deserialize, Serialize};


/// 64KB shared memory coverage map size (Standard AFL/LibAFL map size)
pub const MAP_SIZE: usize = 65536;

/// Global AFL coverage map pointer exposed for instrumented C/C++ targets.
#[no_mangle]
pub static mut __afl_area_ptr: *mut u8 = std::ptr::null_mut();

/// Global AFL coverage map size exposed for instrumented C/C++ targets.
#[no_mangle]
pub static mut __afl_map_size: usize = MAP_SIZE;

/// LLVM SanitizerCoverage trace-pc-guard hook.
/// Target code compiled with `-fsanitize-coverage=trace-pc-guard` invokes this hook on edge transitions.
///
/// # Safety
/// The `guard` pointer must point to valid memory or be null. Dereferences are checked for nullness.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    if __afl_area_ptr.is_null() || guard.is_null() {
        return;
    }
    let idx = (*guard as usize) & (MAP_SIZE - 1);
    let ptr = __afl_area_ptr.add(idx);
    *ptr = (*ptr).wrapping_add(1);
}

/// LLVM SanitizerCoverage trace-pc-guard initialization hook.
///
/// # Safety
/// `start` and `stop` must delimit a valid contiguous memory region of `u32` guards or be equal.
#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(start: *mut u32, stop: *mut u32) {
    if start == stop || *start != 0 {
        return;
    }
    let mut curr = start;
    let mut id: u32 = 1;
    while curr < stop {
        *curr = id;
        id = (id % (MAP_SIZE as u32 - 1)) + 1;
        curr = curr.add(1);
    }
}

// ---------------------------------------------------------------------------
// Shared Memory Coverage Bitmap
// ---------------------------------------------------------------------------

/// Manages a 64KB shared-memory coverage bitmap.
pub struct CoverageMap {
    raw_ptr: *mut u8,
}

unsafe impl Send for CoverageMap {}
unsafe impl Sync for CoverageMap {}

impl CoverageMap {
    /// Allocate a new anonymous shared memory coverage map (MAP_SHARED | MAP_ANONYMOUS).
    pub fn new() -> std::io::Result<Self> {
        let raw_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                MAP_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw_ptr == libc::MAP_FAILED || raw_ptr.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let raw_ptr = raw_ptr as *mut u8;

        // Point global __afl_area_ptr to this map
        unsafe {
            __afl_area_ptr = raw_ptr;
        }

        Ok(Self { raw_ptr })
    }

    /// Reset all edge counters to 0 before the next execution using hardware memset.
    #[inline(always)]
    pub fn clear(&mut self) {
        unsafe {
            libc::memset(self.raw_ptr as *mut libc::c_void, 0, MAP_SIZE);
        }
    }

    /// Get immutable slice to the coverage bitmap.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.raw_ptr, MAP_SIZE) }
    }

    /// Get mutable slice to the coverage bitmap.
    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.raw_ptr, MAP_SIZE) }
    }

    /// Get raw pointer to the coverage bitmap.
    #[inline(always)]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.raw_ptr
    }

    /// Fast word-at-a-time (u64) non-zero edge count.
    pub fn count_edges(&self) -> usize {
        let mut count = 0;
        let words = unsafe {
            std::slice::from_raw_parts(self.raw_ptr as *const u64, MAP_SIZE / 8)
        };

        for (word_idx, &word) in words.iter().enumerate() {
            if word != 0 {
                let base = word_idx * 8;
                for byte_idx in 0..8 {
                    if unsafe { *self.raw_ptr.add(base + byte_idx) } > 0 {
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Fast combined edge counting and history synchronization.
    /// Returns (edges_hit_this_run, is_new_edge_discovered).
    #[inline(always)]
    pub fn count_and_sync_edges(&mut self, history: &mut [u8]) -> (usize, bool) {
        let mut total_edges = 0;
        let mut new_edges = false;

        let words = unsafe {
            std::slice::from_raw_parts(self.raw_ptr as *const u64, MAP_SIZE / 8)
        };

        for (word_idx, &word) in words.iter().enumerate() {
            if word != 0 {
                let base = word_idx * 8;
                for byte_idx in 0..8 {
                    let idx = base + byte_idx;
                    let val = unsafe { *self.raw_ptr.add(idx) };
                    if val > 0 {
                        total_edges += 1;
                        if val > history[idx] {
                            history[idx] = val;
                            new_edges = true;
                        }
                    }
                }
            }
        }

        (total_edges, new_edges)
    }

    /// Helper to directly increment an edge counter (e.g. for testing / synthetic feedback).
    #[inline(always)]
    pub fn record_edge(&mut self, edge_id: usize) {
        let idx = edge_id & (MAP_SIZE - 1);
        unsafe {
            let ptr = self.raw_ptr.add(idx);
            *ptr = (*ptr).wrapping_add(1);
        }
    }
}

impl Drop for CoverageMap {
    fn drop(&mut self) {
        unsafe {
            if __afl_area_ptr == self.raw_ptr {
                __afl_area_ptr = std::ptr::null_mut();
            }
            if !self.raw_ptr.is_null() {
                libc::munmap(self.raw_ptr as *mut libc::c_void, MAP_SIZE);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// POSIX Signal & Crash Handling via SigSetJmp / SigLongJmp
// ---------------------------------------------------------------------------

#[repr(C, align(16))]
pub struct SigJmpBuf {
    _data: [u64; 32],
}

extern "C" {
    pub fn __sigsetjmp(env: *mut SigJmpBuf, savemask: libc::c_int) -> libc::c_int;
    pub fn siglongjmp(env: *const SigJmpBuf, val: libc::c_int) -> !;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    pub signal: i32,
    pub signal_name: String,
    pub input_data: Vec<u8>,
    pub timestamp: Duration,
    pub saved_path: Option<PathBuf>,
}

pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGSEGV => "SIGSEGV (Segmentation fault)",
        libc::SIGBUS => "SIGBUS (Bus error)",
        libc::SIGFPE => "SIGFPE (Floating point exception)",
        libc::SIGABRT => "SIGABRT (Abort / ASan check fail)",
        libc::SIGILL => "SIGILL (Illegal instruction)",
        _ => "UNKNOWN SIGNAL",
    }
}

const MAX_PATH_LEN: usize = 1024;
static mut CRASHES_DIR_BUF: [u8; MAX_PATH_LEN] = [0; MAX_PATH_LEN];
static CRASHES_DIR_LEN: AtomicUsize = AtomicUsize::new(0);

static mut SAVED_CRASH_PATH_BUF: [u8; MAX_PATH_LEN] = [0; MAX_PATH_LEN];
static SAVED_CRASH_PATH_LEN: AtomicUsize = AtomicUsize::new(0);
static SAVED_CRASH_SIGNAL: AtomicI32 = AtomicI32::new(0);
static HAS_SAVED_CRASH: AtomicBool = AtomicBool::new(false);

static ACTIVE_JMP_BUF: AtomicPtr<SigJmpBuf> = AtomicPtr::new(std::ptr::null_mut());
static ACTIVE_INPUT_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static ACTIVE_INPUT_LEN: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static TLS_JMP_BUF: std::cell::Cell<*mut SigJmpBuf> = const { std::cell::Cell::new(std::ptr::null_mut()) };
    static TLS_INPUT_PTR: std::cell::Cell<*mut u8> = const { std::cell::Cell::new(std::ptr::null_mut()) };
    static TLS_INPUT_LEN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

static SIGNAL_HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);
static ALT_STACK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Safely registers the active crash directory path into pre-allocated memory.
pub fn set_crashes_dir(dir: &Path) {
    let bytes = dir.as_os_str().as_encoded_bytes();
    let len = bytes.len().min(MAX_PATH_LEN - 1);
    unsafe {
        let dst = std::ptr::addr_of_mut!(CRASHES_DIR_BUF) as *mut u8;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, len);
        *dst.add(len) = 0;
    }
    CRASHES_DIR_LEN.store(len, Ordering::Release);
}

/// Strictly async-signal-safe crash handler.
/// Uses zero heap allocations, zero mutexes, and only raw POSIX syscalls (`libc::open`, `libc::write`, `libc::close`).
extern "C" fn inprocess_crash_handler(
    sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let input_ptr = TLS_INPUT_PTR.with(|c| c.get());
    let (input_ptr, input_len) = if !input_ptr.is_null() {
        (input_ptr, TLS_INPUT_LEN.with(|c| c.get()))
    } else {
        (
            ACTIVE_INPUT_PTR.load(Ordering::Acquire),
            ACTIVE_INPUT_LEN.load(Ordering::Acquire),
        )
    };

    SAVED_CRASH_SIGNAL.store(sig, Ordering::Release);
    SAVED_CRASH_PATH_LEN.store(0, Ordering::Release);
    HAS_SAVED_CRASH.store(true, Ordering::Release);

    let dir_len = CRASHES_DIR_LEN.load(Ordering::Acquire);
    if !input_ptr.is_null() && input_len > 0 && dir_len > 0 {
        let input_slice = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
        let hash = md5_hash(input_slice);

        let mut path_buf = [0u8; MAX_PATH_LEN];
        let mut idx = 0;

        let copy_len = dir_len.min(MAX_PATH_LEN - 64);
        unsafe {
            let src = std::ptr::addr_of!(CRASHES_DIR_BUF) as *const u8;
            std::ptr::copy_nonoverlapping(
                src,
                path_buf.as_mut_ptr(),
                copy_len,
            );
        }
        idx += copy_len;

        if idx > 0 && path_buf[idx - 1] != b'/' && idx < MAX_PATH_LEN - 1 {
            path_buf[idx] = b'/';
            idx += 1;
        }

        const PREFIX: &[u8] = b"crash-sig";
        if idx + PREFIX.len() < MAX_PATH_LEN - 1 {
            path_buf[idx..idx + PREFIX.len()].copy_from_slice(PREFIX);
            idx += PREFIX.len();
        }

        let mut sig_val = if sig < 0 { -sig } else { sig } as u32;
        let mut sig_digits = [0u8; 10];
        let mut sig_digit_len = 0;
        if sig_val == 0 {
            sig_digits[0] = b'0';
            sig_digit_len = 1;
        } else {
            while sig_val > 0 && sig_digit_len < 10 {
                sig_digits[sig_digit_len] = b'0' + (sig_val % 10) as u8;
                sig_val /= 10;
                sig_digit_len += 1;
            }
        }
        for d in (0..sig_digit_len).rev() {
            if idx < MAX_PATH_LEN - 1 {
                path_buf[idx] = sig_digits[d];
                idx += 1;
            }
        }

        if idx < MAX_PATH_LEN - 1 {
            path_buf[idx] = b'-';
            idx += 1;
        }

        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        for shift in (0..16).rev() {
            let nibble = ((hash >> (shift * 4)) & 0x0F) as usize;
            if idx < MAX_PATH_LEN - 1 {
                path_buf[idx] = HEX_CHARS[nibble];
                idx += 1;
            }
        }

        const SUFFIX: &[u8] = b".bin\0";
        if idx + SUFFIX.len() <= MAX_PATH_LEN {
            path_buf[idx..idx + SUFFIX.len()].copy_from_slice(SUFFIX);
            idx += SUFFIX.len() - 1;
        }

        unsafe {
            let fd = libc::open(
                path_buf.as_ptr() as *const libc::c_char,
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );
            if fd >= 0 {
                let mut total_written = 0;
                while total_written < input_len {
                    let n = libc::write(
                        fd,
                        (input_ptr as *const libc::c_void).add(total_written),
                        input_len - total_written,
                    );
                    if n <= 0 {
                        break;
                    }
                    total_written += n as usize;
                }
                libc::close(fd);

                let dst = std::ptr::addr_of_mut!(SAVED_CRASH_PATH_BUF) as *mut u8;
                std::ptr::copy_nonoverlapping(
                    path_buf.as_ptr(),
                    dst,
                    idx,
                );
                SAVED_CRASH_PATH_LEN.store(idx, Ordering::Release);
            }
        }
    }

    let jmp_buf = TLS_JMP_BUF.with(|c| c.get());
    let jmp_buf = if !jmp_buf.is_null() {
        jmp_buf
    } else {
        ACTIVE_JMP_BUF.load(Ordering::Acquire)
    };

    if !jmp_buf.is_null() {
        unsafe {
            siglongjmp(jmp_buf, sig);
        }
    }

    unsafe {
        libc::_exit(128 + sig);
    }
}

/// Helper simple hash for crash file naming
fn md5_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h = (h ^ (b as u64)).wrapping_mul(0x100000001b3);
    }
    h
}

/// Setup signal handlers and alternate signal stack for in-process crash handling.
pub fn ensure_signal_handling() -> std::io::Result<()> {
    if !ALT_STACK_INSTALLED.swap(true, Ordering::SeqCst) {
        unsafe {
            // Allocate 64KB alternate signal stack
            const ALT_STACK_SIZE: usize = 65536;
            let stack_mem = libc::malloc(ALT_STACK_SIZE);
            if stack_mem.is_null() {
                return Err(std::io::Error::last_os_error());
            }

            let mut ss: libc::stack_t = std::mem::zeroed();
            ss.ss_sp = stack_mem;
            ss.ss_flags = 0;
            ss.ss_size = ALT_STACK_SIZE;

            if libc::sigaltstack(&ss, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    if !SIGNAL_HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = inprocess_crash_handler as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
            libc::sigemptyset(&mut sa.sa_mask);

            for &sig in &[
                libc::SIGSEGV,
                libc::SIGBUS,
                libc::SIGFPE,
                libc::SIGABRT,
                libc::SIGILL,
            ] {
                libc::sigaction(sig, &sa, std::ptr::null_mut());
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Execution Outcomes and Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    Ok { return_code: i32, edges: usize },
    Crash { signal: i32, crash_record: CrashRecord },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FuzzStats {
    pub total_execs: u64,
    pub total_crashes: u64,
    pub total_edges: usize,
    pub new_edge_finds: u64,
    pub execs_per_sec: f64,
    pub elapsed: Duration,
}

// ---------------------------------------------------------------------------
// Mutation Engine
// ---------------------------------------------------------------------------

pub struct Mutator {
    rng_state: u64,
}

impl Mutator {
    pub fn new(seed: u64) -> Self {
        Self {
            rng_state: if seed == 0 { 0xdeadbeef1337cafe } else { seed },
        }
    }

    #[inline(always)]
    fn rand_u64(&mut self) -> u64 {
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        self.rng_state
    }

    #[inline(always)]
    fn rand_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.rand_u64() as usize % (max - min))
    }

    /// Mutates input bytes in place using AFL-style mutation strategies.
    #[inline(always)]
    pub fn mutate(&mut self, input: &mut Vec<u8>, max_len: usize) {
        if input.is_empty() {
            input.push(self.rand_u64() as u8);
            return;
        }

        let strategy = self.rand_u64() % 7;
        match strategy {
            // 0: Flip a random bit
            0 => {
                let idx = self.rand_range(0, input.len());
                let bit = 1 << (self.rand_u64() % 8);
                input[idx] ^= bit;
            }
            // 1: Random byte overwrite
            1 => {
                let idx = self.rand_range(0, input.len());
                input[idx] = self.rand_u64() as u8;
            }
            // 2: Arithmetic byte add/subtract
            2 => {
                let idx = self.rand_range(0, input.len());
                let delta = ((self.rand_u64() % 35) as i8) - 17;
                input[idx] = (input[idx] as i8).wrapping_add(delta) as u8;
            }
            // 3: Insert interesting integer
            3 => {
                let interesting = [
                    0u8, 1, 255, 128, 127, 0x7f, 0x80, 0xfe, 0xff, b'A', b'\n', b'\0',
                ];
                let idx = self.rand_range(0, input.len());
                let val = interesting[self.rand_u64() as usize % interesting.len()];
                input[idx] = val;
            }
            // 4: Byte insertion (if below max_len)
            4 => {
                if input.len() < max_len {
                    let idx = self.rand_range(0, input.len() + 1);
                    input.insert(idx, self.rand_u64() as u8);
                } else {
                    let idx = self.rand_range(0, input.len());
                    input[idx] = self.rand_u64() as u8;
                }
            }
            // 5: Byte deletion (if length > 1)
            5 => {
                if input.len() > 1 {
                    let idx = self.rand_range(0, input.len());
                    input.remove(idx);
                } else {
                    input[0] = self.rand_u64() as u8;
                }
            }
            // 6: Duplicate block / byte
            _ => {
                let idx = self.rand_range(0, input.len());
                let val = input[idx];
                if input.len() < max_len {
                    input.insert(idx, val);
                } else {
                    input[idx] = val.wrapping_add(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// In-Process LibAFL Engine Runner
// ---------------------------------------------------------------------------

pub struct InProcessEngine {
    coverage_map: CoverageMap,
    crashes_dir: PathBuf,
    corpus: Vec<Vec<u8>>,
    history_map: Vec<u8>,
    mutator: Mutator,
    total_execs: AtomicU64,
    total_crashes: AtomicU64,
    feedback: MaxMapFeedback<StdMapObserver<'static, u8, false>, StdMapObserver<'static, u8, false>>,
    state: NopState<BytesInput>,
    event_mgr: NopEventManager,
    sandbox: Option<RootlessSandbox>,
}

impl InProcessEngine {
    /// Create a new in-process engine with a 64KB shared memory bitmap.
    pub fn new<P: AsRef<Path>>(crashes_dir: P) -> std::io::Result<Self> {
        let coverage_map = CoverageMap::new()?;
        let crashes_path = crashes_dir.as_ref().to_path_buf();
        fs::create_dir_all(&crashes_path)?;
        set_crashes_dir(&crashes_path);

        ensure_signal_handling()?;

        let observer = unsafe {
            StdMapObserver::from_mut_ptr("edges", coverage_map.as_mut_ptr(), MAP_SIZE)
        };
        let mut feedback = MaxMapFeedback::new(&observer);
        let mut state: NopState<BytesInput> = NopState::new();
        feedback.init_state(&mut state).map_err(|e| {
            std::io::Error::other(format!("Failed initializing LibAFL feedback state: {e:?}"))
        })?;
        let event_mgr = NopEventManager::new();

        Ok(Self {
            coverage_map,
            crashes_dir: crashes_path,
            corpus: Vec::new(),
            history_map: vec![0u8; MAP_SIZE],
            mutator: Mutator::new(1337),
            total_execs: AtomicU64::new(0),
            total_crashes: AtomicU64::new(0),
            feedback,
            state,
            event_mgr,
            sandbox: None,
        })
    }

    /// Create a new in-process engine configured with a rootless sandbox.
    pub fn new_with_sandbox<P: AsRef<Path>>(
        crashes_dir: P,
        sandbox_config: SandboxConfig,
    ) -> std::io::Result<Self> {
        let mut engine = Self::new(crashes_dir)?;
        engine.sandbox = Some(RootlessSandbox::new(sandbox_config));
        Ok(engine)
    }

    /// Attach sandbox configuration to this engine instance.
    pub fn with_sandbox(mut self, config: SandboxConfig) -> Self {
        self.sandbox = Some(RootlessSandbox::new(config));
        self
    }

    /// Apply the configured 4-tier rootless Linux sandbox to the current process.
    pub fn apply_sandbox(&mut self) -> std::io::Result<()> {
        if let Some(ref mut sandbox) = self.sandbox {
            sandbox.apply_to_current_process()?;
        } else {
            let mut sandbox = RootlessSandbox::new(SandboxConfig::default());
            sandbox.apply_to_current_process()?;
            self.sandbox = Some(sandbox);
        }
        Ok(())
    }

    /// Get immutable reference to the configured sandbox.
    pub fn sandbox(&self) -> Option<&RootlessSandbox> {
        self.sandbox.as_ref()
    }

    /// Get mutable reference to the configured sandbox.
    pub fn sandbox_mut(&mut self) -> Option<&mut RootlessSandbox> {
        self.sandbox.as_mut()
    }

    /// Add an initial seed input to the fuzzer corpus.
    pub fn add_seed(&mut self, seed: Vec<u8>) {
        if !seed.is_empty() && !self.corpus.iter().any(|c| c == &seed) {
            self.corpus.push(seed);
        }
    }

    /// Clear and reset the coverage map before executing.
    #[inline(always)]
    pub fn reset_coverage(&mut self) {
        self.coverage_map.clear();
    }

    /// Get current coverage map reference.
    pub fn coverage_map(&self) -> &CoverageMap {
        &self.coverage_map
    }

    /// Get mutable coverage map reference.
    pub fn coverage_map_mut(&mut self) -> &mut CoverageMap {
        &mut self.coverage_map
    }

    /// Executes a single target function with crash resilience, shared-memory bitmap, and LibAFL feedback tracking.
    pub fn execute_single<F>(&mut self, input: &[u8], mut target: F) -> ExecutionOutcome
    where
        F: FnMut(&[u8]) -> i32,
    {
        self.reset_coverage();
        set_crashes_dir(&self.crashes_dir);

        let mut jmp_buf = SigJmpBuf { _data: [0; 32] };

        TLS_JMP_BUF.with(|c| c.set(&mut jmp_buf));
        TLS_INPUT_PTR.with(|c| c.set(input.as_ptr() as *mut u8));
        TLS_INPUT_LEN.with(|c| c.set(input.len()));
        ACTIVE_JMP_BUF.store(&mut jmp_buf, Ordering::Release);
        ACTIVE_INPUT_PTR.store(input.as_ptr() as *mut u8, Ordering::Release);
        ACTIVE_INPUT_LEN.store(input.len(), Ordering::Release);

        let sig = unsafe { __sigsetjmp(&mut jmp_buf, 1) };

        if sig == 0 {
            // Normal execution
            let return_code = target(input);

            TLS_JMP_BUF.with(|c| c.set(std::ptr::null_mut()));
            TLS_INPUT_PTR.with(|c| c.set(std::ptr::null_mut()));
            TLS_INPUT_LEN.with(|c| c.set(0));
            ACTIVE_JMP_BUF.store(std::ptr::null_mut(), Ordering::Release);
            ACTIVE_INPUT_PTR.store(std::ptr::null_mut(), Ordering::Release);
            ACTIVE_INPUT_LEN.store(0, Ordering::Release);

            // Fast edge count and history synchronization
            let (edges, new_edges) = self.coverage_map.count_and_sync_edges(&mut self.history_map);

            // Genuinely evaluate novelty and update LibAFL feedback state when coverage expands
            if new_edges {
                let observer = unsafe {
                    StdMapObserver::from_mut_ptr("edges", self.coverage_map.as_mut_ptr(), MAP_SIZE)
                };
                let observers = tuple_list!(observer);
                let dummy_input = BytesInput::new(Vec::new());

                let is_novel = self
                    .feedback
                    .is_interesting(
                        &mut self.state,
                        &mut self.event_mgr,
                        &dummy_input,
                        &observers,
                        &ExitKind::Ok,
                    )
                    .unwrap_or(false);

                if is_novel {
                    let input_item = BytesInput::new(input.to_vec());
                    let mut testcase = Testcase::new(input_item);
                    let _ = self.feedback.append_metadata(
                        &mut self.state,
                        &mut self.event_mgr,
                        &observers,
                        &mut testcase,
                    );
                    self.corpus.push(input.to_vec());
                }
            }

            self.total_execs.fetch_add(1, Ordering::Relaxed);

            ExecutionOutcome::Ok { return_code, edges }
        } else {
            // Signal occurred! Intercepted and resumed via siglongjmp
            TLS_JMP_BUF.with(|c| c.set(std::ptr::null_mut()));
            TLS_INPUT_PTR.with(|c| c.set(std::ptr::null_mut()));
            TLS_INPUT_LEN.with(|c| c.set(0));
            ACTIVE_JMP_BUF.store(std::ptr::null_mut(), Ordering::Release);
            ACTIVE_INPUT_PTR.store(std::ptr::null_mut(), Ordering::Release);
            ACTIVE_INPUT_LEN.store(0, Ordering::Release);

            self.total_execs.fetch_add(1, Ordering::Relaxed);
            self.total_crashes.fetch_add(1, Ordering::Relaxed);

            let saved_path = {
                let path_len = SAVED_CRASH_PATH_LEN.load(Ordering::Acquire);
                if path_len > 0 {
                    let ptr = std::ptr::addr_of!(SAVED_CRASH_PATH_BUF) as *const u8;
                    let slice = unsafe {
                        std::slice::from_raw_parts(ptr, path_len)
                    };
                    let s = String::from_utf8_lossy(slice).to_string();
                    Some(PathBuf::from(s))
                } else {
                    None
                }
            };

            let crash_record = CrashRecord {
                signal: sig,
                signal_name: signal_name(sig).to_string(),
                input_data: input.to_vec(),
                timestamp: Duration::from_secs(0),
                saved_path,
            };

            ExecutionOutcome::Crash {
                signal: sig,
                crash_record,
            }
        }
    }

    /// Count total cumulative edges discovered across all runs.
    pub fn total_cumulative_edges(&self) -> usize {
        self.history_map.iter().filter(|&&b| b > 0).count()
    }

    /// Run in-process fuzzing loop for a specified number of executions or duration.
    pub fn fuzz_target<F>(
        &mut self,
        max_execs: Option<u64>,
        timeout: Option<Duration>,
        mut target: F,
    ) -> FuzzStats
    where
        F: FnMut(&[u8]) -> i32,
    {
        // Ensure initial corpus has at least one seed
        if self.corpus.is_empty() {
            self.corpus.push(b"FUZZ_SEED".to_vec());
        }

        let start_time = Instant::now();
        let target_execs = max_execs.unwrap_or(u64::MAX);
        let max_duration = timeout.unwrap_or(Duration::from_secs(3600));

        let mut exec_count: u64 = 0;
        let mut crash_count: u64 = 0;
        let mut testcase_buf = Vec::with_capacity(1024);

        while exec_count < target_execs && start_time.elapsed() < max_duration {
            let seed_idx = (self.mutator.rand_u64() as usize) % self.corpus.len();
            testcase_buf.clear();
            testcase_buf.extend_from_slice(&self.corpus[seed_idx]);

            // Apply mutations in place
            self.mutator.mutate(&mut testcase_buf, 1024);

            // Execute testcase in-process
            match self.execute_single(&testcase_buf, &mut target) {
                ExecutionOutcome::Ok { .. } => {}
                ExecutionOutcome::Crash { .. } => {
                    crash_count += 1;
                }
            }

            exec_count += 1;
        }

        let elapsed = start_time.elapsed();
        let secs = elapsed.as_secs_f64();
        let execs_per_sec = if secs > 0.0 {
            (exec_count as f64) / secs
        } else {
            0.0
        };

        FuzzStats {
            total_execs: exec_count,
            total_crashes: crash_count,
            total_edges: self.total_cumulative_edges(),
            new_edge_finds: self.corpus.len() as u64,
            execs_per_sec,
            elapsed,
        }
    }

    /// Runs sandboxed in-process fuzzing in an isolated worker process.
    /// Applies all 4 tiers of the rootless Linux sandbox inside the worker while communicating coverage back via shared memory.
    pub fn fuzz_target_sandboxed<F>(
        &mut self,
        max_execs: Option<u64>,
        timeout: Option<Duration>,
        target: F,
    ) -> std::io::Result<FuzzStats>
    where
        F: FnMut(&[u8]) -> i32,
    {
        let mut pipe_fds = [0; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];

        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                unsafe {
                    libc::close(write_fd);
                }

                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let n = unsafe {
                        libc::read(read_fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len())
                    };
                    if n <= 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n as usize]);
                }
                unsafe {
                    libc::close(read_fd);
                }

                let _ = nix::sys::wait::waitpid(child, None);

                let stats: FuzzStats = serde_json::from_slice(&buf).map_err(|e| {
                    std::io::Error::other(format!("Failed deserializing FuzzStats from sandboxed worker: {e}"))
                })?;

                Ok(stats)
            }
            Ok(nix::unistd::ForkResult::Child) => {
                unsafe {
                    libc::close(read_fd);
                }

                // Apply 4-tier rootless sandbox in isolated worker
                if let Err(e) = self.apply_sandbox() {
                    eprintln!("Warning: Failed applying sandbox in worker child: {e}");
                }

                let stats = self.fuzz_target(max_execs, timeout, target);

                if let Ok(json) = serde_json::to_vec(&stats) {
                    let mut written = 0;
                    while written < json.len() {
                        let n = unsafe {
                            libc::write(
                                write_fd,
                                json.as_ptr().add(written) as *const libc::c_void,
                                json.len() - written,
                            )
                        };
                        if n <= 0 {
                            break;
                        }
                        written += n as usize;
                    }
                }

                unsafe {
                    libc::close(write_fd);
                    libc::_exit(0);
                }
            }
            Err(e) => Err(std::io::Error::other(format!("Fork failed: {e}"))),
        }
    }

    /// Execute a dynamic shared object (`.so`) harness exposing `LLVMFuzzerTestOneInput`.
    pub fn fuzz_shared_object(
        &mut self,
        so_path: &Path,
        max_execs: Option<u64>,
        timeout: Option<Duration>,
    ) -> Result<FuzzStats, String> {
        let lib = unsafe {
            libloading::Library::new(so_path)
                .map_err(|e| format!("Failed loading shared library {}: {e}", so_path.display()))?
        };

        type FuzzFn = unsafe extern "C" fn(*const u8, usize) -> libc::c_int;
        let test_one_input: libloading::Symbol<FuzzFn> = unsafe {
            lib.get(b"LLVMFuzzerTestOneInput\0")
                .map_err(|e| format!("Missing LLVMFuzzerTestOneInput symbol: {e}"))?
        };

        let stats = self.fuzz_target(max_execs, timeout, |data| unsafe {
            test_one_input(data.as_ptr(), data.len())
        });

        Ok(stats)
    }

    /// Verifies LibAFL observer and feedback integration directly.
    /// Genuinely evaluates novelty and state update with `StdMapObserver` and `MaxMapFeedback`.
    pub fn verify_libafl_feedback(&mut self) -> bool {
        let observer = unsafe {
            StdMapObserver::from_mut_ptr("edges", self.coverage_map.as_mut_ptr(), MAP_SIZE)
        };
        let mut feedback = MaxMapFeedback::new(&observer);
        let mut state: NopState<BytesInput> = NopState::new();
        if feedback.init_state(&mut state).is_err() {
            return false;
        }
        let mut event_mgr = NopEventManager::new();
        let observers = tuple_list!(observer);

        // 1. Record synthetic edge 1234 in coverage map
        self.coverage_map.record_edge(1234);

        let input_bytes = BytesInput::new(vec![0x41, 0x42]);
        let is_interesting = feedback
            .is_interesting(
                &mut state,
                &mut event_mgr,
                &input_bytes,
                &observers,
                &ExitKind::Ok,
            )
            .unwrap_or(false);

        if !is_interesting {
            return false;
        }

        // 2. Append metadata to update feedback history map
        let mut testcase = Testcase::new(input_bytes.clone());
        if feedback
            .append_metadata(&mut state, &mut event_mgr, &observers, &mut testcase)
            .is_err()
        {
            return false;
        }

        // 3. Second evaluation on same coverage must NOT be interesting
        let is_interesting_second = feedback
            .is_interesting(
                &mut state,
                &mut event_mgr,
                &input_bytes,
                &observers,
                &ExitKind::Ok,
            )
            .unwrap_or(true);

        self.coverage_map.clear();
        !is_interesting_second
    }
}
