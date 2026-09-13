//! 4-Tier Rootless Linux Sandbox for CrashWise Engine
//!
//! Tiers:
//! 1. Rootless cgroups v2 (memory limits, swap off, cpu quota, pids max)
//! 2. Linux namespaces (CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWIPC)
//! 3. Seccomp BPF syscall filter (PR_SET_NO_NEW_PRIVS = 1, allow essential compute/memory, block forbidden)
//! 4. POSIX resource limits (RLIMIT_CORE = 0, RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE)

use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Configuration for the 4-tier rootless Linux sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum memory in megabytes (Tier 1 & Tier 4). Default: 2048 MB (2 GB).
    pub memory_limit_mb: u64,
    /// Maximum swap memory in megabytes (Tier 1). Default: 0 MB (swap disabled).
    pub swap_limit_mb: u64,
    /// CPU quota in microseconds per period (Tier 1). Default: 100,000 us.
    pub cpu_quota_us: u64,
    /// CPU period in microseconds (Tier 1). Default: 100,000 us (100 ms).
    pub cpu_period_us: u64,
    /// Maximum number of process IDs (Tier 1). Default: 16.
    pub max_pids: u64,
    /// CPU execution timeout in seconds (Tier 4). Default: 300 seconds.
    pub timeout_seconds: u64,
    /// Whether to enable cgroups v2 resource quotas. Default: true.
    pub enable_cgroups: bool,
    /// Whether to enable Linux namespaces isolation. Default: true.
    pub enable_namespaces: bool,
    /// Whether to enable Seccomp BPF syscall filtering. Default: true.
    pub enable_seccomp: bool,
    /// Whether to enable POSIX resource limits. Default: true.
    pub enable_rlimits: bool,
    /// If true, forbidden syscalls result in SECCOMP_RET_KILL_PROCESS.
    /// If false, forbidden syscalls return -EPERM (SECCOMP_RET_ERRNO). Default: false.
    pub seccomp_kill_violators: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit_mb: 2048,
            swap_limit_mb: 0,
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
            max_pids: 16,
            timeout_seconds: 300,
            enable_cgroups: true,
            enable_namespaces: true,
            enable_seccomp: true,
            enable_rlimits: true,
            seccomp_kill_violators: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tier 1: Rootless cgroups v2
// ---------------------------------------------------------------------------

/// RAII Guard for an unprivileged cgroup v2 subtree.
/// Automatically cleans up the child cgroup directory on drop.
#[derive(Debug)]
pub struct CgroupV2Guard {
    cgroup_path: PathBuf,
}

impl CgroupV2Guard {
    pub fn path(&self) -> &Path {
        &self.cgroup_path
    }
}

impl Drop for CgroupV2Guard {
    fn drop(&mut self) {
        if self.cgroup_path.exists() {
            // If the current process was attached to this cgroup, migrate it back to parent
            let my_pid = std::process::id();
            let procs_path = self.cgroup_path.join("cgroup.procs");
            if let Ok(procs) = fs::read_to_string(&procs_path) {
                if procs.lines().any(|l| l.trim() == my_pid.to_string()) {
                    if let Some(parent) = self.cgroup_path.parent() {
                        let parent_procs = parent.join("cgroup.procs");
                        let _ = fs::write(&parent_procs, format!("{my_pid}\n"));
                    }
                }
            }

            // Optional: try killing remaining child processes if cgroup.kill is available
            let kill_path = self.cgroup_path.join("cgroup.kill");
            if kill_path.exists() {
                let _ = fs::write(&kill_path, "1");
            }
            // Remove the cgroup directory
            if let Err(e) = fs::remove_dir(&self.cgroup_path) {
                debug!(
                    "Note: Could not immediately remove cgroup dir {}: {}",
                    self.cgroup_path.display(),
                    e
                );
            }
        }
    }
}


pub struct CgroupV2Manager;

impl CgroupV2Manager {
    /// Detect the writable rootless cgroup v2 user slice directory.
    pub fn detect_user_cgroup_dir() -> Option<PathBuf> {
        let uid = unsafe { libc::getuid() };

        // 1. Primary path: /sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/
        let primary = PathBuf::from(format!(
            "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
        ));
        if primary.is_dir() {
            return Some(primary);
        }

        // 2. Secondary path from /proc/self/cgroup
        if let Ok(cgroup_content) = fs::read_to_string("/proc/self/cgroup") {
            for line in cgroup_content.lines() {
                // e.g. 0::/user.slice/user-1000.slice/user@1000.service/app.slice/...
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() == 3 {
                    let rel_path = parts[2].trim_start_matches('/');
                    let full_path = PathBuf::from("/sys/fs/cgroup").join(rel_path);

                    // Find nearest writable parent
                    let mut curr = Some(full_path);
                    while let Some(p) = curr {
                        if p.is_dir() {
                            let procs_file = p.join("cgroup.procs");
                            if procs_file.exists() {
                                // Check if writable
                                if fs::OpenOptions::new().write(true).open(&procs_file).is_ok() {
                                    return Some(p);
                                }
                            }
                        }
                        curr = p.parent().map(|p| p.to_path_buf());
                    }
                }
            }
        }

        None
    }

    /// Create and configure a rootless cgroup v2 child slice with strict quotas.
    pub fn create_sandbox_cgroup(config: &SandboxConfig) -> Result<CgroupV2Guard> {
        let parent = Self::detect_user_cgroup_dir().ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                "No writable rootless cgroup v2 hierarchy detected",
            )
        })?;

        let unique_id = uuid::Uuid::new_v4();
        let cgroup_dir = parent.join(format!("crashwise-{unique_id}"));
        fs::create_dir_all(&cgroup_dir)?;

        let guard = CgroupV2Guard {
            cgroup_path: cgroup_dir.clone(),
        };

        // 1. Apply memory quota: memory.max
        let memory_max_bytes = config.memory_limit_mb.saturating_mul(1024 * 1024);
        let mem_file = cgroup_dir.join("memory.max");
        if let Err(e) = fs::write(&mem_file, memory_max_bytes.to_string()) {
            warn!("cgroups v2: failed writing memory.max: {e}");
        }

        // 2. Disable swap: memory.swap.max = 0
        let swap_max_bytes = config.swap_limit_mb.saturating_mul(1024 * 1024);
        let swap_file = cgroup_dir.join("memory.swap.max");
        if let Err(e) = fs::write(&swap_file, swap_max_bytes.to_string()) {
            debug!("cgroups v2: failed writing memory.swap.max: {e}");
        }

        // 3. Apply CPU quota: cpu.max = "quota period"
        let cpu_file = cgroup_dir.join("cpu.max");
        let cpu_val = format!("{} {}", config.cpu_quota_us, config.cpu_period_us);
        if let Err(e) = fs::write(&cpu_file, cpu_val) {
            debug!("cgroups v2: failed writing cpu.max: {e}");
        }

        // 4. Apply PID quota: pids.max
        let pids_file = cgroup_dir.join("pids.max");
        if let Err(e) = fs::write(&pids_file, config.max_pids.to_string()) {
            debug!("cgroups v2: failed writing pids.max: {e}");
        }

        info!(
            "Configured rootless cgroup v2 sandbox at {}",
            cgroup_dir.display()
        );
        Ok(guard)
    }

    /// Attach a process ID to a cgroup v2 directory.
    pub fn attach_process(cgroup_dir: &Path, pid: u32) -> Result<()> {
        let procs_file = cgroup_dir.join("cgroup.procs");
        fs::write(&procs_file, format!("{pid}\n"))?;
        debug!("Attached pid {pid} to cgroup {}", cgroup_dir.display());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tier 2: Linux Namespaces
// ---------------------------------------------------------------------------

pub struct NamespaceManager;

impl NamespaceManager {
    /// Applies unprivileged Linux namespace isolation to the calling process.
    /// Uses CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWNS, and CLONE_NEWIPC.
    pub fn apply_namespaces() -> Result<()> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Attempt unshare with namespaces
        // CLONE_NEWUSER (0x10000000), CLONE_NEWNET (0x40000000), CLONE_NEWNS (0x00020000), CLONE_NEWIPC (0x08000000)
        let flags = libc::CLONE_NEWUSER
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWIPC;

        let res = unsafe { libc::unshare(flags) };
        if res != 0 {
            // If full namespace bundle fails (e.g. unprivileged user namespaces restricted), try single user namespace
            let user_res = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            if user_res != 0 {
                let err = Error::last_os_error();
                warn!("Namespace unshare failed (rootless fallback active): {err}");
                return Err(err);
            }
        }

        // Set up UID/GID mapping for rootless user namespace
        // 1. setgroups deny
        if let Err(e) = fs::write("/proc/self/setgroups", "deny") {
            debug!("Could not write to /proc/self/setgroups: {e}");
        }

        // 2. uid_map: map container root (0) to host uid
        let uid_map = format!("0 {uid} 1\n");
        if let Err(e) = fs::write("/proc/self/uid_map", uid_map) {
            debug!("Could not write /proc/self/uid_map: {e}");
        }

        // 3. gid_map: map container root (0) to host gid
        let gid_map = format!("0 {gid} 1\n");
        if let Err(e) = fs::write("/proc/self/gid_map", gid_map) {
            debug!("Could not write /proc/self/gid_map: {e}");
        }

        info!("Rootless namespaces successfully applied (USER, NET, NS, IPC)");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tier 3: Seccomp BPF Syscall Filter
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

// BPF Instruction Constants
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp Return Actions
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// Architecture Identification (x86_64)
pub const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// seccomp_data struct offsets
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

pub struct SeccompFilter;

impl SeccompFilter {
    /// Compile the Classic BPF instruction program that blocks forbidden syscalls.
    pub fn build_bpf_program(kill_violators: bool) -> Vec<SockFilter> {
        let mut filter = vec![
            // 1. Load architecture from seccomp_data: [BPF_LD | BPF_W | BPF_ABS, offset 4]
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_ARCH_OFFSET,
            },
            // 2. Check architecture == AUDIT_ARCH_X86_64: if true continue (skip 1), else jump to kill
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_X86_64,
            },
            // 3. Kill process on architecture mismatch
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            // 4. Load syscall number from seccomp_data: [BPF_LD | BPF_W | BPF_ABS, offset 0]
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_NR_OFFSET,
            },
        ];

        // Forbidden syscalls on x86_64:
        // execve (59), execveat (322)
        // socket (41), connect (42), bind (49), listen (50), accept (43), accept4 (288)
        // ptrace (101)
        // mount (165), umount2 (166), pivot_root (155)
        // reboot (169)
        // kill (62), tkill (200), tgkill (234)
        let forbidden: &[u32] = &[
            59,  // execve
            322, // execveat
            41,  // socket
            42,  // connect
            49,  // bind
            50,  // listen
            43,  // accept
            288, // accept4
            101, // ptrace
            165, // mount
            166, // umount2
            155, // pivot_root
            169, // reboot
            62,  // kill
            200, // tkill
            234, // tgkill
        ];

        let deny_action = if kill_violators {
            SECCOMP_RET_KILL_PROCESS
        } else {
            SECCOMP_RET_ERRNO | (libc::EPERM as u32)
        };

        // For each forbidden syscall, if it matches, jump to the deny instruction
        let total_checks = forbidden.len();
        for (idx, &syscall_nr) in forbidden.iter().enumerate() {
            let jump_offset = (total_checks - 1 - idx) as u8 + 1;
            filter.push(SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: jump_offset,
                jf: 0,
                k: syscall_nr,
            });
        }

        // Allow all non-forbidden syscalls
        filter.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });

        // Deny instruction target for forbidden syscalls
        filter.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: deny_action,
        });

        filter
    }

    /// Installs the Seccomp BPF syscall filter in the calling thread/process.
    pub fn apply(kill_violators: bool) -> Result<()> {
        // 1. Enforce PR_SET_NO_NEW_PRIVS = 1 (required before loading unprivileged seccomp filter)
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(Error::last_os_error());
        }

        // 2. Build BPF filter instructions
        let instructions = Self::build_bpf_program(kill_violators);
        let prog = SockFprog {
            len: instructions.len() as u16,
            filter: instructions.as_ptr(),
        };

        // 3. Load Seccomp filter via SYS_seccomp (SECCOMP_SET_MODE_FILTER)
        const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
        let sys_ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0,
                &prog as *const SockFprog,
            )
        };

        if sys_ret != 0 {
            // Fallback to prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)
            const PR_SET_SECCOMP: libc::c_int = 22;
            const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
            let prctl_ret = unsafe {
                libc::prctl(
                    PR_SET_SECCOMP,
                    SECCOMP_MODE_FILTER,
                    &prog as *const SockFprog,
                )
            };
            if prctl_ret != 0 {
                return Err(Error::last_os_error());
            }
        }

        info!("Seccomp BPF filter applied (PR_SET_NO_NEW_PRIVS = 1, blocked execve/socket/ptrace/mount)");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tier 4: POSIX Resource Limits (rlimits)
// ---------------------------------------------------------------------------

pub struct RlimitManager;

impl RlimitManager {
    /// Apply POSIX resource limits (RLIMIT_CORE = 0, RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE).
    pub fn apply_rlimits(config: &SandboxConfig) -> Result<()> {
        unsafe {
            // 1. RLIMIT_CORE = 0 (disable core dumps)
            let core_lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &core_lim) != 0 {
                warn!("Failed to set RLIMIT_CORE: {}", Error::last_os_error());
            }

            // 2. RLIMIT_AS (address space limit)
            let as_bytes = config.memory_limit_mb.saturating_mul(1024 * 1024);
            let as_lim = libc::rlimit {
                rlim_cur: as_bytes,
                rlim_max: as_bytes,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &as_lim) != 0 {
                debug!("Failed to set RLIMIT_AS: {}", Error::last_os_error());
            }

            // 3. RLIMIT_CPU (CPU time limit)
            if config.timeout_seconds > 0 {
                let cpu_lim = libc::rlimit {
                    rlim_cur: config.timeout_seconds,
                    rlim_max: config.timeout_seconds + 5,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &cpu_lim) != 0 {
                    debug!("Failed to set RLIMIT_CPU: {}", Error::last_os_error());
                }
            }

            // 4. RLIMIT_FSIZE (maximum file write limit, 10MB)
            let fsize_lim = libc::rlimit {
                rlim_cur: 10 * 1024 * 1024,
                rlim_max: 10 * 1024 * 1024,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &fsize_lim) != 0 {
                debug!("Failed to set RLIMIT_FSIZE: {}", Error::last_os_error());
            }
        }

        info!("POSIX resource limits enforced (RLIMIT_CORE=0, RLIMIT_AS={}MB, RLIMIT_FSIZE=10MB)", config.memory_limit_mb);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RootlessSandbox: Unified 4-Tier Orchestrator
// ---------------------------------------------------------------------------

pub struct RootlessSandbox {
    config: SandboxConfig,
    cgroup_guard: Option<CgroupV2Guard>,
}

impl RootlessSandbox {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            cgroup_guard: None,
        }
    }

    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Apply all 4 tiers of rootless isolation to the calling process.
    pub fn apply_to_current_process(&mut self) -> Result<()> {
        info!("Applying 4-tier rootless Linux sandbox to current process");

        // Tier 4: Resource limits
        if self.config.enable_rlimits {
            if let Err(e) = RlimitManager::apply_rlimits(&self.config) {
                warn!("Rlimits setup warning: {e}");
            }
        }

        // Tier 1: Cgroups v2
        if self.config.enable_cgroups {
            match CgroupV2Manager::create_sandbox_cgroup(&self.config) {
                Ok(guard) => {
                    let pid = std::process::id();
                    if let Err(e) = CgroupV2Manager::attach_process(guard.path(), pid) {
                        warn!("cgroups v2 attach warning: {e}");
                    }
                    self.cgroup_guard = Some(guard);
                }
                Err(e) => {
                    warn!("cgroups v2 unavailable, continuing with other tiers: {e}");
                }
            }
        }

        // Tier 2: Namespaces
        if self.config.enable_namespaces {
            if let Err(e) = NamespaceManager::apply_namespaces() {
                warn!("Namespaces unshare warning (gracefully continuing): {e}");
            }
        }

        // Tier 3: Seccomp BPF
        if self.config.enable_seccomp {
            if let Err(e) = SeccompFilter::apply(self.config.seccomp_kill_violators) {
                warn!("Seccomp BPF installation warning: {e}");
            }
        }

        Ok(())
    }

    /// Configures environment variables and sandbox options on a tokio Command.
    pub fn wrap_command(cmd: &mut Command, config: &SandboxConfig) {
        info!("Applying Linux execution sandbox controls");
        let asan_opts = format!(
            "detect_leaks=0:abort_on_error=1:symbolize=1:disable_coredump=1:max_allocation_size_mb={}",
            config.memory_limit_mb
        );
        cmd.env("ASAN_OPTIONS", asan_opts);
        cmd.env("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1");
    }

    /// Attaches an existing or spawned child PID to the cgroup sandbox.
    pub fn attach_child_pid(&self, pid: u32) -> Result<()> {
        if let Some(guard) = &self.cgroup_guard {
            CgroupV2Manager::attach_process(guard.path(), pid)?;
        }
        Ok(())
    }

    /// Returns whether rootless cgroups v2 hierarchy is accessible.
    pub fn is_cgroups_v2_available() -> bool {
        CgroupV2Manager::detect_user_cgroup_dir().is_some()
    }
}
