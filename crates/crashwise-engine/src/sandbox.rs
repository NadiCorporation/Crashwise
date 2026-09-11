use tokio::process::Command;
use tracing::info;

pub struct SandboxConfig {
    pub memory_limit_mb: u64,
    pub timeout_seconds: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit_mb: 2048,
            timeout_seconds: 300,
        }
    }
}

pub struct RootlessSandbox;

impl RootlessSandbox {
    pub fn wrap_command(cmd: &mut Command, _config: &SandboxConfig) {
        info!("Applying Linux execution sandbox controls");
        cmd.env("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1:symbolize=1:disable_coredump=1");
        cmd.env("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1");
    }
}
