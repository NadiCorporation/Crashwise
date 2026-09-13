use crate::asan::AsanParser;
use crashwise_core::error::{CrashwiseError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Result of executing a standalone PoC binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocRunResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_seconds: f64,
    pub reproduced_crash: bool,
    pub clean_execution: bool,
    pub violation_type: Option<String>,
    pub timed_out: bool,
}

/// Standalone PoC replay runner with configurable timeout and ASan environment flags.
#[derive(Debug, Clone)]
pub struct PocRunner {
    pub timeout: Duration,
    pub env_vars: Vec<(String, String)>,
    pub args: Vec<String>,
}

impl Default for PocRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl PocRunner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            env_vars: vec![
                (
                    "ASAN_OPTIONS".to_string(),
                    "detect_leaks=0:abort_on_error=1:symbolize=1:disable_coredump=1".to_string(),
                ),
            ],
            args: Vec::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Asynchronously execute the compiled PoC binary with timeout and capture results.
    pub async fn run(&self, binary_path: &Path) -> Result<PocRunResult> {
        let start = std::time::Instant::now();

        let mut cmd = tokio::process::Command::new(binary_path);
        for arg in &self.args {
            cmd.arg(arg);
        }
        for (k, v) in &self.env_vars {
            cmd.env(k, v);
        }

        let run_fut = cmd.output();
        let timeout_res = tokio::time::timeout(self.timeout, run_fut).await;
        let duration = start.elapsed().as_secs_f64();

        match timeout_res {
            Err(_) => Ok(PocRunResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: "Execution timed out".to_string(),
                duration_seconds: duration,
                reproduced_crash: false,
                clean_execution: false,
                violation_type: Some("Timeout".to_string()),
                timed_out: true,
            }),
            Ok(Err(e)) => Err(CrashwiseError::TriageError(format!(
                "Failed to execute PoC binary {}: {e}",
                binary_path.display()
            ))),
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let combined = format!("{}\n{}", stdout, stderr);
                let exit_code = output.status.code();

                let violation = AsanParser::detect_sanitizer_violation(&combined);
                let clean = AsanParser::is_clean_execution(&combined, exit_code);

                // Crash reproduced if sanitizer violation found, or terminated by signal / non-zero with crash markers
                let reproduced = violation.is_some()
                    || (!output.status.success()
                        && (combined.contains("AddressSanitizer")
                            || combined.contains("SEGV")
                            || combined.contains("runtime error")
                            || combined.contains("Sanitizer")));

                Ok(PocRunResult {
                    success: output.status.success(),
                    exit_code,
                    stdout,
                    stderr,
                    duration_seconds: duration,
                    reproduced_crash: reproduced,
                    clean_execution: clean,
                    violation_type: violation,
                    timed_out: false,
                })
            }
        }
    }

    /// Synchronously execute the compiled PoC binary.
    pub fn run_sync(&self, binary_path: &Path) -> Result<PocRunResult> {
        let start = std::time::Instant::now();

        let mut cmd = std::process::Command::new(binary_path);
        for arg in &self.args {
            cmd.arg(arg);
        }
        for (k, v) in &self.env_vars {
            cmd.env(k, v);
        }

        let output = cmd.output().map_err(|e| {
            CrashwiseError::TriageError(format!(
                "Failed to execute PoC binary {}: {e}",
                binary_path.display()
            ))
        })?;

        let duration = start.elapsed().as_secs_f64();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{}\n{}", stdout, stderr);
        let exit_code = output.status.code();

        let violation = AsanParser::detect_sanitizer_violation(&combined);
        let clean = AsanParser::is_clean_execution(&combined, exit_code);
        let reproduced = violation.is_some()
            || (!output.status.success()
                && (combined.contains("AddressSanitizer")
                    || combined.contains("SEGV")
                    || combined.contains("runtime error")
                    || combined.contains("Sanitizer")));

        Ok(PocRunResult {
            success: output.status.success(),
            exit_code,
            stdout,
            stderr,
            duration_seconds: duration,
            reproduced_crash: reproduced,
            clean_execution: clean,
            violation_type: violation,
            timed_out: false,
        })
    }
}
