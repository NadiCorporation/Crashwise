use crashwise_core::error::{CrashwiseError, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tracing::{info, warn};

pub struct FuzzExecutionResult {
    pub exit_status: Option<i32>,
    pub crashes: Vec<PathBuf>,
    pub output_logs: String,
}

pub struct FuzzRunner {
    pub timeout: Duration,
}

impl FuzzRunner {
    pub fn new(timeout_seconds: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_seconds),
        }
    }

    pub async fn run_fuzz(
        &self,
        harness_bin: &Path,
        corpus_dir: &Path,
        crashes_dir: &Path,
    ) -> Result<FuzzExecutionResult> {
        tokio::fs::create_dir_all(corpus_dir).await?;
        tokio::fs::create_dir_all(crashes_dir).await?;

        info!("Starting fuzzer execution for {}", harness_bin.display());

        let artifact_prefix = format!("{}/crash-", crashes_dir.display());

        let mut cmd = Command::new(harness_bin);
        cmd.arg(format!("-artifact_prefix={}", artifact_prefix))
            .arg("-max_total_time=60")
            .arg("-rss_limit_mb=2048")
            .arg(corpus_dir);

        let output = tokio::select! {
            res = cmd.output() => {
                res.map_err(|e| CrashwiseError::EngineError(format!("Fuzzer process failed to execute: {e}")))?
            }
            _ = tokio::time::sleep(self.timeout) => {
                warn!("Fuzzer reached timeout duration of {:?}", self.timeout);
                return Ok(FuzzExecutionResult {
                    exit_status: None,
                    crashes: self.discover_crashes(crashes_dir).await?,
                    output_logs: "Fuzzer stopped after reaching timeout".to_string(),
                });
            }
        };

        let logs = format!(
            "STDOUT:\n{}\n\nSTDERR:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let crashes = self.discover_crashes(crashes_dir).await?;

        Ok(FuzzExecutionResult {
            exit_status: output.status.code(),
            crashes,
            output_logs: logs,
        })
    }

    async fn discover_crashes(&self, crashes_dir: &Path) -> Result<Vec<PathBuf>> {
        let mut crashes = Vec::new();
        if crashes_dir.exists() {
            let mut entries = tokio::fs::read_dir(crashes_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_file() {
                    crashes.push(path);
                }
            }
        }
        Ok(crashes)
    }
}
