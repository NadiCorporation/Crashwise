use crate::libafl_runner::InProcessEngine;
use crate::sandbox::{RootlessSandbox, SandboxConfig};
use crashwise_core::error::{CrashwiseError, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{info, warn};

pub struct FuzzExecutionResult {
    pub exit_status: Option<i32>,
    pub crashes: Vec<PathBuf>,
    pub output_logs: String,
    pub execs_per_sec: Option<f64>,
    pub total_execs: Option<u64>,
    pub total_edges: Option<usize>,
}

pub struct FuzzRunner {
    pub timeout: Duration,
    pub sandbox_config: SandboxConfig,
}

impl FuzzRunner {
    pub fn new(timeout_seconds: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_seconds),
            sandbox_config: SandboxConfig {
                timeout_seconds,
                ..Default::default()
            },
        }
    }

    pub fn with_sandbox(mut self, config: SandboxConfig) -> Self {
        self.sandbox_config = config;
        self
    }

    /// Subprocess-based fuzzing with rootless sandbox isolation.
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

        // Apply rootless sandbox environment and controls
        RootlessSandbox::wrap_command(&mut cmd, &self.sandbox_config);

        let start_time = Instant::now();
        let output = tokio::select! {
            res = cmd.output() => {
                res.map_err(|e| CrashwiseError::EngineError(format!("Fuzzer process failed to execute: {e}")))?
            }
            _ = tokio::time::sleep(self.timeout) => {
                warn!("Fuzzer reached timeout duration of {:?}", self.timeout);
                let crashes = self.discover_crashes(crashes_dir).await?;
                return Ok(FuzzExecutionResult {
                    exit_status: None,
                    crashes,
                    output_logs: "Fuzzer stopped after reaching timeout".to_string(),
                    execs_per_sec: None,
                    total_execs: None,
                    total_edges: None,
                });
            }
        };

        let logs = format!(
            "STDOUT:\n{}\n\nSTDERR:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let crashes = self.discover_crashes(crashes_dir).await?;
        let elapsed = start_time.elapsed().as_secs_f64();

        Ok(FuzzExecutionResult {
            exit_status: output.status.code(),
            crashes,
            output_logs: logs,
            execs_per_sec: if elapsed > 0.0 { Some(0.0) } else { None },
            total_execs: None,
            total_edges: None,
        })
    }

    /// In-process LibAFL fuzzing with 64KB shared memory bitmap and rootless sandbox.
    pub fn run_inprocess_fuzz<F>(
        &self,
        corpus_dir: &Path,
        crashes_dir: &Path,
        max_execs: Option<u64>,
        target: F,
    ) -> Result<FuzzExecutionResult>
    where
        F: FnMut(&[u8]) -> i32,
    {
        std::fs::create_dir_all(corpus_dir)?;
        std::fs::create_dir_all(crashes_dir)?;

        let mut engine = InProcessEngine::new(crashes_dir)
            .map_err(|e| CrashwiseError::EngineError(format!("Failed to initialize InProcessEngine: {e}")))?;

        // Load existing seeds from corpus_dir
        if let Ok(entries) = std::fs::read_dir(corpus_dir) {
            for entry in entries.flatten() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    engine.add_seed(bytes);
                }
            }
        }

        let stats = engine.fuzz_target(max_execs, Some(self.timeout), target);

        // Discover generated crashes
        let mut crashes = Vec::new();
        if let Ok(entries) = std::fs::read_dir(crashes_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    crashes.push(p);
                }
            }
        }

        let logs = format!(
            "In-Process LibAFL Execution Finished:\nTotal Execs: {}\nThroughput: {:.2} execs/sec\nTotal Edges: {}\nCrashes: {}\nElapsed: {:?}",
            stats.total_execs, stats.execs_per_sec, stats.total_edges, stats.total_crashes, stats.elapsed
        );

        Ok(FuzzExecutionResult {
            exit_status: Some(0),
            crashes,
            output_logs: logs,
            execs_per_sec: Some(stats.execs_per_sec),
            total_execs: Some(stats.total_execs),
            total_edges: Some(stats.total_edges),
        })
    }

    /// In-process execution of a compiled shared object (`.so`) harness.
    pub fn run_inprocess_so(
        &self,
        so_path: &Path,
        corpus_dir: &Path,
        crashes_dir: &Path,
        max_execs: Option<u64>,
    ) -> Result<FuzzExecutionResult> {
        std::fs::create_dir_all(corpus_dir)?;
        std::fs::create_dir_all(crashes_dir)?;

        let mut engine = InProcessEngine::new(crashes_dir)
            .map_err(|e| CrashwiseError::EngineError(format!("Failed to initialize InProcessEngine: {e}")))?;

        // Load initial seeds
        if let Ok(entries) = std::fs::read_dir(corpus_dir) {
            for entry in entries.flatten() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    engine.add_seed(bytes);
                }
            }
        }

        let stats = engine
            .fuzz_shared_object(so_path, max_execs, Some(self.timeout))
            .map_err(CrashwiseError::EngineError)?;

        let mut crashes = Vec::new();
        if let Ok(entries) = std::fs::read_dir(crashes_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    crashes.push(p);
                }
            }
        }

        let logs = format!(
            "In-Process LibAFL Shared Object Execution Finished:\nTotal Execs: {}\nThroughput: {:.2} execs/sec\nTotal Edges: {}\nCrashes: {}\nElapsed: {:?}",
            stats.total_execs, stats.execs_per_sec, stats.total_edges, stats.total_crashes, stats.elapsed
        );

        Ok(FuzzExecutionResult {
            exit_status: Some(0),
            crashes,
            output_logs: logs,
            execs_per_sec: Some(stats.execs_per_sec),
            total_execs: Some(stats.total_execs),
            total_edges: Some(stats.total_edges),
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

