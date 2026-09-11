use crashwise_core::error::{CrashwiseError, Result};
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tracing::{info, warn};

pub struct SanityGate;

impl SanityGate {
    pub async fn verify_harness_binary(harness_bin: &Path) -> Result<()> {
        info!("Running 5-second sanity gate on {}", harness_bin.display());

        let temp_dir = tempfile::tempdir()?;
        let sample_seed = temp_dir.path().join("sample_seed");
        tokio::fs::write(&sample_seed, b"CRASHWISE_SANITY_INPUT_HEADER\x00\x01\x02\x03").await?;

        let mut cmd = Command::new(harness_bin);
        cmd.arg("-runs=10")
            .arg("-max_total_time=5")
            .arg(&sample_seed);

        let output = tokio::select! {
            res = cmd.output() => {
                res.map_err(|e| CrashwiseError::HarnessError(format!("Failed to execute harness sanity run: {e}")))?
            }
            _ = tokio::time::sleep(Duration::from_secs(6)) => {
                warn!("Sanity gate timed out after 6 seconds - possible infinite loop in harness");
                return Err(CrashwiseError::HarnessError("Sanity gate timeout (infinite loop detected)".to_string()));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("AddressSanitizer") || stderr.contains("SEGV") {
                return Err(CrashwiseError::HarnessError(format!(
                    "Harness crashed during 5-second sanity run:\n{stderr}"
                )));
            }
        }

        info!("Harness passed sanity gate verification cleanly");
        Ok(())
    }
}
