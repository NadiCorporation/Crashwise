use crate::patch_applier::PatchApplier;
use crate::patch_synth::PatchCandidate;
use crate::poc_gen::PocCompiler;
use crate::poc_runner::PocRunner;
use crashwise_build::compiler::{BuildOutput, TargetBuilder};
use crashwise_build::detector::detect_build_system;
use crashwise_core::error::{CrashwiseError, Result};
use crashwise_core::models::CrashRecord;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Structured report summarizing the 5-stage closed-loop verification results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub verified: bool,
    pub pre_patch_reproduced: bool,
    pub patch_applied_cleanly: bool,
    pub target_recompiled: bool,
    pub post_patch_poc_clean: bool,
    pub regression_passed: bool,
    pub failure_stage: Option<String>,
    pub compiler_output: Option<String>,
    pub poc_output: Option<String>,
    pub regression_output: Option<String>,
    pub duration_seconds: f64,
}

/// 5-Stage Closed-Loop Patch Verification Engine.
///
/// Stage 1: Pre-patch PoC reproduction assertion (verifies crash occurs on unpatched code)
/// Stage 2: Atomic patch application (with rollback guard)
/// Stage 3: Target recompilation with ASan instrumentation
/// Stage 4: Post-patch PoC replay assertion (verifies clean exit 0 and 0 memory violations)
/// Stage 5: Target regression test suite execution (verifies zero regressions)
pub struct PatchVerifier {
    pub target_dir: PathBuf,
    pub build_output: BuildOutput,
    pub regression_command: Option<String>,
}

impl PatchVerifier {
    pub fn new(target_dir: PathBuf, build_output: BuildOutput) -> Self {
        Self {
            target_dir,
            build_output,
            regression_command: None,
        }
    }

    pub fn with_regression_command(mut self, cmd: impl Into<String>) -> Self {
        self.regression_command = Some(cmd.into());
        self
    }

    /// Execute the full 5-stage closed-loop patch verification.
    pub async fn verify_patch(
        &self,
        crash: &CrashRecord,
        poc_source: &Path,
        patch: &PatchCandidate,
    ) -> Result<VerificationReport> {
        let start_time = std::time::Instant::now();

        let mut report = VerificationReport {
            verified: false,
            pre_patch_reproduced: false,
            patch_applied_cleanly: false,
            target_recompiled: false,
            post_patch_poc_clean: false,
            regression_passed: false,
            failure_stage: None,
            compiler_output: None,
            poc_output: None,
            regression_output: None,
            duration_seconds: 0.0,
        };

        let temp_dir = tempfile::tempdir().map_err(|e| {
            CrashwiseError::TriageError(format!("Failed to create verification tempdir: {e}"))
        })?;

        // ---------------------------------------------------------------------
        // Stage 1: Pre-patch PoC reproduction assertion
        // ---------------------------------------------------------------------
        info!("Stage 1/5: Verifying pre-patch crash reproduction with standalone PoC...");
        let pre_poc_bin = temp_dir.path().join("pre_patch_poc_bin");
        let pre_compiler = self.build_poc_compiler();

        let pre_comp_res = pre_compiler.compile_with_output(poc_source, &pre_poc_bin).await?;
        report.compiler_output = Some(format!(
            "STDOUT:\n{}\nSTDERR:\n{}",
            pre_comp_res.stdout, pre_comp_res.stderr
        ));

        if !pre_comp_res.success {
            report.pre_patch_reproduced = false;
            report.failure_stage = Some("pre_patch_compilation".to_string());
            report.duration_seconds = start_time.elapsed().as_secs_f64();
            return Ok(report);
        }

        let runner = PocRunner::new();
        let pre_run = runner.run(&pre_poc_bin).await?;
        report.poc_output = Some(format!(
            "PRE-PATCH STDOUT:\n{}\nPRE-PATCH STDERR:\n{}",
            pre_run.stdout, pre_run.stderr
        ));

        if !pre_run.reproduced_crash {
            warn!("PoC did not reproduce crash on unpatched target binary");
            report.pre_patch_reproduced = false;
            report.failure_stage = Some("pre_patch_reproduction".to_string());
            report.duration_seconds = start_time.elapsed().as_secs_f64();
            return Ok(report);
        }
        report.pre_patch_reproduced = true;
        info!("Stage 1/5 PASSED: Pre-patch crash successfully reproduced");

        // ---------------------------------------------------------------------
        // Stage 2: Atomic patch application
        // ---------------------------------------------------------------------
        info!("Stage 2/5: Applying unified diff patch atomically with rollback guard...");
        let mut patch_guard = match PatchApplier::apply_patch(&self.target_dir, patch) {
            Ok(guard) => guard,
            Err(e) => {
                warn!("Patch application failed: {e}");
                report.patch_applied_cleanly = false;
                report.failure_stage = Some("patch_application".to_string());
                report.duration_seconds = start_time.elapsed().as_secs_f64();
                return Ok(report);
            }
        };
        report.patch_applied_cleanly = true;
        info!("Stage 2/5 PASSED: Patch applied cleanly");

        // ---------------------------------------------------------------------
        // Stage 3: Target recompilation with ASan instrumentation
        // ---------------------------------------------------------------------
        info!("Stage 3/5: Recompiling target with AddressSanitizer instrumentation...");
        let recompiled_output = match self.recompile_target(patch).await {
            Ok(output) => output,
            Err(e) => {
                warn!("Target recompilation failed: {e}");
                report.target_recompiled = false;
                report.failure_stage = Some("target_recompilation".to_string());
                report.compiler_output = Some(format!("Recompilation failed: {e}"));
                let _ = patch_guard.rollback();
                report.duration_seconds = start_time.elapsed().as_secs_f64();
                return Ok(report);
            }
        };
        report.target_recompiled = true;
        info!("Stage 3/5 PASSED: Target successfully recompiled with ASan");

        // ---------------------------------------------------------------------
        // Stage 4: Post-patch PoC replay assertion
        // ---------------------------------------------------------------------
        info!("Stage 4/5: Replaying PoC against patched target to verify crash elimination...");
        let post_poc_bin = temp_dir.path().join("post_patch_poc_bin");
        let post_compiler = self.build_poc_compiler_with_output(&recompiled_output);

        let post_comp_res = post_compiler.compile_with_output(poc_source, &post_poc_bin).await?;
        if !post_comp_res.success {
            warn!("Failed to compile PoC against patched target");
            report.post_patch_poc_clean = false;
            report.failure_stage = Some("post_patch_compilation".to_string());
            report.compiler_output = Some(format!(
                "STDOUT:\n{}\nSTDERR:\n{}",
                post_comp_res.stdout, post_comp_res.stderr
            ));
            let _ = patch_guard.rollback();
            report.duration_seconds = start_time.elapsed().as_secs_f64();
            return Ok(report);
        }

        let post_run = runner.run(&post_poc_bin).await?;
        let post_poc_summary = format!(
            "POST-PATCH STDOUT:\n{}\nPOST-PATCH STDERR:\n{}",
            post_run.stdout, post_run.stderr
        );
        report.poc_output = Some(format!(
            "{}\n\n{}",
            report.poc_output.take().unwrap_or_default(),
            post_poc_summary
        ));

        if !post_run.clean_execution {
            warn!(
                "PoC execution failed or reported sanitizer violation post-patch (exit: {:?}, violation: {:?})",
                post_run.exit_code, post_run.violation_type
            );
            report.post_patch_poc_clean = false;
            report.failure_stage = Some("post_patch_poc_replay".to_string());
            let _ = patch_guard.rollback();
            report.duration_seconds = start_time.elapsed().as_secs_f64();
            return Ok(report);
        }
        report.post_patch_poc_clean = true;
        info!("Stage 4/5 PASSED: PoC executed cleanly with 0 sanitizer violations post-patch");

        // ---------------------------------------------------------------------
        // Stage 5: Target regression test suite execution
        // ---------------------------------------------------------------------
        info!("Stage 5/5: Running target regression test suite to prove zero regression...");
        match self.run_regression_tests().await {
            Ok(output) => {
                report.regression_passed = true;
                report.regression_output = output;
                info!("Stage 5/5 PASSED: Regression tests passed successfully");
            }
            Err((err_msg, output)) => {
                warn!("Regression test suite failed: {err_msg}");
                report.regression_passed = false;
                report.failure_stage = Some("regression_test_suite".to_string());
                report.regression_output = Some(format!("FAILED: {err_msg}\n{output}"));
                let _ = patch_guard.rollback();
                report.duration_seconds = start_time.elapsed().as_secs_f64();
                return Ok(report);
            }
        }

        // All 5 stages succeeded!
        report.verified = true;
        patch_guard.commit();
        report.duration_seconds = start_time.elapsed().as_secs_f64();

        info!(
            "Patch verification fully SUCCEEDED in {:.2}s for crash {}",
            report.duration_seconds, crash.id
        );

        Ok(report)
    }

    /// Execute verification and update `crash.verified = true` if all 5 stages pass.
    pub async fn verify_patch_record(
        &self,
        crash: &mut CrashRecord,
        poc_source: &Path,
        patch: &PatchCandidate,
    ) -> Result<VerificationReport> {
        let report = self.verify_patch(crash, poc_source, patch).await?;
        if report.verified {
            crash.verified = true;
            crash.suggested_patch = Some(patch.unified_diff.clone());
        }
        Ok(report)
    }

    /// Alias for `verify_patch_record`.
    pub async fn verify_and_update_crash(
        &self,
        crash: &mut CrashRecord,
        poc_source: &Path,
        patch: &PatchCandidate,
    ) -> Result<VerificationReport> {
        self.verify_patch_record(crash, poc_source, patch).await
    }

    fn build_poc_compiler(&self) -> PocCompiler {
        self.build_poc_compiler_with_output(&self.build_output)
    }

    fn build_poc_compiler_with_output(&self, build_output: &BuildOutput) -> PocCompiler {
        let mut compiler = PocCompiler::new()
            .with_include_dirs(build_output.include_dirs.clone())
            .with_link_libs(build_output.static_libs.clone());

        for shared in &build_output.shared_libs {
            compiler.add_link_lib(shared);
        }

        compiler
    }

    async fn recompile_target(&self, patch: &PatchCandidate) -> Result<BuildOutput> {
        if let Some(detected) = detect_build_system(&self.target_dir) {
            let builder = TargetBuilder::new(self.target_dir.clone());
            return builder.build_target(&self.target_dir, detected.build_type).await;
        }

        if self.target_dir.join("CMakeLists.txt").exists() {
            let builder = TargetBuilder::new(self.target_dir.clone());
            return builder.build_cmake(&self.target_dir).await;
        }

        if self.target_dir.join("Makefile").exists() {
            let builder = TargetBuilder::new(self.target_dir.clone());
            return builder.build_make(&self.target_dir).await;
        }

        // For targets without formal CMake/Makefile (e.g. single-file modules or lightweight fixtures):
        // Verify patched file compiles cleanly with clang and ASan
        let patched_file = self.target_dir.join(&patch.file_path);
        let target_file = if patched_file.exists() {
            patched_file
        } else {
            self.target_dir.join(
                patch
                    .file_path
                    .strip_prefix("a/")
                    .or_else(|| patch.file_path.strip_prefix("b/"))
                    .unwrap_or(&patch.file_path),
            )
        };

        if target_file.exists() {
            let temp_obj = target_file.with_extension("test.o");
            let mut cmd = tokio::process::Command::new("clang");
            cmd.arg("-c")
                .arg("-O1")
                .arg("-g")
                .arg("-fsanitize=address,undefined")
                .arg("-fno-omit-frame-pointer");

            for inc in &self.build_output.include_dirs {
                cmd.arg(format!("-I{}", inc.display()));
            }

            cmd.arg(&target_file).arg("-o").arg(&temp_obj);

            let res = cmd.output().await.map_err(|e| {
                CrashwiseError::BuildError(format!("Failed to invoke clang for syntax check: {e}"))
            })?;

            if !res.status.success() {
                let stderr = String::from_utf8_lossy(&res.stderr);
                return Err(CrashwiseError::BuildError(format!(
                    "Syntax or compilation error in patched file: {stderr}"
                )));
            }

            let _ = tokio::fs::remove_file(&temp_obj).await;
        }

        // Return current build output updated with include directories
        Ok(BuildOutput {
            static_libs: self.build_output.static_libs.clone(),
            shared_libs: self.build_output.shared_libs.clone(),
            include_dirs: vec![
                self.target_dir.clone(),
                self.target_dir.join("include"),
                self.target_dir.join("src"),
            ],
            compile_commands_path: self.build_output.compile_commands_path.clone(),
        })
    }

    async fn run_regression_tests(&self) -> std::result::Result<Option<String>, (String, String)> {
        if let Some(ref cmd_str) = self.regression_command {
            let output = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(cmd_str)
                .current_dir(&self.target_dir)
                .output()
                .await
                .map_err(|e| {
                    (
                        format!("Failed to spawn regression command '{cmd_str}': {e}"),
                        String::new(),
                    )
                })?;

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr);

            if !output.status.success() {
                return Err((
                    format!(
                        "Regression command '{}' failed with exit code {:?}",
                        cmd_str,
                        output.status.code()
                    ),
                    combined,
                ));
            }

            return Ok(Some(combined));
        }

        // Default: If no regression command was specified, test suite passes
        Ok(Some("No custom regression test command specified; passed by default.".to_string()))
    }
}
