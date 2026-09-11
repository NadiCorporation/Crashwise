use crate::llm::LlmClient;
use crate::sanity_gate::SanityGate;
use crashwise_ast::types::FunctionSignature;
use crashwise_core::error::{CrashwiseError, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{info, warn};

pub struct HarnessSynthesizer {
    llm: LlmClient,
    max_retries: usize,
}

impl HarnessSynthesizer {
    pub fn new(llm: LlmClient) -> Self {
        Self {
            llm,
            max_retries: 3,
        }
    }

    pub async fn synthesize_and_validate(
        &self,
        func: &FunctionSignature,
        include_dirs: &[PathBuf],
        static_libs: &[PathBuf],
        output_dir: &Path,
    ) -> Result<PathBuf> {
        let system_prompt = r#"You are a principal vulnerability researcher writing libFuzzer C/C++ fuzzing harnesses.
RULES:
1. Output ONLY a single fenced code block tagged ```cpp. No explanations.
2. The harness MUST define: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
3. Do NOT redefine or stub target functions. Always #include the target headers and call the public API.
4. Use FuzzedDataProvider if splitting data is required. Guard against NULL returns. Free all allocations."#;

        let mut user_prompt = format!(
            "Generate a production-grade libFuzzer harness for the following target function:\n\nName: {}\nReturn type: {}\nFile: {}\nLine: {}\n\nSignature: {}(...)",
            func.name,
            func.return_type,
            func.file_path.display(),
            func.line_number,
            func.name,
        );

        let harness_cpp = output_dir.join(format!("harness_{}.cpp", func.name));
        let harness_bin = output_dir.join(format!("fuzz_{}", func.name));

        for attempt in 1..=self.max_retries {
            info!("Harness synthesis attempt {}/{} for {}", attempt, self.max_retries, func.name);
            let response = self.llm.complete(system_prompt, &user_prompt).await?;
            let code = self.extract_code_block(&response)?;

            tokio::fs::write(&harness_cpp, &code).await?;

            match self.compile_harness(&harness_cpp, &harness_bin, include_dirs, static_libs).await {
                Ok(_) => {
                    info!("Harness compiled successfully! Verifying with Sanity Gate...");
                    match SanityGate::verify_harness_binary(&harness_bin).await {
                        Ok(_) => return Ok(harness_bin),
                        Err(e) => {
                            warn!("Harness failed sanity gate: {e}. Retrying synthesis with diagnostic feedback...");
                            user_prompt = format!(
                                "Previous harness failed runtime sanity verification:\n{}\n\nFix the harness code to prevent crashes and leaks:",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("Harness compilation error: {e}. Feeding compiler error back to LLM for self-correction...");
                    user_prompt = format!(
                        "Previous harness failed to compile with clang++:\n{}\n\nFix the compiler errors. Ensure all headers are included and types are cast correctly:",
                        e
                    );
                }
            }
        }

        Err(CrashwiseError::HarnessError(format!(
            "Failed to synthesize valid harness for {} after {} attempts",
            func.name, self.max_retries
        )))
    }

    fn extract_code_block(&self, raw: &str) -> Result<String> {
        let re = regex::Regex::new(r"```(?:cpp|c)?\s*\n([\s\S]*?)\n```").unwrap();
        if let Some(caps) = re.captures(raw) {
            if let Some(m) = caps.get(1) {
                return Ok(m.as_str().to_string());
            }
        }
        if raw.contains("LLVMFuzzerTestOneInput") {
            return Ok(raw.to_string());
        }
        Err(CrashwiseError::HarnessError("LLM response did not contain a valid C/C++ code block".to_string()))
    }

    pub async fn compile_harness(
        &self,
        harness_src: &Path,
        harness_bin: &Path,
        include_dirs: &[PathBuf],
        static_libs: &[PathBuf],
    ) -> Result<()> {
        let mut cmd = Command::new("clang++");
        cmd.arg("-O1")
            .arg("-g")
            .arg("-fsanitize=fuzzer,address,undefined")
            .arg(harness_src)
            .arg("-o")
            .arg(harness_bin);

        for inc in include_dirs {
            cmd.arg(format!("-I{}", inc.display()));
        }

        for lib in static_libs {
            cmd.arg(lib);
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| CrashwiseError::HarnessError(format!("Failed to invoke clang++: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CrashwiseError::HarnessError(stderr.to_string()));
        }

        Ok(())
    }
}
