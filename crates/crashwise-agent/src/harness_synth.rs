use crate::exemplar_retriever::ExemplarRetriever;
use crate::llm::{LlmClient, LlmProvider};
use crate::sanity_gate::SanityGate;
use chrono::Utc;
use crashwise_ast::types::FunctionSignature;
use crashwise_core::db::Database;
use crashwise_core::error::{CrashwiseError, Result};
use crashwise_core::models::AgentFeedbackRecord;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;
use tracing::{info, warn};
use uuid::Uuid;

pub struct HarnessSynthesizer {
    llm: Arc<dyn LlmProvider>,
    max_retries: usize,
    db: Option<Database>,
    target_name: Option<String>,
    campaign_id: Option<Uuid>,
}

impl HarnessSynthesizer {
    /// Create a new synthesizer with a default LlmClient.
    pub fn new(llm: LlmClient) -> Self {
        Self {
            llm: Arc::new(llm),
            max_retries: 3,
            db: None,
            target_name: None,
            campaign_id: None,
        }
    }

    /// Create a synthesizer with an arbitrary LlmProvider (e.g. MockLlmClient).
    pub fn from_provider(provider: Arc<dyn LlmProvider>) -> Self {
        Self {
            llm: provider,
            max_retries: 3,
            db: None,
            target_name: None,
            campaign_id: None,
        }
    }

    /// Attach a Database instance for feedback memory retrieval and self-correction learning.
    pub fn with_db(mut self, db: Database) -> Self {
        self.db = Some(db);
        self
    }

    /// Configure the target name (e.g., "cJSON", "zlib", "libpng", "sqlite3").
    pub fn with_target_name(mut self, target_name: impl Into<String>) -> Self {
        self.target_name = Some(target_name.into());
        self
    }

    /// Configure campaign ID for association with feedback memory records.
    pub fn with_campaign_id(mut self, campaign_id: Uuid) -> Self {
        self.campaign_id = Some(campaign_id);
        self
    }

    /// Configure maximum retry attempts on compilation or sanity failure.
    pub fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn db(&self) -> Option<&Database> {
        self.db.as_ref()
    }

    pub fn target_name(&self) -> Option<&str> {
        self.target_name.as_deref()
    }

    pub fn campaign_id(&self) -> Option<Uuid> {
        self.campaign_id
    }

    /// Build the standard system prompt.
    pub fn base_system_prompt() -> &'static str {
        r#"You are a principal vulnerability researcher writing libFuzzer C/C++ fuzzing harnesses.
RULES:
1. Output ONLY a single fenced code block tagged ```cpp. No explanations.
2. The harness MUST define: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
3. Do NOT redefine or stub target functions. Always #include the target headers and call the public API.
4. Always wrap C header includes with extern "C" { ... } when compiling as C++.
5. Include <stdint.h>, <stddef.h>, <stdlib.h>, and <string.h>.
6. Guard against empty inputs (if (size == 0) return 0;).
7. Free all allocated structures and handles to prevent AddressSanitizer false positives."#
    }

    /// Infer target name from function file path if not explicitly configured.
    pub fn infer_target_name(file_path: &Path) -> Option<String> {
        let path_str = file_path.to_string_lossy().to_lowercase();
        if path_str.contains("cjson") {
            Some("cJSON".to_string())
        } else if path_str.contains("zlib") {
            Some("zlib".to_string())
        } else if path_str.contains("png") || path_str.contains("libpng") {
            Some("libpng".to_string())
        } else if path_str.contains("sqlite") {
            Some("sqlite3".to_string())
        } else {
            file_path.file_stem().map(|stem| stem.to_string_lossy().to_string())
        }
    }

    /// Format detailed signature and parameter information for the target function.
    pub fn build_target_function_details(func: &FunctionSignature) -> String {
        let params_formatted = if func.parameters.is_empty() {
            "void".to_string()
        } else {
            func.parameters
                .iter()
                .map(|p| {
                    let const_prefix = if p.is_const { "const " } else { "" };
                    let ptr_suffix = if p.is_pointer { "*" } else { "" };
                    format!("{const_prefix}{}{ptr_suffix} {}", p.type_name, p.name)
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut details = format!(
            "Function Name: {}\nReturn Type: {}\nFull Prototype: {} {}({})\nSource Location: {}:{}\n",
            func.name,
            func.return_type,
            func.return_type,
            func.name,
            params_formatted,
            func.file_path.display(),
            func.line_number
        );

        if !func.parameters.is_empty() {
            details.push_str("Parameters Breakdown:\n");
            for (idx, p) in func.parameters.iter().enumerate() {
                details.push_str(&format!(
                    "  {}. Name: '{}', Type: '{}', Pointer: {}, Const: {}\n",
                    idx + 1,
                    p.name,
                    p.type_name,
                    p.is_pointer,
                    p.is_const
                ));
            }
        }

        if let Some(header) = ExemplarRetriever::infer_target_header(&func.file_path) {
            details.push_str(&format!("Recommended Include: #include \"{}\"\n", header));
        }

        details
    }

    /// Construct initial synthesis prompts, dynamically retrieving exemplars and coverage tokens if DB is present.
    pub fn build_synthesis_prompts(
        &self,
        func: &FunctionSignature,
        target_name: Option<&str>,
    ) -> Result<(String, String)> {
        let system_prompt = Self::base_system_prompt().to_string();

        let target_details = Self::build_target_function_details(func);
        let base_user_prompt = format!(
            "Generate a production-grade libFuzzer harness for the following target function:\n\n{}",
            target_details
        );

        if let Some(db) = &self.db {
            let exemplars = ExemplarRetriever::retrieve_exemplars(db, target_name, 2)?;
            let tokens = ExemplarRetriever::retrieve_coverage_tokens(db, target_name, 15)?;
            let augmented_user = ExemplarRetriever::build_augmented_user_prompt(
                &base_user_prompt,
                &exemplars,
                &tokens,
            );
            Ok((system_prompt, augmented_user))
        } else {
            Ok((system_prompt, base_user_prompt))
        }
    }

    /// Synthesize and validate a harness, employing the self-correction compiler loop
    /// and recording feedback exemplars into SQLite.
    pub async fn synthesize_and_validate(
        &self,
        func: &FunctionSignature,
        include_dirs: &[PathBuf],
        static_libs: &[PathBuf],
        output_dir: &Path,
    ) -> Result<PathBuf> {
        let effective_target = self
            .target_name
            .clone()
            .or_else(|| Self::infer_target_name(&func.file_path));
        let target_name_ref = effective_target.as_deref();

        let (system_prompt, mut user_prompt) =
            self.build_synthesis_prompts(func, target_name_ref)?;

        let harness_cpp = output_dir.join(format!("harness_{}.cpp", func.name));
        let harness_bin = output_dir.join(format!("fuzz_{}", func.name));

        let mut last_failing_code: Option<String> = None;
        let mut last_diagnostic: Option<String> = None;

        for attempt in 1..=self.max_retries {
            info!(
                "Harness synthesis attempt {}/{} for {} (target: {:?})",
                attempt, self.max_retries, func.name, target_name_ref
            );
            let response = self.llm.complete(&system_prompt, &user_prompt).await?;
            let code = self.extract_code_block(&response)?;

            tokio::fs::write(&harness_cpp, &code).await?;

            match self
                .compile_harness(&harness_cpp, &harness_bin, include_dirs, static_libs)
                .await
            {
                Ok(_) => {
                    info!("Harness compiled successfully! Verifying with Sanity Gate...");

                    // If this was a successful repair following a compiler failure, record the fix in feedback memory
                    if attempt > 1 {
                        if let (Some(ref orig_code), Some(ref diag)) =
                            (&last_failing_code, &last_diagnostic)
                        {
                            if let Some(db) = &self.db {
                                match db.record_resolved_fix(
                                    self.campaign_id,
                                    target_name_ref.unwrap_or("unknown"),
                                    diag,
                                    orig_code,
                                    &code,
                                ) {
                                    Ok(fix_id) => {
                                        info!(
                                            "Persisted resolved compiler fix to agent_feedback_memory (id: {})",
                                            fix_id
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to persist resolved compiler fix: {e}"
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Reset failure state on successful compilation
                    last_failing_code = None;
                    last_diagnostic = None;

                    match SanityGate::verify_harness_binary(&harness_bin).await {
                        Ok(_) => {
                            info!("Harness passed Sanity Gate!");

                            // Persist verified harness into agent_feedback_memory as a harness_exemplar
                            if let Some(db) = &self.db {
                                let record = AgentFeedbackRecord {
                                    id: Uuid::new_v4(),
                                    campaign_id: self.campaign_id,
                                    target_name: target_name_ref.unwrap_or("unknown").to_string(),
                                    feedback_type: "harness_exemplar".to_string(),
                                    compiler_diagnostic: None,
                                    error_category: None,
                                    original_code: None,
                                    resolved_code: Some(code.clone()),
                                    coverage_tokens: None,
                                    success_count: 1,
                                    failure_count: 0,
                                    score: 1.0,
                                    created_at: Utc::now(),
                                    updated_at: Utc::now(),
                                };

                                match db.insert_feedback_record(&record) {
                                    Ok(_) => {
                                        info!(
                                            "Persisted verified harness exemplar to agent_feedback_memory (id: {})",
                                            record.id
                                        );
                                    }
                                    Err(e) => {
                                        warn!("Failed to persist harness exemplar: {e}");
                                    }
                                }
                            }

                            return Ok(harness_bin);
                        }
                        Err(e) => {
                            warn!(
                                "Harness failed sanity gate: {e}. Retrying synthesis with diagnostic feedback..."
                            );
                            user_prompt = format!(
                                "Previous harness failed runtime sanity verification:\n{}\n\nFix the harness code to prevent crashes and memory leaks:",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    let raw_diag = e.to_string();
                    warn!(
                        "Harness compilation error: {raw_diag}. Feeding compiler error back to LLM for self-correction..."
                    );

                    last_failing_code = Some(code.clone());
                    last_diagnostic = Some(raw_diag.clone());

                    // Query matching historical fixes from feedback memory
                    let similar_fixes = if let Some(db) = &self.db {
                        ExemplarRetriever::retrieve_similar_fixes(
                            db,
                            &raw_diag,
                            target_name_ref,
                            3,
                        )
                        .unwrap_or_default()
                    } else {
                        Vec::new()
                    };

                    user_prompt = ExemplarRetriever::build_compiler_retry_prompt(
                        &raw_diag,
                        &code,
                        &similar_fixes,
                    );
                }
            }
        }

        Err(CrashwiseError::HarnessError(format!(
            "Failed to synthesize valid harness for {} after {} attempts",
            func.name, self.max_retries
        )))
    }

    pub fn extract_code_block(&self, raw: &str) -> Result<String> {
        let re = regex::Regex::new(r"```(?:cpp|c)?\s*\n([\s\S]*?)\n```").unwrap();
        if let Some(caps) = re.captures(raw) {
            if let Some(m) = caps.get(1) {
                return Ok(m.as_str().to_string());
            }
        }
        if raw.contains("LLVMFuzzerTestOneInput") {
            return Ok(raw.to_string());
        }
        Err(CrashwiseError::HarnessError(
            "LLM response did not contain a valid C/C++ code block".to_string(),
        ))
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

    /// Synthesize a deterministic, high-compilation-rate libFuzzer harness template
    /// from a function signature and optional header context.
    pub fn synthesize_deterministic_harness(
        func: &FunctionSignature,
        target_name: Option<&str>,
        target_header: Option<&str>,
    ) -> String {
        let header = target_header
            .map(|h| h.to_string())
            .or_else(|| ExemplarRetriever::infer_target_header(&func.file_path))
            .unwrap_or_else(|| format!("{}.h", target_name.unwrap_or("target")));

        let mut out = String::new();
        out.push_str("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n\n");
        out.push_str("extern \"C\" {\n");
        out.push_str(&format!("#include <{}>\n", header));
        out.push_str("}\n\n");
        out.push_str("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n");
        out.push_str("    if (size == 0) return 0;\n\n");

        // Prepare arguments based on signature
        let mut call_args = Vec::new();
        let mut cleanup_stmts = Vec::new();

        for (idx, p) in func.parameters.iter().enumerate() {
            let arg_var = format!("arg_{}", idx);
            let lower_type = p.type_name.to_lowercase();

            if p.is_pointer {
                if lower_type.contains("char") {
                    out.push_str(&format!(
                        "    char *{} = (char *)malloc(size + 1);\n    if (!{}) return 0;\n    memcpy({}, data, size);\n    {}[size] = '\\0';\n",
                        arg_var, arg_var, arg_var, arg_var
                    ));
                    cleanup_stmts.push(format!("free({});", arg_var));
                    call_args.push(arg_var);
                } else if lower_type.contains("uint8") || lower_type.contains("void") {
                    call_args.push(format!("({})data", p.type_name));
                } else {
                    // Structure pointer or other pointer type
                    out.push_str(&format!(
                        "    {} *{} = ({} *)malloc(sizeof({}));\n    if ({}) memset({}, 0, sizeof({}));\n",
                        p.type_name, arg_var, p.type_name, p.type_name, arg_var, arg_var, p.type_name
                    ));
                    cleanup_stmts.push(format!("if ({}) free({});", arg_var, arg_var));
                    call_args.push(arg_var);
                }
            } else if lower_type.contains("size_t") || lower_type.contains("int") || lower_type.contains("long") {
                out.push_str(&format!("    {} {} = ({})size;\n", p.type_name, arg_var, p.type_name));
                call_args.push(arg_var);
            } else if lower_type.contains("float") || lower_type.contains("double") {
                out.push_str(&format!("    {} {} = 0.0;\n", p.type_name, arg_var));
                call_args.push(arg_var);
            } else {
                out.push_str(&format!("    {} {};\n    memset(&{}, 0, sizeof({}));\n", p.type_name, arg_var, arg_var, p.type_name));
                call_args.push(arg_var);
            }
        }

        let call_str = if call_args.is_empty() {
            format!("{}();", func.name)
        } else {
            format!("{}({});", func.name, call_args.join(", "))
        };

        if func.return_type != "void" {
            out.push_str(&format!("    auto result = {}\n", call_str));
            // Target specific destructors
            if target_name == Some("cJSON") && func.return_type.contains("cJSON") {
                out.push_str("    if (result) cJSON_Delete(result);\n");
            }
        } else {
            out.push_str(&format!("    {}\n", call_str));
        }

        for cleanup in cleanup_stmts {
            out.push_str(&format!("    {}\n", cleanup));
        }

        out.push_str("    return 0;\n}\n");
        out
    }
}
