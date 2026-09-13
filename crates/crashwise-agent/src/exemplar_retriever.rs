use crashwise_core::db::{classify_compiler_error, Database};
use crashwise_core::error::Result;
use crashwise_core::models::AgentFeedbackRecord;

/// Dynamic exemplar retrieval and prompt augmentation engine.
/// Queries historical feedback memory in SQLite and formats high-value
/// exemplars, coverage-expanding tokens, and compiler repair patterns
/// into LLM prompt contexts.
pub struct ExemplarRetriever;

impl ExemplarRetriever {
    /// Retrieve verified harness exemplars for a specific target (or generic fallback).
    pub fn retrieve_exemplars(
        db: &Database,
        target_name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AgentFeedbackRecord>> {
        db.query_harness_exemplars(target_name, limit)
    }

    /// Retrieve high-value coverage tokens for a target codebase.
    pub fn retrieve_coverage_tokens(
        db: &Database,
        target_name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>> {
        db.query_coverage_tokens(target_name, limit)
    }

    /// Retrieve similar historical compiler fixes matching a diagnostic stderr.
    pub fn retrieve_similar_fixes(
        db: &Database,
        diagnostic: &str,
        target_name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AgentFeedbackRecord>> {
        db.query_similar_compiler_fixes(diagnostic, target_name, limit)
    }

    /// Classify a compiler diagnostic into an error category.
    pub fn classify_error(diagnostic: &str) -> String {
        classify_compiler_error(diagnostic)
    }

    /// Extract key compiler diagnostic lines (e.g., error messages and notes) from raw stderr.
    pub fn extract_diagnostic_summary(raw_stderr: &str) -> String {
        let mut key_lines = Vec::new();
        for line in raw_stderr.lines() {
            let trimmed = line.trim();
            if trimmed.contains("error:")
                || trimmed.contains("fatal error:")
                || trimmed.contains("note:")
                || trimmed.contains("undefined reference")
                || trimmed.contains("cannot open")
            {
                key_lines.push(trimmed);
            }
        }

        if key_lines.is_empty() {
            // Fall back to first 10 lines of stderr
            raw_stderr
                .lines()
                .take(10)
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            key_lines.join("\n")
        }
    }

    /// Format verified harness exemplars into a prompt context section.
    pub fn format_exemplars_section(exemplars: &[AgentFeedbackRecord]) -> String {
        if exemplars.is_empty() {
            return String::new();
        }

        let mut out = String::from("\n\n### VERIFIED HARNESS EXEMPLARS FOR THIS TARGET:\n");
        out.push_str("// Study these working harnesses for required headers, type casts, and calling conventions:\n\n");

        for (idx, ex) in exemplars.iter().enumerate() {
            out.push_str(&format!(
                "// Exemplar #{} (Target: {}, Score: {:.2}):\n",
                idx + 1,
                ex.target_name,
                ex.score
            ));
            if let Some(code) = &ex.resolved_code {
                out.push_str("```cpp\n");
                out.push_str(code.trim());
                out.push_str("\n```\n\n");
            }
        }
        out
    }

    /// Format high-value coverage tokens into a prompt context section.
    pub fn format_coverage_tokens_section(tokens: &[String]) -> String {
        if tokens.is_empty() {
            return String::new();
        }

        let mut out = String::from("\n\n### HIGH-VALUE COVERAGE TOKENS:\n");
        out.push_str("// These API symbols and tokens are known to expand edge coverage for this target:\n");
        let json_tokens = serde_json::to_string(tokens).unwrap_or_else(|_| "[]".to_string());
        out.push_str(&json_tokens);
        out.push('\n');
        out
    }

    /// Format historical compiler error resolutions into a prompt context section.
    pub fn format_compiler_fixes_section(fixes: &[AgentFeedbackRecord]) -> String {
        if fixes.is_empty() {
            return String::new();
        }

        let mut out = String::from("\n\n### HISTORICAL RESOLUTIONS FOR SIMILAR COMPILER ERRORS:\n");
        out.push_str("// Previous synthesis attempts encountered similar compiler errors and resolved them as follows:\n\n");

        for (idx, fix) in fixes.iter().enumerate() {
            let cat = fix.error_category.as_deref().unwrap_or("compiler_error");
            out.push_str(&format!(
                "// Resolution #{} [Category: {}] (Target: {}):\n",
                idx + 1,
                cat,
                fix.target_name
            ));
            if let Some(diag) = &fix.compiler_diagnostic {
                let first_line = diag.lines().next().unwrap_or(diag).trim();
                out.push_str(&format!("// Diagnostic: {}\n", first_line));
            }
            if let Some(orig) = &fix.original_code {
                out.push_str("// Failing code snippet:\n```cpp\n");
                out.push_str(orig.trim());
                out.push_str("\n```\n");
            }
            if let Some(resolved) = &fix.resolved_code {
                out.push_str("// Successful resolved code:\n```cpp\n");
                out.push_str(resolved.trim());
                out.push_str("\n```\n\n");
            }
        }
        out
    }

    /// Build an augmented user prompt injecting target exemplars and coverage tokens.
    pub fn build_augmented_user_prompt(
        base_prompt: &str,
        exemplars: &[AgentFeedbackRecord],
        coverage_tokens: &[String],
    ) -> String {
        let mut prompt = base_prompt.to_string();
        if !exemplars.is_empty() || !coverage_tokens.is_empty() {
            prompt.push_str("\n\n[Context from Feedback Memory]:");
            prompt.push_str(&Self::format_exemplars_section(exemplars));
            prompt.push_str(&Self::format_coverage_tokens_section(coverage_tokens));
        }
        prompt
    }

    /// Build a compiler error retry prompt incorporating diagnostic and matching historical fixes.
    pub fn build_compiler_retry_prompt(
        raw_diagnostic: &str,
        failing_code: &str,
        similar_fixes: &[AgentFeedbackRecord],
    ) -> String {
        let summary = Self::extract_diagnostic_summary(raw_diagnostic);
        let mut prompt = format!(
            "Previous harness failed to compile with clang++:\n{}\n\nFailing harness code snippet:\n```cpp\n{}\n```\n\nFix the compiler errors. Ensure all target headers are included and types are cast correctly:",
            summary,
            failing_code.trim()
        );

        if !similar_fixes.is_empty() {
            prompt.push_str(&Self::format_compiler_fixes_section(similar_fixes));
        }

        prompt
    }

    /// Extract target header from file path or symbol name heuristics.
    pub fn infer_target_header(file_path: &std::path::Path) -> Option<String> {
        let file_stem = file_path.file_stem()?.to_string_lossy();
        let file_name = file_path.file_name()?.to_string_lossy();

        if file_name.ends_with(".h") || file_name.ends_with(".hpp") {
            return Some(file_name.to_string());
        }

        // Common C conventions: cJSON.c -> cJSON.h, zlib.c -> zlib.h, etc.
        Some(format!("{file_stem}.h"))
    }
}
