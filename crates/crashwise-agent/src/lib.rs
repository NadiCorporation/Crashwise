pub mod exemplar_retriever;
pub mod harness_synth;
pub mod llm;
pub mod sanity_gate;

pub use exemplar_retriever::ExemplarRetriever;
pub use harness_synth::HarnessSynthesizer;
pub use llm::{
    ChatCompletionChoice, ChatCompletionRequest, ChatCompletionResponse, ChatMessage, LlmClient,
    LlmProvider, MockLlmClient,
};
pub use sanity_gate::SanityGate;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crashwise_ast::types::{FunctionSignature, ParameterInfo};
    use crashwise_core::db::Database;
    use crashwise_core::models::AgentFeedbackRecord;
    use std::path::PathBuf;
    use std::sync::Arc;
    use uuid::Uuid;

    fn sample_func(name: &str, ret: &str, params: Vec<ParameterInfo>) -> FunctionSignature {
        FunctionSignature {
            name: name.to_string(),
            return_type: ret.to_string(),
            parameters: params,
            file_path: PathBuf::from("targets/cJSON/cJSON.c"),
            line_number: 100,
            is_static: false,
            is_exported: true,
            has_body: true,
        }
    }

    #[test]
    fn test_exemplar_formatting_empty_and_populated() {
        assert_eq!(ExemplarRetriever::format_exemplars_section(&[]), "");
        assert_eq!(ExemplarRetriever::format_coverage_tokens_section(&[]), "");
        assert_eq!(ExemplarRetriever::format_compiler_fixes_section(&[]), "");

        let ex = AgentFeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: "cJSON".to_string(),
            feedback_type: "harness_exemplar".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: Some("int LLVMFuzzerTestOneInput(...) { return 0; }".to_string()),
            coverage_tokens: None,
            success_count: 3,
            failure_count: 0,
            score: 0.95,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let formatted = ExemplarRetriever::format_exemplars_section(&[ex]);
        assert!(formatted.contains("### VERIFIED HARNESS EXEMPLARS FOR THIS TARGET:"));
        assert!(formatted.contains("cJSON"));
        assert!(formatted.contains("LLVMFuzzerTestOneInput"));

        let tokens = vec!["cJSON_Parse".to_string(), "cJSON_Delete".to_string()];
        let formatted_tokens = ExemplarRetriever::format_coverage_tokens_section(&tokens);
        assert!(formatted_tokens.contains("### HIGH-VALUE COVERAGE TOKENS:"));
        assert!(formatted_tokens.contains("cJSON_Parse"));
        assert!(formatted_tokens.contains("cJSON_Delete"));

        let fix = AgentFeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: "cJSON".to_string(),
            feedback_type: "resolved_fix".to_string(),
            compiler_diagnostic: Some("error: 'cJSON.h' file not found".to_string()),
            error_category: Some("missing_header".to_string()),
            original_code: Some("#include <wrong.h>".to_string()),
            resolved_code: Some("#include <cJSON.h>".to_string()),
            coverage_tokens: None,
            success_count: 1,
            failure_count: 0,
            score: 1.0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let formatted_fixes = ExemplarRetriever::format_compiler_fixes_section(&[fix]);
        assert!(formatted_fixes.contains("### HISTORICAL RESOLUTIONS FOR SIMILAR COMPILER ERRORS:"));
        assert!(formatted_fixes.contains("missing_header"));
        assert!(formatted_fixes.contains("#include <cJSON.h>"));
    }

    #[test]
    fn test_diagnostic_summary_and_error_classification() {
        let raw_diag = r#"/tmp/harness.cpp:3:10: fatal error: 'cJSON.h' file not found
#include <cJSON.h>
         ^~~~~~~~~
1 error generated."#;

        let summary = ExemplarRetriever::extract_diagnostic_summary(raw_diag);
        assert!(summary.contains("fatal error: 'cJSON.h' file not found"));

        let cat = ExemplarRetriever::classify_error(raw_diag);
        assert_eq!(cat, "missing_header");

        let undefined_diag = "undefined reference to `cJSON_Parse'";
        assert_eq!(
            ExemplarRetriever::classify_error(undefined_diag),
            "undefined_symbol"
        );
    }

    #[test]
    fn test_dynamic_exemplar_retrieval_and_prompt_augmentation() {
        let db = Database::open_in_memory().unwrap();

        // 1. Insert exemplar
        let ex = AgentFeedbackRecord {
            id: Uuid::new_v4(),
            campaign_id: None,
            target_name: "cJSON".to_string(),
            feedback_type: "harness_exemplar".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: Some("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { cJSON *j = cJSON_Parse((const char*)data); if(j) cJSON_Delete(j); return 0; }".to_string()),
            coverage_tokens: None,
            success_count: 5,
            failure_count: 0,
            score: 1.0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_feedback_record(&ex).unwrap();

        // 2. Insert coverage tokens
        db.record_coverage_tokens(
            None,
            "cJSON",
            &["cJSON_ParseWithLength".to_string(), "cJSON_PrintUnformatted".to_string()],
        )
        .unwrap();

        // 3. Build prompts with synthesizer
        let mock_llm = Arc::new(MockLlmClient::new(vec![]));
        let synth = HarnessSynthesizer::from_provider(mock_llm)
            .with_db(db)
            .with_target_name("cJSON");

        let func = sample_func(
            "cJSON_Parse",
            "cJSON *",
            vec![ParameterInfo {
                name: "value".to_string(),
                type_name: "char".to_string(),
                is_pointer: true,
                is_const: true,
            }],
        );

        let (_sys, user) = synth.build_synthesis_prompts(&func, Some("cJSON")).unwrap();

        assert!(user.contains("cJSON_Parse"));
        assert!(user.contains("Full Prototype: cJSON * cJSON_Parse(const char* value)"));
        assert!(user.contains("[Context from Feedback Memory]"));
        assert!(user.contains("### VERIFIED HARNESS EXEMPLARS FOR THIS TARGET:"));
        assert!(user.contains("cJSON_ParseWithLength"));
        assert!(user.contains("cJSON_PrintUnformatted"));
    }

    #[test]
    fn test_code_block_extraction() {
        let mock = LlmClient::new("http://localhost:8080".to_string(), None, "mock".to_string());
        let synth = HarnessSynthesizer::new(mock);

        let fenced = "Here is the harness:\n```cpp\nextern \"C\" int LLVMFuzzerTestOneInput() { return 0; }\n```\nEnjoy!";
        let extracted = synth.extract_code_block(fenced).unwrap();
        assert_eq!(
            extracted,
            "extern \"C\" int LLVMFuzzerTestOneInput() { return 0; }"
        );

        let fenced_c = "```c\nextern \"C\" int LLVMFuzzerTestOneInput() { return 0; }\n```";
        let extracted_c = synth.extract_code_block(fenced_c).unwrap();
        assert_eq!(
            extracted_c,
            "extern \"C\" int LLVMFuzzerTestOneInput() { return 0; }"
        );

        let unfenced = "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }";
        let extracted_unfenced = synth.extract_code_block(unfenced).unwrap();
        assert_eq!(extracted_unfenced, unfenced);

        let invalid = "Just some text without any code.";
        assert!(synth.extract_code_block(invalid).is_err());
    }

    #[test]
    fn test_deterministic_harness_synthesis() {
        let func = sample_func(
            "cJSON_Parse",
            "cJSON *",
            vec![ParameterInfo {
                name: "value".to_string(),
                type_name: "char".to_string(),
                is_pointer: true,
                is_const: true,
            }],
        );

        let harness = HarnessSynthesizer::synthesize_deterministic_harness(
            &func,
            Some("cJSON"),
            Some("cJSON.h"),
        );

        assert!(harness.contains("#include <cJSON.h>"));
        assert!(harness.contains("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"));
        assert!(harness.contains("cJSON_Parse("));
        assert!(harness.contains("cJSON_Delete"));
        assert!(harness.contains("free("));
    }

    #[test]
    fn test_mock_llm_records_prompts() {
        let mock = Arc::new(MockLlmClient::new(vec![
            "```cpp\nextern \"C\" int LLVMFuzzerTestOneInput() { return 0; }\n```".to_string(),
        ]));

        let synth = HarnessSynthesizer::from_provider(mock.clone())
            .with_target_name("test_target")
            .with_campaign_id(Uuid::new_v4());

        assert_eq!(synth.target_name(), Some("test_target"));
        assert!(synth.campaign_id().is_some());
        assert_eq!(mock.recorded_prompts().len(), 0);
    }
}
