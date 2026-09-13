pub mod config;
pub mod db;
pub mod error;
pub mod models;

pub use config::CrashwiseConfig;
pub use db::Database;
pub use error::{CrashwiseError, Result};
pub use models::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_persistence() {
        let db = Database::open_in_memory().unwrap();

        let target = CampaignTarget {
            repo_url: "https://github.com/madler/zlib".to_string(),
            name: "zlib".to_string(),
            subdir: None,
            clone_depth: 1,
            commit_hash: None,
        };

        let campaign = Campaign::new(target, FuzzerEngine::Libfuzzer, 300, 3);
        db.insert_campaign(&campaign).unwrap();

        let list = db.list_campaigns().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].target.name, "zlib");
        assert_eq!(list[0].status, CampaignStatus::Pending);

        db.update_campaign_status(campaign.id, CampaignStatus::Running).unwrap();
        let updated = db.list_campaigns().unwrap();
        assert_eq!(updated[0].status, CampaignStatus::Running);
    }

    #[test]
    fn test_feedback_memory_schema_and_indexes() {
        let db = Database::open_in_memory().unwrap();
        // Check that agent_feedback_memory table exists
        assert!(db.table_exists("agent_feedback_memory").unwrap());

        // Verify all 5 indexes exist
        assert!(db.index_exists("idx_feedback_type").unwrap());
        assert!(db.index_exists("idx_feedback_target").unwrap());
        assert!(db.index_exists("idx_feedback_error_cat").unwrap());
        assert!(db.index_exists("idx_feedback_score").unwrap());
        assert!(db.index_exists("idx_feedback_created").unwrap());

        let records = db.query_harness_exemplars(None, 10).unwrap();
        assert!(records.is_empty());
        let tokens = db.query_coverage_tokens(None, 10).unwrap();
        assert!(tokens.is_empty());
    }


    #[test]
    fn test_feedback_memory_crud_and_queries() {
        let db = Database::open_in_memory().unwrap();

        // 1. Record resolved compiler fix
        let fix_id = db
            .record_resolved_fix(
                None,
                "cJSON",
                "fatal error: 'cJSON.h' file not found",
                "#include <missing.h>",
                "#include <cJSON.h>",
            )
            .unwrap();
        assert_ne!(fix_id, uuid::Uuid::nil());

        // 2. Query similar fixes
        let similar = db
            .query_similar_compiler_fixes("error: 'cJSON.h' file not found", Some("cJSON"), 5)
            .unwrap();
        assert_eq!(similar.len(), 1);
        assert_eq!(similar[0].id, fix_id);
        assert_eq!(similar[0].target_name, "cJSON");
        assert_eq!(similar[0].error_category.as_deref(), Some("missing_header"));
        assert_eq!(
            similar[0].resolved_code.as_deref(),
            Some("#include <cJSON.h>")
        );

        // 3. Record coverage tokens
        let tok_id = db
            .record_coverage_tokens(
                None,
                "cJSON",
                &[
                    "cJSON_Parse".to_string(),
                    "cJSON_Delete".to_string(),
                    "cJSON_Print".to_string(),
                ],
            )
            .unwrap();
        assert_ne!(tok_id, uuid::Uuid::nil());

        let tokens = db.query_coverage_tokens(Some("cJSON"), 10).unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(tokens.contains(&"cJSON_Parse".to_string()));
        assert!(tokens.contains(&"cJSON_Delete".to_string()));
        assert!(tokens.contains(&"cJSON_Print".to_string()));

        // 4. Insert harness exemplar
        let exemplar = AgentFeedbackRecord {
            id: uuid::Uuid::new_v4(),
            campaign_id: None,
            target_name: "cJSON".to_string(),
            feedback_type: "harness_exemplar".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: Some("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { cJSON *json = cJSON_ParseWithLength((const char*)data, size); if (json) cJSON_Delete(json); return 0; }".to_string()),
            coverage_tokens: None,
            success_count: 5,
            failure_count: 0,
            score: 0.95,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        db.insert_feedback_record(&exemplar).unwrap();

        let exemplars = db.query_harness_exemplars(Some("cJSON"), 5).unwrap();
        assert_eq!(exemplars.len(), 1);
        assert_eq!(exemplars[0].target_name, "cJSON");
        assert_eq!(exemplars[0].feedback_type, "harness_exemplar");
        assert!(exemplars[0].resolved_code.as_ref().unwrap().contains("cJSON_ParseWithLength"));
    }

    #[test]
    fn test_compiler_fixes_ranking_and_cross_target_exemplars() {
        let db = Database::open_in_memory().unwrap();

        // Insert fixes for different targets and errors
        db.record_resolved_fix(
            None,
            "zlib",
            "error: unknown type name 'z_stream'",
            "void test() { z_stream strm; }",
            "#include <zlib.h>\nvoid test() { z_stream strm; }",
        )
        .unwrap();

        db.record_resolved_fix(
            None,
            "libpng",
            "error: unknown type name 'png_structp'",
            "void test() { png_structp png; }",
            "#include <png.h>\nvoid test() { png_structp png; }",
        )
        .unwrap();

        // Query for zlib error with target zlib
        let results = db
            .query_similar_compiler_fixes("unknown type name 'z_stream'", Some("zlib"), 10)
            .unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].target_name, "zlib");

        // Query for exemplar with fallback to other targets
        let generic_exemplars = db.query_harness_exemplars(Some("unknown_target"), 2).unwrap();
        assert!(generic_exemplars.is_empty()); // No exemplars inserted yet

        // Insert exemplar under 'general'
        let exemplar = AgentFeedbackRecord {
            id: uuid::Uuid::new_v4(),
            campaign_id: None,
            target_name: "common".to_string(),
            feedback_type: "harness_exemplar".to_string(),
            compiler_diagnostic: None,
            error_category: None,
            original_code: None,
            resolved_code: Some("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }".to_string()),
            coverage_tokens: None,
            success_count: 10,
            failure_count: 0,
            score: 0.99,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        db.insert_feedback_record(&exemplar).unwrap();

        // Now querying for an unknown target should fallback to returning available exemplars
        let fallback_exemplars = db.query_harness_exemplars(Some("new_target"), 2).unwrap();
        assert_eq!(fallback_exemplars.len(), 1);
        assert_eq!(fallback_exemplars[0].target_name, "common");
    }
}


