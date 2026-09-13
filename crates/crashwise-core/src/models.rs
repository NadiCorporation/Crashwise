use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerEngine {
    #[default]
    Libfuzzer,
    Aflpp,
    Honggfuzz,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Pending,
    Building,
    Synthesizing,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTarget {
    pub repo_url: String,
    pub name: String,
    pub subdir: Option<String>,
    pub clone_depth: u32,
    pub commit_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id: Uuid,
    pub target: CampaignTarget,
    pub engine: FuzzerEngine,
    pub status: CampaignStatus,
    pub timeout_seconds: u64,
    pub max_iterations: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Campaign {
    pub fn new(target: CampaignTarget, engine: FuzzerEngine, timeout_seconds: u64, max_iterations: u32) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            target,
            engine,
            status: CampaignStatus::Pending,
            timeout_seconds,
            max_iterations,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Harness {
    pub id: Uuid,
    pub campaign_id: Uuid,
    pub target_function: String,
    pub source_path: PathBuf,
    pub code: String,
    pub binary_path: Option<PathBuf>,
    pub iteration: u32,
    pub compile_success: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    pub id: Uuid,
    pub campaign_id: Uuid,
    pub crash_type: String,
    pub stack_hash: String,
    pub stack_trace: String,
    pub input_path: PathBuf,
    pub cwe_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub suggested_patch: Option<String>,
    pub poc_c_code: Option<String>,
    pub verified: bool,
    pub found_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub active_campaigns: usize,
    pub execs_per_sec: u64,
    pub total_executions: u64,
    pub unique_edges: u64,
    pub crashes_found: usize,
    pub uptime_seconds: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFeedbackRecord {
    pub id: Uuid,
    pub campaign_id: Option<Uuid>,
    pub target_name: String,
    pub feedback_type: String, // "compiler_error" | "resolved_fix" | "coverage_token" | "harness_exemplar"
    pub compiler_diagnostic: Option<String>,
    pub error_category: Option<String>,
    pub original_code: Option<String>,
    pub resolved_code: Option<String>,
    pub coverage_tokens: Option<Vec<String>>,
    pub success_count: u32,
    pub failure_count: u32,
    pub score: f32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

