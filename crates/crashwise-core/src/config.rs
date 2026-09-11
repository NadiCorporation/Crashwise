use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashwiseConfig {
    pub workdir: PathBuf,
    pub build_timeout_seconds: u64,
    pub fuzz_timeout_seconds: u64,
    pub api_host: String,
    pub api_port: u16,
    pub llm_provider: String,
    pub llm_model: String,
    pub llm_base_url: Option<String>,
    pub llm_api_key: Option<String>,
}

impl Default for CrashwiseConfig {
    fn default() -> Self {
        let workdir = std::env::var("CRASHWISE_WORKDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/crashwise"));

        let build_timeout_seconds = std::env::var("CRASHWISE_BUILD_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(900);

        let fuzz_timeout_seconds = std::env::var("CRASHWISE_FUZZ_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);

        let api_host = std::env::var("CRASHWISE_API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let api_port = std::env::var("CRASHWISE_API_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8000);

        let llm_provider = std::env::var("CRASHWISE_LLM_PROVIDER").unwrap_or_else(|_| "deepseek".to_string());
        let llm_model = std::env::var("CRASHWISE_LLM_MODEL").unwrap_or_else(|_| "deepseek-chat".to_string());
        let llm_base_url = std::env::var("OPENAI_API_BASE").ok();
        let llm_api_key = std::env::var("OPENAI_API_KEY")
            .or_else(|_| std::env::var("ANTHROPIC_API_KEY"))
            .or_else(|_| std::env::var("CRASHWISE_LLM_API_KEY"))
            .ok();

        Self {
            workdir,
            build_timeout_seconds,
            fuzz_timeout_seconds,
            api_host,
            api_port,
            llm_provider,
            llm_model,
            llm_base_url,
            llm_api_key,
        }
    }
}
