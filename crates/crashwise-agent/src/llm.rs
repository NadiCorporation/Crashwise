use crashwise_core::error::{CrashwiseError, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionChoice {
    pub message: ChatMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    pub choices: Vec<ChatCompletionChoice>,
}

pub struct LlmClient {
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub client: reqwest::Client,
}

impl LlmClient {
    pub fn new(base_url: String, api_key: Option<String>, model: String) -> Self {
        Self {
            base_url,
            api_key,
            model,
            client: reqwest::Client::new(),
        }
    }

    pub async fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let endpoint = if self.base_url.ends_with("/chat/completions") {
            self.base_url.clone()
        } else {
            format!("{}/chat/completions", self.base_url.trim_end_matches('/'))
        };

        let request = ChatCompletionRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_prompt.to_string(),
                },
            ],
            temperature: 0.1,
        };

        let mut req_builder = self.client.post(&endpoint).json(&request);
        if let Some(key) = &self.api_key {
            req_builder = req_builder.bearer_auth(key);
        }

        info!("Dispatching LLM completion request to {}", endpoint);
        let resp = req_builder
            .send()
            .await
            .map_err(|e| CrashwiseError::HarnessError(format!("LLM HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(CrashwiseError::HarnessError(format!("LLM API returned error: {error_text}")));
        }

        let completion: ChatCompletionResponse = resp
            .json()
            .await
            .map_err(|e| CrashwiseError::HarnessError(format!("Failed to parse LLM response: {e}")))?;

        completion
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| CrashwiseError::HarnessError("LLM returned empty completion choices".to_string()))
    }
}
