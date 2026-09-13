use crashwise_core::error::{CrashwiseError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
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

/// Abstract provider trait allowing flexible LLM execution (live API vs deterministic mock).
#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String>;
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
            return Err(CrashwiseError::HarnessError(format!(
                "LLM API returned error: {error_text}"
            )));
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

#[async_trait::async_trait]
impl LlmProvider for LlmClient {
    async fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        LlmClient::complete(self, system_prompt, user_prompt).await
    }
}

/// In-memory mock LLM client for deterministic testing of synthesis workflows and prompt verification.
pub struct MockLlmClient {
    responses: Mutex<Vec<String>>,
    recorded_prompts: Mutex<Vec<(String, String)>>,
    #[allow(clippy::type_complexity)]
    handler: Option<Box<dyn Fn(&str, &str) -> Result<String> + Send + Sync>>,
}

impl MockLlmClient {
    pub fn new(responses: Vec<String>) -> Self {
        Self {
            responses: Mutex::new(responses),
            recorded_prompts: Mutex::new(Vec::new()),
            handler: None,
        }
    }

    pub fn with_handler<F>(handler: F) -> Self
    where
        F: Fn(&str, &str) -> Result<String> + Send + Sync + 'static,
    {
        Self {
            responses: Mutex::new(Vec::new()),
            recorded_prompts: Mutex::new(Vec::new()),
            handler: Some(Box::new(handler)),
        }
    }

    pub fn recorded_prompts(&self) -> Vec<(String, String)> {
        self.recorded_prompts.lock().unwrap().clone()
    }

    pub fn last_prompt(&self) -> Option<(String, String)> {
        self.recorded_prompts.lock().unwrap().last().cloned()
    }
}

#[async_trait::async_trait]
impl LlmProvider for MockLlmClient {
    async fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        self.recorded_prompts
            .lock()
            .unwrap()
            .push((system_prompt.to_string(), user_prompt.to_string()));

        if let Some(ref h) = self.handler {
            return h(system_prompt, user_prompt);
        }

        let mut queue = self.responses.lock().unwrap();
        if queue.is_empty() {
            return Err(CrashwiseError::HarnessError(
                "MockLlmClient: no remaining responses in queue".to_string(),
            ));
        }
        Ok(queue.remove(0))
    }
}
