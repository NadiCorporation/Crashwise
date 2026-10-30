//! Agent loop skeleton (ARCHITECTURE.md §2, §3, §6).
//!
//! This module defines the loop's shape, not its full execution:
//! freedom modes, the tool registry with an allowlist, campaign
//! state with hypotheses and budgets, and checkpoint save/load.
//! Tool execution is deliberately out of scope here: each tool in
//! the registry is a named entry whose execution is implemented
//! separately, so the loop can never "invent" a tool or run a
//! shell command from LLM output.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use uuid::Uuid;

/// Freedom set by the master. See ARCHITECTURE.md §1.
/// Freedom of exploration inside the sandbox is high; freedom
/// of external effect is gated and never granted by the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreedomMode {
    Off,
    ReadOnly,
    Assisted,
    LimitedAutonomous,
}

/// A tool the agent may call. The registry in ARCHITECTURE.md §3
/// is the source of truth for these names; adding a name here
/// without an implementation and an allowlist entry is a bug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolName {
    AstScan,
    BuildTarget,
    SynthesizeHarness,
    RunFuzz,
    TriageCrash,
    GeneratePoc,
    SynthesizePatch,
    VerifyPatch,
    ResearchRead,
}

impl ToolName {
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolName::AstScan => "ast_scan",
            ToolName::BuildTarget => "build_target",
            ToolName::SynthesizeHarness => "synthesize_harness",
            ToolName::RunFuzz => "run_fuzz",
            ToolName::TriageCrash => "triage_crash",
            ToolName::GeneratePoc => "generate_poc",
            ToolName::SynthesizePatch => "synthesize_patch",
            ToolName::VerifyPatch => "verify_patch",
            ToolName::ResearchRead => "research_read",
        }
    }

    /// All tools known to the registry.
    pub fn all() -> Vec<ToolName> {
        vec![
            ToolName::AstScan,
            ToolName::BuildTarget,
            ToolName::SynthesizeHarness,
            ToolName::RunFuzz,
            ToolName::TriageCrash,
            ToolName::GeneratePoc,
            ToolName::SynthesizePatch,
            ToolName::VerifyPatch,
            ToolName::ResearchRead,
        ]
    }
}

/// One call the agent wants to make. Arguments are opaque JSON
/// here; each tool validates its own schema before executing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: ToolName,
    pub arguments_json: String,
}

/// Allowlist for a campaign. Only tools in this set may be called.
/// Sending, publishing, disclosing, submitting, and spending are
/// not tools at all and can never appear in an allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRegistry {
    pub allowed: HashSet<ToolName>,
}

impl ToolRegistry {
    pub fn new(allowed: Vec<ToolName>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }

    /// Recommended starting allowlist: read and build/fuzz/triage
    /// tools, with no research egress beyond the allowlisted
    /// gateway (enforced by the research tool itself).
    pub fn assisted_default() -> Self {
        Self::new(ToolName::all())
    }

    pub fn is_allowed(&self, tool: &ToolName) -> bool {
        self.allowed.contains(tool)
    }

    pub fn check(&self, call: &ToolCall) -> Result<(), String> {
        if self.is_allowed(&call.tool) {
            Ok(())
        } else {
            Err(format!(
                "tool '{}' is not in this campaign's allowlist",
                call.tool.as_str()
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypothesisStatus {
    Open,
    Testing,
    Confirmed,
    Refuted,
}

/// A hypothesis the agent is testing, with confidence updated
/// from tool results. Confidence is bookkeeping, not evidence:
/// only a verified evidence bundle counts as a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: Uuid,
    pub description: String,
    pub target_function: Option<String>,
    pub confidence: f32,
    pub status: HypothesisStatus,
}

impl Hypothesis {
    pub fn new(description: &str, target_function: Option<&str>) -> Self {
        Self {
            id: Uuid::new_v4(),
            description: description.to_string(),
            target_function: target_function.map(|s| s.to_string()),
            confidence: 0.5,
            status: HypothesisStatus::Open,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub max_iterations: u32,
    pub max_tokens: Option<u64>,
    pub tokens_used: u64,
    pub iterations_used: u32,
}

impl Budget {
    pub fn new(max_iterations: u32, max_tokens: Option<u64>) -> Self {
        Self {
            max_iterations,
            max_tokens,
            tokens_used: 0,
            iterations_used: 0,
        }
    }

    pub fn exhausted(&self) -> bool {
        if self.iterations_used >= self.max_iterations {
            return true;
        }
        if let Some(max) = self.max_tokens {
            if self.tokens_used >= max {
                return true;
            }
        }
        false
    }
}

/// Persistent campaign state (ARCHITECTURE.md §6). This is the
/// agent's memory: if it is lost, the long horizon is lost.
/// It is saved at every checkpoint and loaded on resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignState {
    pub campaign_id: Uuid,
    pub target: String,
    pub freedom: FreedomMode,
    pub plan: Vec<String>,
    pub hypotheses: Vec<Hypothesis>,
    pub tool_history: Vec<String>,
    pub budget: Budget,
    pub stopped: bool,
    pub stop_reason: Option<String>,
}

impl CampaignState {
    pub fn new(target: &str, freedom: FreedomMode, budget: Budget) -> Self {
        Self {
            campaign_id: Uuid::new_v4(),
            target: target.to_string(),
            freedom,
            plan: Vec::new(),
            hypotheses: Vec::new(),
            tool_history: Vec::new(),
            budget,
            stopped: false,
            stop_reason: None,
        }
    }

    pub fn record_tool_call(&mut self, call: &ToolCall, result_summary: &str) {
        self.tool_history.push(format!(
            "{}: {}",
            call.tool.as_str(),
            result_summary
        ));
        self.budget.iterations_used += 1;
    }

    pub fn stop(&mut self, reason: &str) {
        self.stopped = true;
        self.stop_reason = Some(reason.to_string());
    }

    pub fn save_checkpoint(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialise campaign state: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("failed to write checkpoint: {e}"))?;
        Ok(())
    }

    pub fn load_checkpoint(path: &Path) -> Result<Self, String> {
        let json =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read checkpoint: {e}"))?;
        serde_json::from_str(&json).map_err(|e| format!("failed to parse checkpoint: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn allowlist_rejects_unknown_tool() {
        let registry = ToolRegistry::new(vec![ToolName::AstScan]);
        let bad = ToolCall {
            tool: ToolName::RunFuzz,
            arguments_json: "{}".to_string(),
        };
        assert!(registry.check(&bad).is_err());
        let good = ToolCall {
            tool: ToolName::AstScan,
            arguments_json: "{}".to_string(),
        };
        assert!(registry.check(&good).is_ok());
    }

    #[test]
    fn budget_stops_loop() {
        let mut budget = Budget::new(2, Some(100));
        assert!(!budget.exhausted());
        budget.iterations_used = 2;
        assert!(budget.exhausted());
    }

    #[test]
    fn checkpoint_round_trip() {
        let mut state = CampaignState::new(
            "cJSON",
            FreedomMode::Assisted,
            Budget::new(100, None),
        );
        state.plan.push("map attack surface".to_string());
        state.hypotheses.push(Hypothesis::new(
            "cJSON_Parse heap overflow on long input",
            Some("cJSON_Parse"),
        ));
        let file = NamedTempFile::new().unwrap();
        state.save_checkpoint(file.path()).unwrap();
        let loaded = CampaignState::load_checkpoint(file.path()).unwrap();
        assert_eq!(loaded.campaign_id, state.campaign_id);
        assert_eq!(loaded.target, "cJSON");
        assert_eq!(loaded.plan.len(), 1);
        assert_eq!(loaded.hypotheses.len(), 1);
        assert_eq!(loaded.freedom, FreedomMode::Assisted);
    }
}
