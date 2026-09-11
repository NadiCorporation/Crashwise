"use client";

import { useState } from "react";

interface CampaignLauncherProps {
  onNavigateToLive?: () => void;
}

interface Preset {
  label: string;
  repo: string;
  name: string;
  subdir?: string;
  fuzzer: "libfuzzer" | "afl++";
}

const PRESETS: Preset[] = [
  {
    label: "cJSON (C / CMake)",
    repo: "https://github.com/DaveGamble/cJSON",
    name: "cJSON",
    fuzzer: "libfuzzer",
  },
  {
    label: "re2 (C++ / CMake)",
    repo: "https://github.com/google/re2",
    name: "re2",
    fuzzer: "libfuzzer",
  },
  {
    label: "libevent (C / CMake)",
    repo: "https://github.com/libevent/libevent",
    name: "libevent",
    fuzzer: "libfuzzer",
  },
  {
    label: "googletest (Monorepo Subdir)",
    repo: "https://github.com/google/googletest",
    name: "googletest",
    subdir: "googletest",
    fuzzer: "libfuzzer",
  },
];

export function CampaignLauncher({ onNavigateToLive }: CampaignLauncherProps) {
  // Form State
  const [targetRepo, setTargetRepo] = useState("");
  const [targetName, setTargetName] = useState("");
  const [targetSubdir, setTargetSubdir] = useState("");
  const [targetBranch, setTargetBranch] = useState("");
  const [targetCloneDepth, setTargetCloneDepth] = useState<number>(1);
  const [fuzzerType, setFuzzerType] = useState<"libfuzzer" | "afl++">("libfuzzer");
  const [sanitizers, setSanitizers] = useState("address,undefined");
  const [timeoutSeconds, setTimeoutSeconds] = useState<number>(600);
  const [maxIterations, setMaxIterations] = useState<number>(5);
  const [customFuzzerFlags, setCustomFuzzerFlags] = useState("");

  // LLM State
  const [showLlmOptions, setShowLlmOptions] = useState(false);
  const [llmModel, setLlmModel] = useState("");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [llmBaseUrl, setLlmBaseUrl] = useState("");
  const [llmTemperature, setLlmTemperature] = useState<number>(0.0);
  const [reasoningEffort, setReasoningEffort] = useState<string>("");
  const [maxSynthRetries, setMaxSynthRetries] = useState<number>(4);

  // Advanced State
  const [enableSelfHealing, setEnableSelfHealing] = useState(false);
  const [healingMaxAttempts, setHealingMaxAttempts] = useState<number>(10);
  const [enableMab, setEnableMab] = useState(false);
  const [mabAlgorithm, setMabAlgorithm] = useState<string>("thompson");
  const [mabExplorationRatio, setMabExplorationRatio] = useState<number>(0.2);

  // UI State
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [successResult, setSuccessResult] = useState<{ campaignId: string; workflowId: string } | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const applyPreset = (preset: Preset) => {
    setTargetRepo(preset.repo);
    setTargetName(preset.name);
    setTargetSubdir(preset.subdir || "");
    setFuzzerType(preset.fuzzer);
    setErrors({});
    setSuccessResult(null);
    setErrorMessage(null);
  };

  const validate = (): boolean => {
    const errs: Record<string, string> = {};
    if (!targetRepo.trim()) {
      errs.targetRepo = "Target repository URL or path is required.";
    }
    if (!targetName.trim()) {
      errs.targetName = "Target name is required.";
    } else if (!/^[a-zA-Z0-9_-]+$/.test(targetName.trim())) {
      errs.targetName = "Target name must contain only letters, numbers, hyphens, or underscores.";
    }
    if (timeoutSeconds < 10 || timeoutSeconds > 86400) {
      errs.timeoutSeconds = "Timeout must be between 10 and 86400 seconds.";
    }
    if (maxIterations < 1 || maxIterations > 20) {
      errs.maxIterations = "Max iterations must be between 1 and 20.";
    }
    if (targetCloneDepth < 0) {
      errs.targetCloneDepth = "Clone depth must be >= 0 (0 for full clone).";
    }
    if (llmTemperature < 0 || llmTemperature > 2.0) {
      errs.llmTemperature = "Temperature must be between 0.0 and 2.0.";
    }
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSuccessResult(null);
    setErrorMessage(null);

    if (!validate()) return;

    setSubmitting(true);
    try {
      const payload: Record<string, any> = {
        target_repo: targetRepo.trim(),
        target_name: targetName.trim(),
        target_subdir: targetSubdir.trim() ? targetSubdir.trim() : null,
        target_branch: targetBranch.trim() ? targetBranch.trim() : null,
        target_clone_depth: targetCloneDepth,
        fuzzer_type: fuzzerType,
        sanitizers: sanitizers.trim(),
        timeout_seconds: timeoutSeconds,
        max_iterations: maxIterations,
        custom_fuzzer_flags: customFuzzerFlags.trim() ? customFuzzerFlags.trim() : null,
        enable_self_healing: enableSelfHealing,
        healing_max_attempts: healingMaxAttempts,
        enable_mab: enableMab,
        mab_algorithm: mabAlgorithm,
        mab_exploration_ratio: mabExplorationRatio,
        max_synth_retries: maxSynthRetries,
      };

      if (llmModel.trim()) payload.llm_model = llmModel.trim();
      if (llmApiKey.trim()) payload.llm_api_key = llmApiKey.trim();
      if (llmBaseUrl.trim()) payload.llm_base_url = llmBaseUrl.trim();
      if (llmTemperature !== undefined && llmTemperature !== null) payload.llm_temperature = llmTemperature;
      if (reasoningEffort.trim()) payload.reasoning_effort = reasoningEffort.trim();

      const response = await fetch("/campaigns/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (response.ok || response.status === 202) {
        const data = await response.json();
        setSuccessResult({
          campaignId: data.campaign_id,
          workflowId: data.workflow_id,
        });
      } else {
        const errText = await response.text();
        setErrorMessage(`Server Error (${response.status}): ${errText}`);
      }
    } catch (err: any) {
      setErrorMessage(`Network / Dispatch Error: ${err.message || err}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Presets */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-lg font-bold text-foreground">🚀 Launch New Fuzzing Campaign</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Configure target source, fuzzing engine, sanitizers, and AI synthesis parameters.
          </p>
        </div>

        {/* Quick Presets */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] text-muted-foreground font-medium mr-1">Presets:</span>
          {PRESETS.map((p) => (
            <button
              key={p.name}
              type="button"
              onClick={() => applyPreset(p)}
              className="px-2.5 py-1 text-[11px] bg-muted hover:bg-muted/80 text-foreground border border-border rounded transition font-mono"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Success Alert */}
      {successResult && (
        <div className="p-4 border border-accent-green/40 bg-accent-green/10 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse" />
              <h3 className="text-xs font-bold text-accent-green uppercase tracking-wider">
                ✓ Campaign Dispatched Successfully
              </h3>
            </div>
            {onNavigateToLive && (
              <button
                type="button"
                onClick={onNavigateToLive}
                className="px-3 py-1 bg-accent-green text-background text-xs font-bold rounded hover:opacity-90 transition shadow-sm"
              >
                View in Live Tab →
              </button>
            )}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono pt-1 text-foreground">
            <div>
              <span className="text-muted-foreground">Campaign ID:</span> {successResult.campaignId}
            </div>
            <div>
              <span className="text-muted-foreground">Workflow ID:</span> {successResult.workflowId}
            </div>
          </div>
        </div>
      )}

      {/* Error Alert */}
      {errorMessage && (
        <div className="p-4 border border-accent-red/40 bg-accent-red/10 rounded-lg text-xs text-accent-red space-y-1">
          <div className="font-bold">⚠ Campaign Dispatch Failed</div>
          <div className="font-mono">{errorMessage}</div>
        </div>
      )}

      {/* Main Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Section 1: Target Definition */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            1. Target Repository & Structure
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Target Repository URL or Path <span className="text-accent-red">*</span>
              </label>
              <input
                type="text"
                value={targetRepo}
                onChange={(e) => setTargetRepo(e.target.value)}
                placeholder="https://github.com/org/repo or /path/to/source"
                className={`w-full px-3 py-2 text-xs font-mono bg-background border ${
                  errors.targetRepo ? "border-accent-red" : "border-border"
                } rounded focus:outline-none focus:border-accent-green text-foreground`}
              />
              {errors.targetRepo && (
                <p className="text-[11px] text-accent-red mt-1">{errors.targetRepo}</p>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Target Name <span className="text-accent-red">*</span>
              </label>
              <input
                type="text"
                value={targetName}
                onChange={(e) => setTargetName(e.target.value)}
                placeholder="e.g. cJSON, re2, libevent"
                className={`w-full px-3 py-2 text-xs font-mono bg-background border ${
                  errors.targetName ? "border-accent-red" : "border-border"
                } rounded focus:outline-none focus:border-accent-green text-foreground`}
              />
              {errors.targetName && (
                <p className="text-[11px] text-accent-red mt-1">{errors.targetName}</p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Monorepo Subdirectory <span className="text-muted-foreground text-[10px]">(optional)</span>
              </label>
              <input
                type="text"
                value={targetSubdir}
                onChange={(e) => setTargetSubdir(e.target.value)}
                placeholder="e.g. lib/zlib or googletest"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Git Branch <span className="text-muted-foreground text-[10px]">(optional)</span>
              </label>
              <input
                type="text"
                value={targetBranch}
                onChange={(e) => setTargetBranch(e.target.value)}
                placeholder="main, master, v1.2.0"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Clone Depth <span className="text-muted-foreground text-[10px]">(0 for full history)</span>
              </label>
              <input
                type="number"
                min={0}
                value={targetCloneDepth}
                onChange={(e) => setTargetCloneDepth(parseInt(e.target.value) || 0)}
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>
          </div>
        </div>

        {/* Section 2: Fuzzing Engine & Execution */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            2. Fuzzing Engine & Execution Limits
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Fuzzing Engine</label>
              <select
                value={fuzzerType}
                onChange={(e) => setFuzzerType(e.target.value as "libfuzzer" | "afl++")}
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              >
                <option value="libfuzzer">libFuzzer (In-process, coverage-guided)</option>
                <option value="afl++">AFL++ (Feedback-driven mutator)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Sanitizers</label>
              <input
                type="text"
                value={sanitizers}
                onChange={(e) => setSanitizers(e.target.value)}
                placeholder="address,undefined"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Timeout per Run (sec)
              </label>
              <input
                type="number"
                min={10}
                max={86400}
                value={timeoutSeconds}
                onChange={(e) => setTimeoutSeconds(parseInt(e.target.value) || 600)}
                className={`w-full px-3 py-2 text-xs font-mono bg-background border ${
                  errors.timeoutSeconds ? "border-accent-red" : "border-border"
                } rounded focus:outline-none focus:border-accent-green text-foreground`}
              />
              {errors.timeoutSeconds && (
                <p className="text-[11px] text-accent-red mt-1">{errors.timeoutSeconds}</p>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Max Iterations</label>
              <input
                type="number"
                min={1}
                max={20}
                value={maxIterations}
                onChange={(e) => setMaxIterations(parseInt(e.target.value) || 5)}
                className={`w-full px-3 py-2 text-xs font-mono bg-background border ${
                  errors.maxIterations ? "border-accent-red" : "border-border"
                } rounded focus:outline-none focus:border-accent-green text-foreground`}
              />
              {errors.maxIterations && (
                <p className="text-[11px] text-accent-red mt-1">{errors.maxIterations}</p>
              )}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-foreground mb-1">
              Custom Fuzzer Flags <span className="text-muted-foreground text-[10px]">(optional)</span>
            </label>
            <input
              type="text"
              value={customFuzzerFlags}
              onChange={(e) => setCustomFuzzerFlags(e.target.value)}
              placeholder="-rss_limit_mb=4096 -dict=target.dict"
              className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
            />
          </div>
        </div>

        {/* Section 3: AI Model & Synthesis Settings (Collapsible) */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <div className="flex items-center justify-between cursor-pointer" onClick={() => setShowLlmOptions(!showLlmOptions)}>
            <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
              <span>3. AI Harness Synthesizer & Reasoning</span>
              <span className="text-[10px] text-accent-blue font-mono">
                {showLlmOptions ? "▲ Hide" : "▼ Show Options"}
              </span>
            </h3>
            <span className="text-xs text-muted-foreground">
              {llmModel ? `Model: ${llmModel}` : "Using System Default"}
            </span>
          </div>

          {showLlmOptions && (
            <div className="pt-2 border-t border-border space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">LLM Model Override</label>
                  <input
                    type="text"
                    value={llmModel}
                    onChange={(e) => setLlmModel(e.target.value)}
                    placeholder="claude-sonnet-4-5, gpt-4o, deepseek-chat"
                    className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">API Key Override</label>
                  <div className="relative">
                    <input
                      type={showApiKey ? "text" : "password"}
                      value={llmApiKey}
                      onChange={(e) => setLlmApiKey(e.target.value)}
                      placeholder="sk-..."
                      className="w-full px-3 py-2 pr-14 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                    />
                    <button
                      type="button"
                      onClick={() => setShowApiKey(!showApiKey)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground hover:text-foreground font-mono"
                    >
                      {showApiKey ? "Hide" : "Show"}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Base URL Override</label>
                  <input
                    type="text"
                    value={llmBaseUrl}
                    onChange={(e) => setLlmBaseUrl(e.target.value)}
                    placeholder="https://api.openai.com/v1"
                    className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Temperature (0.0 - 2.0)</label>
                  <input
                    type="number"
                    step={0.1}
                    min={0.0}
                    max={2.0}
                    value={llmTemperature}
                    onChange={(e) => setLlmTemperature(parseFloat(e.target.value) || 0.0)}
                    className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Reasoning Effort</label>
                  <select
                    value={reasoningEffort}
                    onChange={(e) => setReasoningEffort(e.target.value)}
                    className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                  >
                    <option value="">Default (Provider Managed)</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-foreground mb-1">Max Synth Retries</label>
                  <input
                    type="number"
                    min={0}
                    max={10}
                    value={maxSynthRetries}
                    onChange={(e) => setMaxSynthRetries(parseInt(e.target.value) || 4)}
                    className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Section 4: Autonomous Self-Healing & Multi-Armed Bandit */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            4. Autonomous Feedback & Optimization
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Self-Healing */}
            <div className="space-y-3 p-3 border border-border/60 rounded-md bg-background/50">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-foreground flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableSelfHealing}
                    onChange={(e) => setEnableSelfHealing(e.target.checked)}
                    className="rounded border-border text-accent-green focus:ring-accent-green"
                  />
                  <span>Self-Healing Engine (LangGraph)</span>
                </label>
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                  enableSelfHealing ? "bg-accent-green/20 text-accent-green" : "bg-muted text-muted-foreground"
                }`}>
                  {enableSelfHealing ? "ENABLED" : "OFF"}
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Automatically diagnose compilation and linker errors, modifying headers and linker flags in sandbox.
              </p>
              {enableSelfHealing && (
                <div>
                  <label className="block text-[11px] text-muted-foreground mb-1">Max Healing Attempts</label>
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={healingMaxAttempts}
                    onChange={(e) => setHealingMaxAttempts(parseInt(e.target.value) || 10)}
                    className="w-full px-2.5 py-1.5 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                  />
                </div>
              )}
            </div>

            {/* MAB Strategist */}
            <div className="space-y-3 p-3 border border-border/60 rounded-md bg-background/50">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-foreground flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableMab}
                    onChange={(e) => setEnableMab(e.target.checked)}
                    className="rounded border-border text-accent-blue focus:ring-accent-blue"
                  />
                  <span>Multi-Armed Bandit (MAB) Evolution</span>
                </label>
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                  enableMab ? "bg-accent-blue/20 text-accent-blue" : "bg-muted text-muted-foreground"
                }`}>
                  {enableMab ? "ENABLED" : "OFF"}
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Balance exploration and exploitation across coverage barrier bypasses and mutation strategies.
              </p>
              {enableMab && (
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[11px] text-muted-foreground mb-1">Algorithm</label>
                    <select
                      value={mabAlgorithm}
                      onChange={(e) => setMabAlgorithm(e.target.value)}
                      className="w-full px-2.5 py-1.5 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-blue text-foreground"
                    >
                      <option value="thompson">Thompson Sampling</option>
                      <option value="ucb1">UCB1</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] text-muted-foreground mb-1">Exploration Ratio</label>
                    <input
                      type="number"
                      step={0.05}
                      min={0.0}
                      max={1.0}
                      value={mabExplorationRatio}
                      onChange={(e) => setMabExplorationRatio(parseFloat(e.target.value) || 0.2)}
                      className="w-full px-2.5 py-1.5 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-blue text-foreground"
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Submit Bar */}
        <div className="flex items-center justify-between pt-4 border-t border-border">
          <div className="text-xs text-muted-foreground font-mono">
            {targetName ? `Target: ${targetName} (${fuzzerType})` : "Configure parameters above"}
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="px-6 py-2.5 bg-accent-green hover:bg-accent-green/90 text-background font-bold text-xs uppercase tracking-wider rounded transition disabled:opacity-50 flex items-center gap-2 shadow"
          >
            {submitting ? (
              <>
                <span className="w-3 h-3 border-2 border-background border-t-transparent rounded-full animate-spin" />
                <span>Launching Campaign…</span>
              </>
            ) : (
              <span>🚀 Start Fuzzing Campaign</span>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
