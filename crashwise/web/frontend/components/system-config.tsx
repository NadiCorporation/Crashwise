"use client";

import { useEffect, useState } from "react";

interface SystemConfigData {
  temporal_host?: string;
  temporal_namespace?: string;
  temporal_task_queue?: string;
  crashwise_api_port?: number;
  crashwise_api_url?: string;
  database_url?: string;
  redis_url?: string;
  redis_enabled?: boolean;
  worker_name?: string;
  crashwise_env?: string;
  log_level?: string;
  crashwise_llm_model?: string;
  crashwise_llm_temperature?: number;
  crashwise_llm_max_tokens?: number;
  crashwise_llm_reasoning_effort?: string;
  openai_api_base?: string;
  ai_provider?: string;
  ai_model?: string;
  ollama_url?: string;
  docker_disk_quota?: string;
  notifications_enabled?: boolean;
  webhook_url?: string;
  webhook_format?: string;
  min_cvss_threshold?: number;
  crashwise_workdir?: string;
  crashwise_build_timeout?: number;
  has_openai_api_key?: boolean;
  has_anthropic_api_key?: boolean;
  has_google_api_key?: boolean;
  has_ai_api_key?: boolean;
  openai_api_key_masked?: string | null;
  anthropic_api_key_masked?: string | null;
  google_api_key_masked?: string | null;
  ai_api_key_masked?: string | null;
}

export function SystemConfig() {
  const [config, setConfig] = useState<SystemConfigData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [restartBanner, setRestartBanner] = useState<string | null>(null);

  // Form values
  const [temporalHost, setTemporalHost] = useState("");
  const [temporalNamespace, setTemporalNamespace] = useState("");
  const [temporalTaskQueue, setTemporalTaskQueue] = useState("");
  const [apiPort, setApiPort] = useState<number>(8000);
  const [databaseUrl, setDatabaseUrl] = useState("");
  const [redisUrl, setRedisUrl] = useState("");
  const [redisEnabled, setRedisEnabled] = useState(false);
  const [workerName, setWorkerName] = useState("");
  const [crashwiseEnv, setCrashwiseEnv] = useState("development");
  const [logLevel, setLogLevel] = useState("INFO");
  const [workdir, setWorkdir] = useState("/tmp/crashwise");
  const [buildTimeout, setBuildTimeout] = useState<number>(900);
  const [diskQuota, setDiskQuota] = useState("5G");

  // AI / LLM
  const [llmModel, setLlmModel] = useState("");
  const [llmTemperature, setLlmTemperature] = useState<number>(0.0);
  const [llmMaxTokens, setLlmMaxTokens] = useState<number>(4096);
  const [llmReasoningEffort, setLlmReasoningEffort] = useState("");
  const [openaiBaseUrl, setOpenaiBaseUrl] = useState("");
  const [aiProvider, setAiProvider] = useState("");
  const [aiModel, setAiModel] = useState("");
  const [ollamaUrl, setOllamaUrl] = useState("");

  // Secret API Keys
  const [openaiKey, setOpenaiKey] = useState("");
  const [showOpenaiKey, setShowOpenaiKey] = useState(false);
  const [anthropicKey, setAnthropicKey] = useState("");
  const [showAnthropicKey, setShowAnthropicKey] = useState(false);
  const [googleKey, setGoogleKey] = useState("");
  const [showGoogleKey, setShowGoogleKey] = useState(false);
  const [aiKey, setAiKey] = useState("");
  const [showAiKey, setShowAiKey] = useState(false);

  // Notifications
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookFormat, setWebhookFormat] = useState("slack");
  const [minCvssThreshold, setMinCvssThreshold] = useState<number>(7.0);

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const resp = await fetch("/api/config");
      if (resp.ok) {
        const data: SystemConfigData = await resp.json();
        setConfig(data);

        // Populate fields
        setTemporalHost(data.temporal_host || "localhost:7233");
        setTemporalNamespace(data.temporal_namespace || "default");
        setTemporalTaskQueue(data.temporal_task_queue || "crashwise");
        setApiPort(data.crashwise_api_port || 8000);
        setDatabaseUrl(data.database_url || "sqlite+aiosqlite:///./crashwise.db");
        setRedisUrl(data.redis_url || "redis://localhost:6379/0");
        setRedisEnabled(Boolean(data.redis_enabled));
        setWorkerName(data.worker_name || "crashwise-worker-0");
        setCrashwiseEnv(data.crashwise_env || "development");
        setLogLevel(data.log_level || "INFO");
        setWorkdir(data.crashwise_workdir || "/tmp/crashwise");
        setBuildTimeout(data.crashwise_build_timeout || 900);
        setDiskQuota(data.docker_disk_quota || "5G");

        setLlmModel(data.crashwise_llm_model || "claude-sonnet-4-5");
        setLlmTemperature(data.crashwise_llm_temperature ?? 0.0);
        setLlmMaxTokens(data.crashwise_llm_max_tokens || 4096);
        setLlmReasoningEffort(data.crashwise_llm_reasoning_effort || "");
        setOpenaiBaseUrl(data.openai_api_base || "");
        setAiProvider(data.ai_provider || "");
        setAiModel(data.ai_model || "");
        setOllamaUrl(data.ollama_url || "http://localhost:11434");

        setNotificationsEnabled(Boolean(data.notifications_enabled));
        setWebhookUrl(data.webhook_url || "");
        setWebhookFormat(data.webhook_format || "slack");
        setMinCvssThreshold(data.min_cvss_threshold ?? 7.0);
      }
    } catch (e) {
      setSaveError(`Failed to load system config: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveSuccess(null);
    setSaveError(null);
    setRestartBanner(null);

    const payload: Record<string, any> = {
      temporal_host: temporalHost.trim(),
      temporal_namespace: temporalNamespace.trim(),
      temporal_task_queue: temporalTaskQueue.trim(),
      crashwise_api_port: apiPort,
      database_url: databaseUrl.trim(),
      redis_url: redisUrl.trim(),
      redis_enabled: redisEnabled,
      worker_name: workerName.trim(),
      crashwise_env: crashwiseEnv.trim(),
      log_level: logLevel.trim(),
      crashwise_workdir: workdir.trim(),
      crashwise_build_timeout: buildTimeout,
      docker_disk_quota: diskQuota.trim(),

      crashwise_llm_model: llmModel.trim(),
      crashwise_llm_temperature: llmTemperature,
      crashwise_llm_max_tokens: llmMaxTokens,
      crashwise_llm_reasoning_effort: llmReasoningEffort.trim() ? llmReasoningEffort.trim() : null,
      openai_api_base: openaiBaseUrl.trim() ? openaiBaseUrl.trim() : null,
      ai_provider: aiProvider.trim() ? aiProvider.trim() : null,
      ai_model: aiModel.trim() ? aiModel.trim() : null,
      ollama_url: ollamaUrl.trim() ? ollamaUrl.trim() : null,

      notifications_enabled: notificationsEnabled,
      webhook_url: webhookUrl.trim() ? webhookUrl.trim() : null,
      webhook_format: webhookFormat.trim(),
      min_cvss_threshold: minCvssThreshold,
    };

    // Only send secret keys if updated
    if (openaiKey.trim()) payload.openai_api_key = openaiKey.trim();
    if (anthropicKey.trim()) payload.anthropic_api_key = anthropicKey.trim();
    if (googleKey.trim()) payload.google_api_key = googleKey.trim();
    if (aiKey.trim()) payload.ai_api_key = aiKey.trim();

    try {
      const resp = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (resp.ok) {
        const resData = await resp.json();
        setSaveSuccess(`Configuration saved! Updated ${resData.updated_keys?.length || 0} variables in .env.`);
        if (resData.restart_required) {
          setRestartBanner(resData.message || "Restart Required: Changes written to .env. Please restart Crashwise services for changes to take effect.");
        }
        // Refresh masked data
        fetchConfig();
        // Clear input secrets
        setOpenaiKey("");
        setAnthropicKey("");
        setGoogleKey("");
        setAiKey("");
      } else {
        const errText = await resp.text();
        setSaveError(`Save Failed (${resp.status}): ${errText}`);
      }
    } catch (e: any) {
      setSaveError(`Network error while saving config: ${e.message || e}`);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="border border-border rounded-lg p-8 text-center text-muted-foreground text-xs">
        Loading system configuration from backend…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-lg font-bold text-foreground">⚙️ System Configuration (.env Editor)</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Modify cluster orchestrator settings, database connections, and AI provider credentials.
          </p>
        </div>
        <button
          type="button"
          onClick={fetchConfig}
          className="px-3 py-1.5 bg-muted hover:bg-muted/80 text-foreground border border-border text-xs rounded transition"
        >
          ↻ Reload Configuration
        </button>
      </div>

      {/* Restart Required Banner */}
      {restartBanner && (
        <div className="p-4 border border-accent-orange/50 bg-accent-orange/10 rounded-lg space-y-1 text-accent-orange">
          <div className="flex items-center gap-2 font-bold text-xs">
            <span>⚠</span>
            <span>RESTART REQUIRED</span>
          </div>
          <p className="text-xs font-mono">{restartBanner}</p>
        </div>
      )}

      {/* Save Success Banner */}
      {saveSuccess && (
        <div className="p-3 border border-accent-green/40 bg-accent-green/10 rounded-lg text-xs text-accent-green font-mono">
          ✓ {saveSuccess}
        </div>
      )}

      {/* Save Error Banner */}
      {saveError && (
        <div className="p-3 border border-accent-red/40 bg-accent-red/10 rounded-lg text-xs text-accent-red font-mono">
          ✗ {saveError}
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* Section 1: Infrastructure & Environment */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            1. Core Infrastructure & Orchestration
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Temporal Host</label>
              <input
                type="text"
                value={temporalHost}
                onChange={(e) => setTemporalHost(e.target.value)}
                placeholder="localhost:7233"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Temporal Task Queue</label>
              <input
                type="text"
                value={temporalTaskQueue}
                onChange={(e) => setTemporalTaskQueue(e.target.value)}
                placeholder="crashwise"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Temporal Namespace</label>
              <input
                type="text"
                value={temporalNamespace}
                onChange={(e) => setTemporalNamespace(e.target.value)}
                placeholder="default"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">CrashWise API Port</label>
              <input
                type="number"
                value={apiPort}
                onChange={(e) => setApiPort(parseInt(e.target.value) || 8000)}
                placeholder="8000"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Worker Replica Name</label>
              <input
                type="text"
                value={workerName}
                onChange={(e) => setWorkerName(e.target.value)}
                placeholder="crashwise-worker-0"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Environment / Log Level</label>
              <div className="grid grid-cols-2 gap-2">
                <input
                  type="text"
                  value={crashwiseEnv}
                  onChange={(e) => setCrashwiseEnv(e.target.value)}
                  placeholder="development"
                  className="w-full px-2 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                />
                <select
                  value={logLevel}
                  onChange={(e) => setLogLevel(e.target.value)}
                  className="w-full px-2 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                >
                  <option value="DEBUG">DEBUG</option>
                  <option value="INFO">INFO</option>
                  <option value="WARNING">WARNING</option>
                  <option value="ERROR">ERROR</option>
                </select>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Database URL (Async SQLAlchemy)</label>
              <input
                type="text"
                value={databaseUrl}
                onChange={(e) => setDatabaseUrl(e.target.value)}
                placeholder="sqlite+aiosqlite:///./crashwise.db"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Redis URL <span className="text-[10px] text-muted-foreground">(State / Heartbeats)</span>
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={redisUrl}
                  onChange={(e) => setRedisUrl(e.target.value)}
                  placeholder="redis://localhost:6379/0"
                  className="flex-1 px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                />
                <label className="flex items-center gap-1.5 px-3 py-2 border border-border rounded text-xs bg-background cursor-pointer">
                  <input
                    type="checkbox"
                    checked={redisEnabled}
                    onChange={(e) => setRedisEnabled(e.target.checked)}
                    className="rounded border-border text-accent-green focus:ring-accent-green"
                  />
                  <span>Enable</span>
                </label>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Workdir Root (CRASHWISE_WORKDIR)
              </label>
              <input
                type="text"
                value={workdir}
                onChange={(e) => setWorkdir(e.target.value)}
                placeholder="/tmp/crashwise"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Build Timeout (sec)
              </label>
              <input
                type="number"
                min={30}
                value={buildTimeout}
                onChange={(e) => setBuildTimeout(parseInt(e.target.value) || 900)}
                placeholder="900"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Docker Container Disk Quota
              </label>
              <input
                type="text"
                value={diskQuota}
                onChange={(e) => setDiskQuota(e.target.value)}
                placeholder="5G"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>
          </div>
        </div>

        {/* Section 2: AI & LLM Inference */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            2. AI & Large Language Model Engines
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Primary LLM Model</label>
              <input
                type="text"
                value={llmModel}
                onChange={(e) => setLlmModel(e.target.value)}
                placeholder="claude-sonnet-4-5, gpt-4o, deepseek-chat"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Temperature</label>
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
              <label className="block text-xs font-medium text-foreground mb-1">Max Output Tokens</label>
              <input
                type="number"
                min={256}
                max={131072}
                value={llmMaxTokens}
                onChange={(e) => setLlmMaxTokens(parseInt(e.target.value) || 4096)}
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Custom OpenAI Base URL</label>
              <input
                type="text"
                value={openaiBaseUrl}
                onChange={(e) => setOpenaiBaseUrl(e.target.value)}
                placeholder="https://api.deepseek.com or http://localhost:11434/v1"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Local / Cloud AI Provider</label>
              <input
                type="text"
                value={aiProvider}
                onChange={(e) => setAiProvider(e.target.value)}
                placeholder="ollama, venice, openai_compatible"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Ollama Base URL</label>
              <input
                type="text"
                value={ollamaUrl}
                onChange={(e) => setOllamaUrl(e.target.value)}
                placeholder="http://localhost:11434"
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>
          </div>
        </div>

        {/* Section 3: Sensitive API Keys */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              3. Secret API Keys & Cloud Credentials
            </h3>
            <span className="text-[11px] text-muted-foreground">
              Leave blank to keep existing keys.
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* OpenAI */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-foreground">OpenAI API Key</label>
                <span className="text-[10px] font-mono text-muted-foreground">
                  {config?.has_openai_api_key ? `Configured (${config.openai_api_key_masked})` : "Not set"}
                </span>
              </div>
              <div className="relative">
                <input
                  type={showOpenaiKey ? "text" : "password"}
                  value={openaiKey}
                  onChange={(e) => setOpenaiKey(e.target.value)}
                  placeholder={config?.has_openai_api_key ? "•••••••••••••••• (Leave blank to keep)" : "sk-..."}
                  className="w-full px-3 py-2 pr-14 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                />
                <button
                  type="button"
                  onClick={() => setShowOpenaiKey(!showOpenaiKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground hover:text-foreground font-mono"
                >
                  {showOpenaiKey ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            {/* Anthropic */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-foreground">Anthropic API Key</label>
                <span className="text-[10px] font-mono text-muted-foreground">
                  {config?.has_anthropic_api_key ? `Configured (${config.anthropic_api_key_masked})` : "Not set"}
                </span>
              </div>
              <div className="relative">
                <input
                  type={showAnthropicKey ? "text" : "password"}
                  value={anthropicKey}
                  onChange={(e) => setAnthropicKey(e.target.value)}
                  placeholder={config?.has_anthropic_api_key ? "•••••••••••••••• (Leave blank to keep)" : "sk-ant-..."}
                  className="w-full px-3 py-2 pr-14 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                />
                <button
                  type="button"
                  onClick={() => setShowAnthropicKey(!showAnthropicKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground hover:text-foreground font-mono"
                >
                  {showAnthropicKey ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            {/* Google */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-foreground">Google Gemini API Key</label>
                <span className="text-[10px] font-mono text-muted-foreground">
                  {config?.has_google_api_key ? `Configured (${config.google_api_key_masked})` : "Not set"}
                </span>
              </div>
              <div className="relative">
                <input
                  type={showGoogleKey ? "text" : "password"}
                  value={googleKey}
                  onChange={(e) => setGoogleKey(e.target.value)}
                  placeholder={config?.has_google_api_key ? "•••••••••••••••• (Leave blank to keep)" : "AIza..."}
                  className="w-full px-3 py-2 pr-14 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                />
                <button
                  type="button"
                  onClick={() => setShowGoogleKey(!showGoogleKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground hover:text-foreground font-mono"
                >
                  {showGoogleKey ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            {/* General AI API Key */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-foreground">Custom AI / Venice API Key</label>
                <span className="text-[10px] font-mono text-muted-foreground">
                  {config?.has_ai_api_key ? `Configured (${config.ai_api_key_masked})` : "Not set"}
                </span>
              </div>
              <div className="relative">
                <input
                  type={showAiKey ? "text" : "password"}
                  value={aiKey}
                  onChange={(e) => setAiKey(e.target.value)}
                  placeholder={config?.has_ai_api_key ? "•••••••••••••••• (Leave blank to keep)" : "Key string"}
                  className="w-full px-3 py-2 pr-14 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
                />
                <button
                  type="button"
                  onClick={() => setShowAiKey(!showAiKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground hover:text-foreground font-mono"
                >
                  {showAiKey ? "Hide" : "Show"}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Section 4: Notifications & Alerts */}
        <div className="border border-border rounded-lg p-4 bg-muted/20 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
            4. Notifications & Incident Webhooks
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Enable Notifications</label>
              <label className="flex items-center gap-2 p-2 bg-background border border-border rounded cursor-pointer">
                <input
                  type="checkbox"
                  checked={notificationsEnabled}
                  onChange={(e) => setNotificationsEnabled(e.target.checked)}
                  className="rounded border-border text-accent-green focus:ring-accent-green"
                />
                <span className="text-xs text-foreground font-medium">Send webhook alerts on critical crashes</span>
              </label>
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Webhook URL</label>
              <input
                type="text"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full px-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Minimum CVSS Severity Alert</label>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min="0.0"
                  max="10.0"
                  step="0.5"
                  value={minCvssThreshold}
                  onChange={(e) => setMinCvssThreshold(parseFloat(e.target.value) || 7.0)}
                  className="flex-1 accent-accent-red"
                />
                <span className="text-xs font-mono font-bold px-2 py-1 bg-background border border-border rounded text-accent-red">
                  {minCvssThreshold.toFixed(1)}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Save Bar */}
        <div className="flex items-center justify-between pt-4 border-t border-border">
          <div className="text-xs text-muted-foreground font-mono">
            Writes to <code className="text-accent-blue font-bold">.env</code> in project root
          </div>

          <button
            type="submit"
            disabled={saving}
            className="px-6 py-2.5 bg-accent-green hover:bg-accent-green/90 text-background font-bold text-xs uppercase tracking-wider rounded transition disabled:opacity-50 flex items-center gap-2 shadow"
          >
            {saving ? (
              <>
                <span className="w-3 h-3 border-2 border-background border-t-transparent rounded-full animate-spin" />
                <span>Saving Configuration…</span>
              </>
            ) : (
              <span>💾 Save Configuration</span>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
