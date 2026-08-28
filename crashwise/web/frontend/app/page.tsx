"use client";

import { useEffect, useState, useCallback } from "react";
import { CampaignsTable } from "@/components/campaigns-table";
import { LiveTelemetry } from "@/components/telemetry";
import { CrashMatrix } from "@/components/crash-matrix";
import { CampaignLauncher } from "@/components/campaign-launcher";
import { SystemConfig } from "@/components/system-config";
import { WorkerStatus } from "@/components/worker-status";
import { LogStreamer } from "@/components/log-streamer";

interface Campaign {
  id: string;
  target_name: string;
  status: string;
  run_count: number;
}

type TabType = "live" | "crashes" | "control" | "launcher" | "config" | "workers" | "logs";

export default function DashboardPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [activeTab, setActiveTab] = useState<TabType>("live");
  const [signalResult, setSignalResult] = useState<string>("");

  const refresh = useCallback(() => {
    fetch("/campaigns")
      .then((r) => (r.ok ? r.json() : []))
      .then(setCampaigns)
      .catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 2000);
    return () => clearInterval(interval);
  }, [refresh]);

  const running = campaigns.filter((c) => c.status === "running");

  const sendSignal = async (workflowId: string, signal: string, payload?: unknown) => {
    setSignalResult("Sending...");
    try {
      const resp = await fetch(`/campaigns/signal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ workflow_id: workflowId, signal, payload }),
      });
      if (resp.ok) {
        setSignalResult(`✓ ${signal} sent`);
      } else {
        setSignalResult(`✗ ${resp.status}: ${await resp.text()}`);
      }
    } catch (e) {
      setSignalResult(`✗ ${e}`);
    }
  };

  const tabs: { id: TabType; label: string }[] = [
    { id: "live", label: "⚡ Live" },
    { id: "crashes", label: "🔴 Crashes" },
    { id: "control", label: "🎛️ God-Mode" },
    { id: "launcher", label: "🚀 Launcher" },
    { id: "config", label: "⚙️ Configuration" },
    { id: "workers", label: "🖥️ Worker Status" },
    { id: "logs", label: "📜 Live Logs" },
  ];

  return (
    <div className="space-y-6">
      {/* 7-Tab Navigation Header */}
      <div className="flex items-center justify-between border-b border-border overflow-x-auto">
        <div className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider transition whitespace-nowrap ${
                activeTab === tab.id
                  ? "text-foreground border-b-2 border-accent-green"
                  : "text-muted-foreground hover:text-foreground border-b-2 border-transparent"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 text-xs text-muted-foreground px-2 shrink-0 font-mono">
          <span className={`w-2 h-2 rounded-full ${running.length > 0 ? "bg-accent-green animate-pulse" : "bg-muted-foreground"}`} />
          <span>{running.length} active</span>
        </div>
      </div>

      {/* ═══ 1. LIVE TAB ═══ */}
      {activeTab === "live" && (
        <div className="space-y-6">
          <LiveTelemetry />

          <section>
            <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground mb-3">
              Campaigns
            </h2>
            <CampaignsTable />
          </section>

          {/* Active campaign execution detail */}
          {running.length > 0 && (
            <section>
              <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground mb-3">
                Execution State
              </h2>
              {running.map((c) => (
                <ExecutionState key={c.id} campaign={c} />
              ))}
            </section>
          )}
        </div>
      )}

      {/* ═══ 2. CRASHES TAB ═══ */}
      {activeTab === "crashes" && <CrashMatrix />}

      {/* ═══ 3. GOD-MODE TAB ═══ */}
      {activeTab === "control" && (
        <div className="space-y-6">
          <div className="border-b border-border pb-4">
            <h2 className="text-lg font-bold text-foreground">🎛️ God-Mode Signal Dispatch</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Transmit runtime control signals directly to running Temporal workflow state machines.
            </p>
          </div>

          {running.length === 0 ? (
            <div className="border border-border rounded-lg p-12 text-center text-muted-foreground text-xs font-mono">
              No running campaigns available for signal interception.
            </div>
          ) : (
            running.map((c) => {
              const wfId = `crashwise-campaign-${c.id}`;
              return (
                <div key={c.id} className="border border-border rounded-lg p-4 space-y-4 bg-muted/20">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm text-foreground">{c.target_name}</span>
                    <span className="text-xs text-muted-foreground font-mono">{wfId.slice(0, 40)}…</span>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <button
                      onClick={() => sendSignal(wfId, "pause_hunt", true)}
                      className="px-3 py-2 bg-accent-orange/20 text-accent-orange rounded text-xs font-bold hover:bg-accent-orange/30 transition border border-accent-orange/30"
                    >
                      ⏸ PAUSE HUNT
                    </button>
                    <button
                      onClick={() => sendSignal(wfId, "pause_hunt", false)}
                      className="px-3 py-2 bg-accent-green/20 text-accent-green rounded text-xs font-bold hover:bg-accent-green/30 transition border border-accent-green/30"
                    >
                      ▶ RESUME HUNT
                    </button>
                    <button
                      onClick={() => sendSignal(wfId, "force_pivot", "operator override")}
                      className="px-3 py-2 bg-accent-blue/20 text-accent-blue rounded text-xs font-bold hover:bg-accent-blue/30 transition border border-accent-blue/30"
                    >
                      🔀 FORCE PIVOT
                    </button>
                  </div>
                </div>
              );
            })
          )}

          {signalResult && (
            <div className={`text-xs font-mono p-3 rounded border ${
              signalResult.startsWith("✓")
                ? "bg-accent-green/10 text-accent-green border-accent-green/30"
                : "bg-accent-red/10 text-accent-red border-accent-red/30"
            }`}>
              {signalResult}
            </div>
          )}
        </div>
      )}

      {/* ═══ 4. CAMPAIGN LAUNCHER TAB ═══ */}
      {activeTab === "launcher" && (
        <CampaignLauncher onNavigateToLive={() => setActiveTab("live")} />
      )}

      {/* ═══ 5. SYSTEM CONFIGURATION TAB ═══ */}
      {activeTab === "config" && <SystemConfig />}

      {/* ═══ 6. WORKER STATUS TAB ═══ */}
      {activeTab === "workers" && <WorkerStatus />}

      {/* ═══ 7. LIVE LOGS TAB ═══ */}
      {activeTab === "logs" && <LogStreamer />}
    </div>
  );
}

function ExecutionState({ campaign }: { campaign: Campaign }) {
  const [state, setState] = useState<any>(null);

  useEffect(() => {
    const poll = () => {
      fetch(`/campaigns/${campaign.id}/state`)
        .then((r) => (r.ok ? r.json() : null))
        .then(setState)
        .catch(() => setState(null));
    };
    poll();
    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, [campaign.id]);

  const STAGE_DESC: Record<string, string> = {
    pending: "Initializing workflow…",
    seeding: "seed_corpus → harvesting test vectors",
    setup: "setup_target → clone + build + harness synthesis",
    executing: "execute_fuzzing → Docker container running",
    triage: "triage_results → crash classification + dedup",
    completed: "Workflow complete",
    failed: "Workflow failed",
  };

  const STAGE_COLOR: Record<string, string> = {
    pending: "text-muted-foreground",
    seeding: "text-accent-orange",
    setup: "text-accent-orange",
    executing: "text-accent-green",
    triage: "text-accent-orange",
    completed: "text-accent-green",
    failed: "text-accent-red",
  };

  const stage = state?.stage ?? "pending";

  return (
    <div className="border border-border rounded-lg p-4 bg-muted font-mono text-[11px] space-y-1 mb-2">
      <div className="flex items-center gap-2 mb-2">
        <span className={`w-2 h-2 rounded-full ${stage === "executing" ? "bg-accent-green animate-pulse" : "bg-accent-orange"}`} />
        <span className={`font-bold ${STAGE_COLOR[stage] ?? "text-foreground"}`}>
          {STAGE_DESC[stage] ?? stage}
        </span>
      </div>
      <div className="text-muted-foreground">Workflow: crashwise-campaign-{campaign.id.slice(0, 8)}…</div>
      <div className="text-muted-foreground">Target: {campaign.target_name}</div>
      {state && (
        <div className="grid grid-cols-4 gap-x-4 mt-2 pt-2 border-t border-border">
          <div>Iteration: <span className="text-foreground font-bold">{state.iteration ?? 0}</span></div>
          <div>Pivots: <span className="text-accent-blue">{state.pivot_count ?? 0}</span></div>
          <div>Evolutions: <span className="text-accent-orange">{state.evolution_count ?? 0}</span></div>
          <div>Paused: <span className={state.paused ? "text-accent-red" : "text-accent-green"}>{state.paused ? "YES" : "NO"}</span></div>
        </div>
      )}
      {state?.last_note && (
        <div className="mt-1 text-muted-foreground truncate">Note: {state.last_note}</div>
      )}
    </div>
  );
}
