"use client";

import { useEffect, useState, useCallback } from "react";
import { CampaignsTable } from "@/components/campaigns-table";
import { LiveTelemetry } from "@/components/telemetry";
import { CrashMatrix } from "@/components/crash-matrix";

interface Campaign {
  id: string;
  target_name: string;
  status: string;
  run_count: number;
}

export default function DashboardPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [activeTab, setActiveTab] = useState<"live" | "crashes" | "control">("live");
  const [signalResult, setSignalResult] = useState<string>("");

  const refresh = useCallback(() => {
    fetch("/campaigns")
      .then((r) => r.json())
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
      const resp = await fetch(`/api/v1/campaigns/signal`, {
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

  return (
    <div className="space-y-6">
      {/* Tab navigation */}
      <div className="flex gap-1 border-b border-border">
        {(["live", "crashes", "control"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-xs font-bold uppercase tracking-wider transition ${
              activeTab === tab
                ? "text-foreground border-b-2 border-accent-green"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {tab === "live" && "⚡ Live"}
            {tab === "crashes" && "🔴 Crashes"}
            {tab === "control" && "🎛️ God-Mode"}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
          <span className={`w-2 h-2 rounded-full ${running.length > 0 ? "bg-accent-green animate-pulse" : "bg-muted-foreground"}`} />
          {running.length} active
        </div>
      </div>

      {/* ═══ LIVE TAB ═══ */}
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
                <div key={c.id} className="border border-border rounded-lg p-4 bg-muted font-mono text-xs space-y-1">
                  <div><span className="text-accent-green">●</span> Workflow: crashwise-campaign-{c.id.slice(0, 8)}…</div>
                  <div><span className="text-accent-orange">●</span> Stage: EXECUTING (iteration {c.run_count})</div>
                  <div><span className="text-accent-blue">●</span> Target: {c.target_name}</div>
                </div>
              ))}
            </section>
          )}
        </div>
      )}

      {/* ═══ CRASHES TAB ═══ */}
      {activeTab === "crashes" && <CrashMatrix />}

      {/* ═══ GOD-MODE TAB ═══ */}
      {activeTab === "control" && (
        <div className="space-y-6">
          <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
            Runtime Signal Dispatch
          </h2>

          {running.length === 0 ? (
            <p className="text-muted-foreground text-sm">No active campaigns to control.</p>
          ) : (
            running.map((c) => {
              const wfId = `crashwise-campaign-${c.id}`;
              return (
                <div key={c.id} className="border border-border rounded-lg p-4 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="font-bold">{c.target_name}</span>
                    <span className="text-xs text-muted-foreground font-mono">{wfId.slice(0, 40)}…</span>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <button
                      onClick={() => sendSignal(wfId, "pause_hunt", true)}
                      className="px-3 py-2 bg-accent-orange/20 text-accent-orange rounded text-xs font-bold hover:bg-accent-orange/30 transition"
                    >
                      ⏸ PAUSE
                    </button>
                    <button
                      onClick={() => sendSignal(wfId, "pause_hunt", false)}
                      className="px-3 py-2 bg-accent-green/20 text-accent-green rounded text-xs font-bold hover:bg-accent-green/30 transition"
                    >
                      ▶ RESUME
                    </button>
                    <button
                      onClick={() => sendSignal(wfId, "force_pivot", "operator override")}
                      className="px-3 py-2 bg-accent-blue/20 text-accent-blue rounded text-xs font-bold hover:bg-accent-blue/30 transition"
                    >
                      🔀 PIVOT
                    </button>
                  </div>
                </div>
              );
            })
          )}

          {signalResult && (
            <div className={`text-xs font-mono p-2 rounded ${
              signalResult.startsWith("✓") ? "bg-accent-green/10 text-accent-green" : "bg-accent-red/10 text-accent-red"
            }`}>
              {signalResult}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
