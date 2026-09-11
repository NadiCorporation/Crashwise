"use client";

import { useEffect, useState, useCallback } from "react";

interface WorkerDetail {
  name: string;
  status: string;
  task_queue: string;
  uptime_seconds: number;
  campaigns_processed: number;
  last_heartbeat: string | null;
}

export function WorkerStatus() {
  const [workers, setWorkers] = useState<WorkerDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [error, setError] = useState<string | null>(null);

  const fetchWorkers = useCallback(async () => {
    try {
      const resp = await fetch("/api/workers");
      if (resp.ok) {
        const data = await resp.json();
        setWorkers(data);
        setError(null);
      } else {
        setError(`Failed to fetch workers (${resp.status})`);
      }
    } catch (e: any) {
      setError(`Network error: ${e.message || e}`);
    } finally {
      setLoading(false);
      setLastRefreshed(new Date());
    }
  }, []);

  useEffect(() => {
    fetchWorkers();
    const interval = setInterval(fetchWorkers, 3000);
    return () => clearInterval(interval);
  }, [fetchWorkers]);

  const formatUptime = (seconds: number): string => {
    if (!seconds || seconds <= 0) return "0s";
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);

    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0 || d > 0) parts.push(`${h}h`);
    if (m > 0 || h > 0 || d > 0) parts.push(`${m}m`);
    parts.push(`${s}s`);
    return parts.join(" ");
  };

  const totalProcessed = workers.reduce((acc, w) => acc + (w.campaigns_processed || 0), 0);
  const activeCount = workers.filter((w) => w.status === "online" || w.status === "busy").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-lg font-bold text-foreground">🖥️ Worker Nodes & Cluster Telemetry</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time heartbeat monitoring, task queue assignment, and replica workload distribution.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-muted-foreground">
            Updated: {lastRefreshed.toLocaleTimeString()}
          </span>
          <button
            onClick={() => fetchWorkers()}
            className="px-3 py-1.5 bg-muted hover:bg-muted/80 text-foreground border border-border text-xs rounded transition"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 border border-accent-red/40 bg-accent-red/10 rounded-lg text-xs text-accent-red font-mono">
          ⚠ {error}
        </div>
      )}

      {/* Cluster Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="border border-border rounded-lg p-4 bg-muted/20">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground mb-1">
            Active Replicas
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-accent-green">{activeCount}</span>
            <span className="text-xs text-muted-foreground">/ {workers.length} nodes</span>
          </div>
        </div>

        <div className="border border-border rounded-lg p-4 bg-muted/20">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground mb-1">
            Temporal Task Queue
          </div>
          <div className="text-sm font-bold font-mono text-accent-blue truncate">
            {workers[0]?.task_queue || "crashwise"}
          </div>
        </div>

        <div className="border border-border rounded-lg p-4 bg-muted/20">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground mb-1">
            Cluster State
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse" />
            <span className="text-sm font-bold font-mono text-foreground">Operational</span>
          </div>
        </div>

        <div className="border border-border rounded-lg p-4 bg-muted/20">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground mb-1">
            Total Campaigns
          </div>
          <div className="text-2xl font-bold font-mono text-foreground">
            {totalProcessed}
          </div>
        </div>
      </div>

      {/* Workers Replicas Table */}
      <div className="border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-muted border-b border-border flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
            Registered Worker Instances
          </h3>
          <span className="text-[11px] text-muted-foreground font-mono">
            {workers.length} {workers.length === 1 ? "Worker" : "Workers"}
          </span>
        </div>

        {loading && !workers.length ? (
          <div className="p-8 text-center text-muted-foreground text-xs font-mono">
            Discovering cluster replicas…
          </div>
        ) : !workers.length ? (
          <div className="p-8 text-center text-muted-foreground text-xs font-mono">
            No active workers detected. Ensure at least one worker process is running.
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="bg-muted/50 border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Worker Identity</th>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Status</th>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Task Queue</th>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Uptime</th>
                <th className="text-right px-4 py-2.5 text-muted-foreground font-medium">Campaigns Processed</th>
                <th className="text-right px-4 py-2.5 text-muted-foreground font-medium">Heartbeat Recency</th>
              </tr>
            </thead>
            <tbody>
              {workers.map((w) => {
                const isOnline = w.status === "online" || w.status === "busy";
                return (
                  <tr key={w.name} className="border-b border-border hover:bg-muted/30 transition">
                    <td className="px-4 py-3 font-mono font-bold text-foreground">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${isOnline ? "bg-accent-green" : "bg-accent-red"}`} />
                        <span>{w.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        w.status === "online"
                          ? "bg-accent-green/20 text-accent-green border border-accent-green/30"
                          : w.status === "busy"
                          ? "bg-accent-blue/20 text-accent-blue border border-accent-blue/30"
                          : "bg-accent-red/20 text-accent-red border border-accent-red/30"
                      }`}>
                        {w.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-accent-blue">
                      {w.task_queue}
                    </td>
                    <td className="px-4 py-3 font-mono text-foreground">
                      {formatUptime(w.uptime_seconds)}
                    </td>
                    <td className="px-4 py-3 font-mono text-right text-foreground">
                      {w.campaigns_processed ?? 0}
                    </td>
                    <td className="px-4 py-3 font-mono text-right text-muted-foreground">
                      {w.last_heartbeat ? new Date(w.last_heartbeat).toLocaleTimeString() : "Live"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
