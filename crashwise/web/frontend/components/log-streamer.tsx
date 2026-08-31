"use client";

import { useEffect, useRef, useState } from "react";

interface LogEntry {
  id: number;
  timestamp: string;
  line: string;
  level?: string;
}

interface CampaignOption {
  id: string;
  target_name: string;
}

export function LogStreamer() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignOption[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>("all");
  const [searchFilter, setSearchFilter] = useState<string>("");
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const nextIdRef = useRef<number>(1);
  const isPausedRef = useRef<boolean>(false);

  // Keep ref in sync with state for SSE listener
  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  // Load active campaigns for dropdown
  useEffect(() => {
    fetch("/campaigns")
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        setCampaigns(data.map((c: any) => ({ id: c.id, target_name: c.target_name })));
      })
      .catch(() => {});
  }, []);

  // Connect SSE
  useEffect(() => {
    let reconnectTimer: any = null;

    const connectStream = () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      let url = "/api/logs/stream?tail=100";
      if (selectedCampaignId !== "all") {
        url += `&campaign_id=${encodeURIComponent(selectedCampaignId)}`;
      }

      const es = new EventSource(url);
      eventSourceRef.current = es;

      es.onopen = () => {
        setIsConnected(true);
      };

      es.onmessage = (event) => {
        if (isPausedRef.current) return;
        try {
          const data = JSON.parse(event.data);
          const newEntry: LogEntry = {
            id: nextIdRef.current++,
            timestamp: data.timestamp || new Date().toISOString(),
            line: data.line || "",
            level: data.level,
          };
          setLogs((prev) => {
            const updated = [...prev, newEntry];
            // Keep buffer reasonable (last 1000 lines)
            if (updated.length > 1000) return updated.slice(-1000);
            return updated;
          });
        } catch {
          // Plain text fallback
          const newEntry: LogEntry = {
            id: nextIdRef.current++,
            timestamp: new Date().toISOString(),
            line: event.data,
          };
          setLogs((prev) => [...prev, newEntry]);
        }
      };

      es.onerror = () => {
        setIsConnected(false);
        es.close();
        // Exponential / delayed retry
        reconnectTimer = setTimeout(connectStream, 3000);
      };
    };

    connectStream();

    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, [selectedCampaignId]);

  // Auto-scroll effect
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  const clearLogs = () => {
    setLogs([]);
  };

  const getLineColor = (line: string, explicitLevel?: string): string => {
    if (explicitLevel === "ERROR" || line.includes("[ERROR]") || line.includes("error=") || line.includes("FATAL") || line.includes("Error")) {
      return "text-accent-red";
    }
    if (explicitLevel === "WARNING" || line.includes("[WARNING]") || line.includes("warn=") || line.includes("WARN")) {
      return "text-accent-orange";
    }
    if (line.includes("[INFO]") || line.includes("stage=") || line.includes("workflow_started")) {
      return "text-accent-blue";
    }
    if (line.includes("[DEBUG]")) {
      return "text-muted-foreground";
    }
    if (line.includes("complete") || line.includes("success") || line.includes("✓") || line.includes("fixed")) {
      return "text-accent-green";
    }
    return "text-foreground";
  };

  const filteredLogs = logs.filter((item) => {
    if (!searchFilter.trim()) return true;
    return item.line.toLowerCase().includes(searchFilter.toLowerCase());
  });

  return (
    <div className="space-y-4">
      {/* Top Controls Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-bold text-foreground">📜 Live Log Stream</h2>
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono border border-border bg-muted">
              <span className={`w-2 h-2 rounded-full ${isConnected ? "bg-accent-green animate-pulse" : "bg-accent-orange"}`} />
              <span className={isConnected ? "text-accent-green font-bold" : "text-accent-orange"}>
                {isConnected ? "Connected (SSE)" : "Reconnecting…"}
              </span>
            </div>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Streaming real-time worker logs, container outputs, and Temporal workflow events.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Campaign Selector */}
          <select
            value={selectedCampaignId}
            onChange={(e) => setSelectedCampaignId(e.target.value)}
            className="px-3 py-1.5 text-xs font-mono bg-muted border border-border rounded focus:outline-none focus:border-accent-green text-foreground"
          >
            <option value="all">All Campaigns</option>
            {campaigns.map((c) => (
              <option key={c.id} value={c.id}>
                {c.target_name} ({c.id.slice(0, 8)}…)
              </option>
            ))}
          </select>

          {/* Search Filter */}
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search log output…"
            className="px-3 py-1.5 text-xs font-mono bg-muted border border-border rounded focus:outline-none focus:border-accent-green text-foreground w-44"
          />

          {/* Auto Scroll Toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-3 py-1.5 text-xs font-mono border rounded transition ${
              autoScroll ? "bg-accent-green/20 text-accent-green border-accent-green/30 font-bold" : "bg-muted text-muted-foreground border-border"
            }`}
          >
            {autoScroll ? "Auto-Scroll: ON" : "Auto-Scroll: OFF"}
          </button>

          {/* Pause / Resume */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`px-3 py-1.5 text-xs font-mono border rounded transition ${
              isPaused ? "bg-accent-orange/20 text-accent-orange border-accent-orange/30 font-bold" : "bg-muted text-muted-foreground border-border"
            }`}
          >
            {isPaused ? "▶ Resume" : "⏸ Pause"}
          </button>

          {/* Clear Console */}
          <button
            onClick={clearLogs}
            className="px-3 py-1.5 bg-muted hover:bg-muted/80 text-foreground border border-border text-xs font-mono rounded transition"
          >
            Clear Console
          </button>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="border border-border rounded-lg bg-[#090d13] font-mono text-[11px] p-4 h-[650px] overflow-y-auto space-y-1 shadow-inner select-text">
        {filteredLogs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-muted-foreground text-xs font-mono">
            {isConnected ? "Awaiting new log events from worker process…" : "Connecting to live log stream…"}
          </div>
        ) : (
          filteredLogs.map((item) => (
            <div key={item.id} className="flex gap-2 leading-relaxed hover:bg-white/5 py-0.5 px-1 rounded transition">
              <span className="text-muted-foreground/60 select-none shrink-0">
                {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : "--:--:--"}
              </span>
              <span className={`break-all ${getLineColor(item.line, item.level)}`}>
                {item.line}
              </span>
            </div>
          ))
        )}
        <div ref={terminalEndRef} />
      </div>

      <div className="flex justify-between items-center text-[11px] font-mono text-muted-foreground px-1">
        <span>Showing {filteredLogs.length} events (Buffer: {logs.length}/1000)</span>
        <span>Filter: {selectedCampaignId === "all" ? "All Sources" : `Campaign: ${selectedCampaignId}`}</span>
      </div>
    </div>
  );
}
