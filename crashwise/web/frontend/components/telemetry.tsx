"use client";

import { useEffect, useState } from "react";

interface TelemetryData {
  global_execs_per_sec: number;
  total_executions: number;
  unique_edges: number;
  crashes_found: number;
  active_campaigns: number;
  timestamp: string;
}

export function LiveTelemetry() {
  const [data, setData] = useState<TelemetryData | null>(null);
  const [uptime, setUptime] = useState(0);

  useEffect(() => {
    let es: EventSource | null = null;
    let reconnectTimer: NodeJS.Timeout | null = null;

    const connect = () => {
      if (es) es.close();
      es = new EventSource("/api/v1/telemetry/stream");
      es.onmessage = (event) => {
        try {
          setData(JSON.parse(event.data));
        } catch {}
      };
      es.onerror = () => {
        if (es) es.close();
        reconnectTimer = setTimeout(connect, 3000);
      };
    };

    connect();
    const timer = setInterval(() => setUptime((u) => u + 1), 1000);
    return () => {
      if (es) es.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearInterval(timer);
    };
  }, []);

  const stats = [
    { label: "EXEC/S", value: data?.global_execs_per_sec?.toLocaleString() ?? "—", color: "text-accent-green" },
    { label: "TOTAL EXECS", value: data?.total_executions?.toLocaleString() ?? "—", color: "text-foreground" },
    { label: "EDGES", value: data?.unique_edges?.toLocaleString() ?? "—", color: "text-accent-blue" },
    { label: "CRASHES", value: data?.crashes_found?.toString() ?? "0", color: data?.crashes_found ? "text-accent-red" : "text-muted-foreground" },
    { label: "UPTIME", value: `${Math.floor(uptime / 60)}m ${uptime % 60}s`, color: "text-muted-foreground" },
  ];

  return (
    <div className="grid grid-cols-5 gap-2">
      {stats.map((s) => (
        <div key={s.label} className="border border-border rounded p-3 bg-muted">
          <p className="text-[10px] text-muted-foreground uppercase tracking-widest">{s.label}</p>
          <p className={`text-xl font-bold mt-0.5 tabular-nums ${s.color}`}>{s.value}</p>
        </div>
      ))}
    </div>
  );
}
