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

  useEffect(() => {
    try {
      const es = new EventSource("/api/v1/telemetry/stream");
      es.onmessage = (event) => {
        try {
          setData(JSON.parse(event.data));
        } catch {}
      };
      es.onerror = () => {
        es.close();
      };
      return () => es.close();
    } catch {
      return undefined;
    }
  }, []);

  const stats = [
    {
      label: "Exec/s",
      value: data?.global_execs_per_sec?.toLocaleString() ?? "—",
      color: "text-accent-green",
    },
    {
      label: "Total Executions",
      value: data?.total_executions?.toLocaleString() ?? "—",
      color: "text-foreground",
    },
    {
      label: "Unique Edges",
      value: data?.unique_edges?.toLocaleString() ?? "—",
      color: "text-accent-blue",
    },
    {
      label: "Crashes Found",
      value: data?.crashes_found?.toLocaleString() ?? "0",
      color: data?.crashes_found ? "text-accent-red" : "text-muted-foreground",
    },
    {
      label: "Active Campaigns",
      value: data?.active_campaigns?.toString() ?? "0",
      color: "text-accent-green",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
      {stats.map((s) => (
        <div key={s.label} className="border border-border rounded-lg p-4 bg-muted">
          <p className="text-xs text-muted-foreground uppercase tracking-wider">{s.label}</p>
          <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
        </div>
      ))}
    </div>
  );
}
