"use client";

import { useEffect, useState } from "react";

interface Crash {
  id: string;
  campaign_id: string;
  crash_type: string;
  crash_state: string;
  severity: string;
  status: string;
  found_at: string;
  sanitizer_log?: string;
  gdb_backtrace?: string;
  reproducer_path?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-accent-red/20 text-accent-red border-accent-red/30",
  high: "bg-accent-red/10 text-accent-red border-accent-red/20",
  medium: "bg-accent-orange/20 text-accent-orange border-accent-orange/30",
  low: "bg-muted text-muted-foreground border-border",
  unknown: "bg-muted text-muted-foreground border-border",
};

const CRASH_TYPE_COLORS: Record<string, string> = {
  "heap-buffer-overflow": "text-accent-red",
  "use-after-free": "text-accent-red",
  "stack-buffer-overflow": "text-accent-red",
  "null-pointer-dereference": "text-accent-orange",
  "out-of-bounds-read": "text-accent-orange",
  "integer-overflow": "text-accent-orange",
};

export function CrashMatrix() {
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [selected, setSelected] = useState<Crash | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/v1/crashes")
      .then((r) => r.json())
      .then(setCrashes)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-muted-foreground text-sm">Loading...</p>;
  if (!crashes.length) {
    return (
      <div className="border border-border rounded-lg p-8 text-center">
        <p className="text-muted-foreground">No crashes found yet.</p>
        <p className="text-xs text-muted-foreground mt-1">Crashes will appear here as campaigns discover them.</p>
      </div>
    );
  }

  return (
    <div className="flex gap-4">
      {/* Crash list */}
      <div className="flex-1 border border-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted border-b border-border">
            <tr>
              <th className="text-left px-4 py-2 text-muted-foreground font-medium">Type</th>
              <th className="text-left px-4 py-2 text-muted-foreground font-medium">State</th>
              <th className="text-left px-4 py-2 text-muted-foreground font-medium">Severity</th>
              <th className="text-left px-4 py-2 text-muted-foreground font-medium">Status</th>
              <th className="text-left px-4 py-2 text-muted-foreground font-medium">Found</th>
            </tr>
          </thead>
          <tbody>
            {crashes.map((c) => (
              <tr
                key={c.id}
                onClick={() => setSelected(c)}
                className={`border-b border-border cursor-pointer transition ${
                  selected?.id === c.id ? "bg-muted" : "hover:bg-muted/50"
                }`}
              >
                <td className={`px-4 py-3 font-medium ${CRASH_TYPE_COLORS[c.crash_type] ?? "text-foreground"}`}>
                  {c.crash_type}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground truncate max-w-[200px]">
                  {c.crash_state}
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold border ${SEVERITY_COLORS[c.severity] ?? SEVERITY_COLORS.unknown}`}>
                    {c.severity}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-muted-foreground">{c.status}</td>
                <td className="px-4 py-3 text-xs text-muted-foreground">
                  {new Date(c.found_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Triage Drawer */}
      {selected && (
        <div className="w-[480px] border border-border rounded-lg bg-muted p-4 space-y-4 overflow-y-auto max-h-[80vh]">
          <div className="flex items-center justify-between">
            <h3 className="font-bold text-sm">Crash Detail</h3>
            <button
              onClick={() => setSelected(null)}
              className="text-muted-foreground hover:text-foreground text-xs"
            >
              ✕ Close
            </button>
          </div>

          <div className="space-y-1 text-xs">
            <p><span className="text-muted-foreground">Type:</span> <span className="font-bold">{selected.crash_type}</span></p>
            <p><span className="text-muted-foreground">State:</span> <span className="font-mono">{selected.crash_state}</span></p>
            <p><span className="text-muted-foreground">Severity:</span> <span className="font-bold">{selected.severity}</span></p>
          </div>

          {selected.gdb_backtrace && (
            <div>
              <p className="text-xs text-muted-foreground mb-1 font-medium">GDB Backtrace</p>
              <pre className="bg-background border border-border rounded p-3 text-xs overflow-x-auto whitespace-pre-wrap">
                {selected.gdb_backtrace}
              </pre>
            </div>
          )}

          {selected.sanitizer_log && (
            <div>
              <p className="text-xs text-muted-foreground mb-1 font-medium">Sanitizer Log</p>
              <pre className="bg-background border border-border rounded p-3 text-xs overflow-x-auto whitespace-pre-wrap text-accent-red">
                {selected.sanitizer_log}
              </pre>
            </div>
          )}

          {selected.reproducer_path && (
            <a
              href={`/api/v1/crashes/${selected.id}/reproducer`}
              className="inline-flex items-center gap-2 px-3 py-1.5 bg-accent-blue/20 text-accent-blue border border-accent-blue/30 rounded text-xs font-medium hover:bg-accent-blue/30 transition"
            >
              ↓ Download Reproducer
            </a>
          )}
        </div>
      )}
    </div>
  );
}
