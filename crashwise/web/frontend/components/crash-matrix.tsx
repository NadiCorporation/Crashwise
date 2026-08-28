"use client";

import { useEffect, useState } from "react";
import { CrashDetailModal } from "./crash-detail-modal";

interface CrashRow {
  id: string;
  campaign_id: string;
  crash_type: string;
  severity: string;
  severity_score?: number;
  vulnerability_type?: string;
  status?: string;
  found_at?: string;
  created_at?: string;
  signal?: string;
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
  const [crashes, setCrashes] = useState<CrashRow[]>([]);
  const [selectedCrash, setSelectedCrash] = useState<{ id: string; campaignId: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const loadCrashes = async () => {
    setLoading(true);
    try {
      // 1. Try fetching from /campaigns and aggregate
      const campResp = await fetch("/campaigns");
      let allCrashes: CrashRow[] = [];

      if (campResp.ok) {
        const campaigns = await campResp.json();
        const crashPromises = campaigns.map(async (c: any) => {
          try {
            const cr = await fetch(`/campaigns/${c.id}/crashes`);
            if (cr.ok) {
              const list = await cr.json();
              return list.map((item: any) => ({
                ...item,
                campaign_id: c.id,
                found_at: item.created_at,
              }));
            }
          } catch {
            return [];
          }
          return [];
        });
        const results = await Promise.all(crashPromises);
        allCrashes = results.flat();
      }

      // 2. Also try /api/v1/crashes to get any web control plane crashes
      try {
        const v1Resp = await fetch("/api/v1/crashes");
        if (v1Resp.ok) {
          const v1List = await v1Resp.json();
          for (const v1Item of v1List) {
            if (!allCrashes.some((c) => c.id === v1Item.id)) {
              allCrashes.push({
                id: v1Item.id,
                campaign_id: v1Item.campaign_id || "00000000-0000-0000-0000-000000000000",
                crash_type: v1Item.crash_type,
                severity: v1Item.severity,
                severity_score: v1Item.severity_score || 0,
                vulnerability_type: v1Item.vulnerability_type || "unknown",
                status: v1Item.status || "discovered",
                found_at: v1Item.found_at || v1Item.created_at || new Date().toISOString(),
                signal: v1Item.signal || "SIGSEGV",
              });
            }
          }
        }
      } catch {}

      setCrashes(allCrashes);
    } catch {
      setCrashes([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCrashes();
  }, []);

  const filtered = crashes.filter((c) => {
    if (severityFilter !== "all" && c.severity.toLowerCase() !== severityFilter.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchType = c.crash_type?.toLowerCase().includes(q);
      const matchCwe = c.vulnerability_type?.toLowerCase().includes(q);
      const matchId = c.id?.toLowerCase().includes(q);
      if (!matchType && !matchCwe && !matchId) return false;
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Controls / Filter Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-lg font-bold text-foreground">🔴 Discovered Crash Matrix</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Deduplicated memory safety findings, CWE classifications, and AI exploitability rankings.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Search Filter */}
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by type, CWE, or ID…"
            className="px-3 py-1.5 text-xs font-mono bg-muted border border-border rounded focus:outline-none focus:border-accent-green text-foreground w-48"
          />

          {/* Severity Filter Buttons */}
          <div className="flex items-center gap-1 bg-muted p-0.5 rounded border border-border">
            {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 text-[11px] font-bold uppercase rounded transition ${
                  severityFilter === sev
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <button
            onClick={loadCrashes}
            className="px-3 py-1.5 bg-muted hover:bg-muted/80 text-foreground border border-border text-xs rounded transition"
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="border border-border rounded-lg p-8 text-center text-muted-foreground text-xs font-mono">
          Querying crash triage database…
        </div>
      ) : !filtered.length ? (
        <div className="border border-border rounded-lg p-12 text-center space-y-2">
          <div className="text-xl">🛡️</div>
          <p className="text-sm font-bold text-foreground">No matching crashes found</p>
          <p className="text-xs text-muted-foreground">
            {crashes.length > 0
              ? "Try adjusting your search query or severity filter."
              : "Crashes will appear here as active fuzzing campaigns uncover vulnerabilities."}
          </p>
        </div>
      ) : (
        <div className="border border-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-muted border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Crash Type</th>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">CWE Classification</th>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Severity / CVSS</th>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Signal</th>
                <th className="text-left px-4 py-2.5 text-muted-foreground font-medium">Found At</th>
                <th className="text-right px-4 py-2.5 text-muted-foreground font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr
                  key={c.id}
                  onClick={() => setSelectedCrash({ id: c.id, campaignId: c.campaign_id })}
                  className="border-b border-border cursor-pointer hover:bg-muted/40 transition"
                >
                  <td className={`px-4 py-3 font-mono font-bold ${CRASH_TYPE_COLORS[c.crash_type] ?? "text-foreground"}`}>
                    {c.crash_type}
                  </td>
                  <td className="px-4 py-3 font-mono text-accent-blue">
                    {c.vulnerability_type || "CWE-Unknown"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        SEVERITY_COLORS[c.severity?.toLowerCase()] ?? SEVERITY_COLORS.unknown
                      }`}>
                        {c.severity}
                      </span>
                      {c.severity_score !== undefined && (
                        <span className="font-mono text-muted-foreground">({c.severity_score}/10)</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-muted-foreground">
                    {c.signal || "SIGSEGV"}
                  </td>
                  <td className="px-4 py-3 font-mono text-muted-foreground">
                    {c.found_at || c.created_at ? new Date(c.found_at || c.created_at!).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedCrash({ id: c.id, campaignId: c.campaign_id });
                      }}
                      className="px-2.5 py-1 bg-muted hover:bg-muted/80 text-foreground border border-border rounded text-[11px] font-mono transition"
                    >
                      Inspect →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Slide-over Crash Detail Modal */}
      {selectedCrash && (
        <CrashDetailModal
          crashId={selectedCrash.id}
          campaignId={selectedCrash.campaignId}
          onClose={() => setSelectedCrash(null)}
        />
      )}
    </div>
  );
}
