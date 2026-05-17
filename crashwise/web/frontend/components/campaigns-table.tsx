"use client";

import { useEffect, useState } from "react";

interface Campaign {
  id: string;
  target_name: string;
  target_repo: string;
  fuzzer_type: string;
  status: string;
  run_count: number;
  seed_count: number;
  created_at: string;
}

const STATUS_STYLES: Record<string, string> = {
  running: "text-accent-green",
  completed: "text-foreground",
  failed: "text-accent-red",
  stalled: "text-accent-orange",
  pending: "text-muted-foreground",
};

export function CampaignsTable() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    const poll = () => {
      fetch("/campaigns")
        .then((r) => r.json())
        .then(setCampaigns)
        .catch(() => {})
        .finally(() => setLoading(false));
    };
    poll();
    const interval = setInterval(poll, 3000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <p className="text-muted-foreground text-xs">Loading…</p>;
  if (!campaigns.length) return <p className="text-muted-foreground text-xs">No campaigns. Run: crashwise run &lt;repo-url&gt;</p>;

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <table className="w-full text-xs">
        <thead className="bg-muted border-b border-border">
          <tr>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Target</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Engine</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Status</th>
            <th className="text-right px-3 py-2 text-muted-foreground font-medium">Runs</th>
            <th className="text-right px-3 py-2 text-muted-foreground font-medium">Seeds</th>
            <th className="text-right px-3 py-2 text-muted-foreground font-medium"></th>
          </tr>
        </thead>
        <tbody>
          {campaigns.map((c) => (
            <>
              <tr key={c.id} className="border-b border-border hover:bg-muted/50 transition cursor-pointer" onClick={() => setExpanded(expanded === c.id ? null : c.id)}>
                <td className="px-3 py-2.5 font-medium">{c.target_name}</td>
                <td className="px-3 py-2.5">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    c.fuzzer_type === "afl++" ? "bg-accent-orange/20 text-accent-orange" : "bg-accent-blue/20 text-accent-blue"
                  }`}>
                    {c.fuzzer_type}
                  </span>
                </td>
                <td className="px-3 py-2.5">
                  <span className={`inline-flex items-center gap-1 ${STATUS_STYLES[c.status] ?? "text-muted-foreground"}`}>
                    {c.status === "running" && <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />}
                    {c.status === "failed" && <span className="w-1.5 h-1.5 rounded-full bg-accent-red" />}
                    {c.status}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-right tabular-nums">{c.run_count}</td>
                <td className="px-3 py-2.5 text-right tabular-nums">{c.seed_count}</td>
                <td className="px-3 py-2.5 text-right text-muted-foreground">
                  {expanded === c.id ? "▲" : "▼"}
                </td>
              </tr>
              {expanded === c.id && (
                <tr key={`${c.id}-detail`}>
                  <td colSpan={6} className="px-3 py-3 bg-muted/30">
                    <CampaignDetail campaign={c} />
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CampaignDetail({ campaign }: { campaign: Campaign }) {
  const [detail, setDetail] = useState<any>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    fetch(`/campaigns/${campaign.id}`)
      .then((r) => r.json())
      .then(setDetail)
      .catch(() => {});
  }, [campaign.id]);

  const handleDelete = async () => {
    if (!confirm(`Delete campaign "${campaign.target_name}" (${campaign.id.slice(0, 8)}…)?`)) return;
    setDeleting(true);
    try {
      const resp = await fetch(`/campaigns/${campaign.id}`, { method: "DELETE" });
      if (resp.ok) window.location.reload();
      else alert(`Delete failed: ${resp.status}`);
    } catch (e) {
      alert(`Delete failed: ${e}`);
    }
    setDeleting(false);
  };

  if (!detail) return <p className="text-muted-foreground text-xs">Loading…</p>;

  const isFailed = campaign.status === "failed" || campaign.status === "stalled";
  const runs = detail.runs || [];
  const lastRun = runs[runs.length - 1];

  return (
    <div className="space-y-2 font-mono text-[11px]">
      <div className="text-muted-foreground">
        Repo: {detail.target_repo} | Created: {detail.created_at}
      </div>

      {lastRun && (
        <div className="grid grid-cols-4 gap-2">
          <div>Iteration: <span className="text-foreground font-bold">{lastRun.iteration}</span></div>
          <div>Execs: <span className="text-foreground font-bold">{lastRun.executions?.toLocaleString()}</span></div>
          <div>Edges: <span className="text-accent-blue font-bold">{lastRun.coverage_edges ?? "—"}</span></div>
          <div>Duration: <span className="text-foreground">{lastRun.duration_seconds?.toFixed(1)}s</span></div>
        </div>
      )}

      {isFailed && (
        <div className="border border-accent-red/30 rounded p-2 bg-accent-red/5 text-accent-red">
          <div className="font-bold mb-1">⚠ Failure Diagnostics</div>
          {!lastRun && <div>No runs recorded — setup_target activity likely failed (clone/build error).</div>}
          {lastRun && lastRun.coverage_edges === 0 && (
            <div>Zero coverage edges — instrumentation failure or no-op harness. Check -fsanitize-coverage flags.</div>
          )}
          {lastRun && lastRun.coverage_edges > 0 && (
            <div>Coverage plateau detected. Harness may be blocked by magic value / checksum / state machine.</div>
          )}
          <div className="mt-1 text-muted-foreground">→ Check Temporal UI at :8233 for activity-level error traces.</div>
        </div>
      )}

      <div className="flex justify-end pt-2">
        <button
          onClick={handleDelete}
          disabled={deleting || campaign.status === "running"}
          className="px-3 py-1.5 text-[10px] font-bold uppercase rounded bg-accent-red/20 text-accent-red hover:bg-accent-red/30 transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {deleting ? "Deleting…" : "🗑 Delete Campaign"}
        </button>
      </div>
    </div>
  );
}
