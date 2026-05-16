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

export function CampaignsTable() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/campaigns")
      .then((r) => r.json())
      .then(setCampaigns)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-muted-foreground text-sm">Loading...</p>;
  if (!campaigns.length) return <p className="text-muted-foreground text-sm">No campaigns.</p>;

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-muted border-b border-border">
          <tr>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Target</th>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Engine</th>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Status</th>
            <th className="text-right px-4 py-2 text-muted-foreground font-medium">Runs</th>
            <th className="text-right px-4 py-2 text-muted-foreground font-medium">Seeds</th>
          </tr>
        </thead>
        <tbody>
          {campaigns.map((c) => (
            <tr key={c.id} className="border-b border-border hover:bg-muted/50 transition">
              <td className="px-4 py-3 font-medium">{c.target_name}</td>
              <td className="px-4 py-3">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                  c.fuzzer_type === "aflpp" ? "bg-accent-orange/20 text-accent-orange" : "bg-accent-blue/20 text-accent-blue"
                }`}>
                  {c.fuzzer_type}
                </span>
              </td>
              <td className="px-4 py-3">
                <span className={`inline-flex items-center gap-1.5 ${
                  c.status === "running" ? "text-accent-green" : "text-muted-foreground"
                }`}>
                  {c.status === "running" && <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse" />}
                  {c.status}
                </span>
              </td>
              <td className="px-4 py-3 text-right tabular-nums">{c.run_count}</td>
              <td className="px-4 py-3 text-right tabular-nums">{c.seed_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
