"use client";

import { useEffect, useState } from "react";

export interface CrashDetail {
  id: string;
  campaign_id: string;
  crash_type: string;
  severity: string;
  severity_score: number;
  vulnerability_type: string;
  suggested_patch: string;
  verification_status: string;
  verification_stdout: string;
  verification_stderr: string;
  stack_trace: string;
  stack_hash: string;
  signal: string;
  logs_path: string;
  sanitizer_output: string;
  poc_code: string;
  poc_compiled: boolean;
  poc_verified: boolean;
  reachability: string;
  reachability_score: number;
  primitive: string;
  created_at: string;
  verified_at?: string | null;
}

interface CrashDetailModalProps {
  crashId: string;
  campaignId: string;
  onClose: () => void;
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-accent-red/20 text-accent-red border-accent-red/40",
  high: "bg-accent-red/10 text-accent-red border-accent-red/30",
  medium: "bg-accent-orange/20 text-accent-orange border-accent-orange/40",
  low: "bg-muted text-muted-foreground border-border",
  unknown: "bg-muted text-muted-foreground border-border",
};

export function CrashDetailModal({ crashId, campaignId, onClose }: CrashDetailModalProps) {
  const [detail, setDetail] = useState<CrashDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetch(`/campaigns/${campaignId}/crashes/${crashId}`)
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
        return r.json();
      })
      .then(setDetail)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [campaignId, crashId]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadPoc = () => {
    if (!detail?.poc_code) return;
    const blob = new Blob([detail.poc_code], { type: "text/x-csrc" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `poc_${detail.id.slice(0, 8)}.c`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleVerifyPatch = async () => {
    if (!detail) return;
    setVerifying(true);
    setVerifyMsg("Dispatching patch verification workflow…");
    try {
      const resp = await fetch(`/crashes/${detail.id}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          crash_id: detail.id,
          campaign_id: detail.campaign_id,
          repo_url: "auto",
          patch: detail.suggested_patch || "/* no patch */",
          seed_path: detail.logs_path || "seed",
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        setVerifyMsg(`✓ Verification workflow started: ${data.workflow_id}`);
      } else {
        const errText = await resp.text();
        setVerifyMsg(`✗ Verification failed (${resp.status}): ${errText}`);
      }
    } catch (e: any) {
      setVerifyMsg(`✗ Error: ${e.message || e}`);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-background/80 backdrop-blur-sm">
      <div className="w-full max-w-3xl h-full bg-muted border-l border-border shadow-2xl flex flex-col overflow-hidden">
        {/* Modal Top Bar */}
        <div className="px-6 py-4 border-b border-border bg-background flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-muted-foreground">Crash Diagnostics</span>
              <span className="text-xs font-mono text-muted-foreground">/</span>
              <span className="text-xs font-mono text-foreground font-bold">{crashId}</span>
            </div>
            <h2 className="text-base font-bold text-foreground mt-0.5">
              {detail ? detail.crash_type : "Loading Crash Details…"}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="px-3 py-1.5 bg-muted hover:bg-muted/80 text-foreground border border-border text-xs rounded transition font-mono"
          >
            ✕ Close
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {loading && (
            <div className="text-center py-16 text-muted-foreground text-xs font-mono">
              Fetching deep diagnostic trace and PoC from storage…
            </div>
          )}

          {error && (
            <div className="p-4 border border-accent-red/40 bg-accent-red/10 rounded-lg text-xs text-accent-red font-mono">
              ⚠ Error: {error}
            </div>
          )}

          {detail && (
            <>
              {/* Triage Overview Bar */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-background p-4 rounded-lg border border-border">
                <div>
                  <div className="text-[10px] uppercase text-muted-foreground font-medium">Severity / CVSS</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase border ${
                      SEVERITY_BADGE[detail.severity.toLowerCase()] ?? SEVERITY_BADGE.unknown
                    }`}>
                      {detail.severity}
                    </span>
                    <span className="text-xs font-mono font-bold text-foreground">
                      {detail.severity_score}/10
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-[10px] uppercase text-muted-foreground font-medium">Vulnerability CWE</div>
                  <div className="text-xs font-mono font-bold text-accent-blue mt-1">
                    {detail.vulnerability_type || "CWE-Unknown"}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] uppercase text-muted-foreground font-medium">Signal / Hash</div>
                  <div className="text-xs font-mono text-foreground mt-1 truncate">
                    {detail.signal || "SIGSEGV"} ({detail.stack_hash?.slice(0, 8) || "—"})
                  </div>
                </div>

                <div>
                  <div className="text-[10px] uppercase text-muted-foreground font-medium">Reachability / Primitive</div>
                  <div className="text-xs font-mono text-foreground mt-1 truncate">
                    {detail.primitive || "unknown"} ({detail.reachability})
                  </div>
                </div>
              </div>

              {/* CVSS Exploitability Meter */}
              <div className="space-y-1">
                <div className="flex justify-between text-[11px] font-mono">
                  <span className="text-muted-foreground">AI Exploitability Score</span>
                  <span className="font-bold text-foreground">{detail.severity_score} / 10</span>
                </div>
                <div className="w-full h-2 bg-background border border-border rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all ${
                      detail.severity_score >= 8
                        ? "bg-accent-red"
                        : detail.severity_score >= 5
                        ? "bg-accent-orange"
                        : "bg-accent-green"
                    }`}
                    style={{ width: `${(detail.severity_score / 10) * 100}%` }}
                  />
                </div>
              </div>

              {/* Suggested AI Patch */}
              <div className="border border-border rounded-lg bg-background p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                      🛡️ Suggested AI Patch
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                      detail.verification_status === "fixed"
                        ? "bg-accent-green/20 text-accent-green border border-accent-green/30"
                        : detail.verification_status === "failed_verification"
                        ? "bg-accent-red/20 text-accent-red border border-accent-red/30"
                        : "bg-muted text-muted-foreground border border-border"
                    }`}>
                      {detail.verification_status}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {detail.suggested_patch && (
                      <button
                        onClick={() => copyToClipboard(detail.suggested_patch, "patch")}
                        className="px-2.5 py-1 text-[11px] bg-muted hover:bg-muted/80 text-foreground border border-border rounded transition font-mono"
                      >
                        {copiedKey === "patch" ? "✓ Copied" : "📋 Copy Patch"}
                      </button>
                    )}
                    <button
                      onClick={handleVerifyPatch}
                      disabled={verifying || !detail.suggested_patch}
                      className="px-3 py-1 text-[11px] bg-accent-blue/20 hover:bg-accent-blue/30 text-accent-blue border border-accent-blue/30 font-bold rounded transition disabled:opacity-40"
                    >
                      {verifying ? "Verifying…" : "⚡ Verify Patch"}
                    </button>
                  </div>
                </div>

                {verifyMsg && (
                  <div className={`p-2.5 rounded text-xs font-mono ${
                    verifyMsg.startsWith("✓") ? "bg-accent-green/10 text-accent-green" : "bg-accent-orange/10 text-accent-orange"
                  }`}>
                    {verifyMsg}
                  </div>
                )}

                {detail.suggested_patch ? (
                  <pre className="p-3 bg-muted/40 border border-border rounded text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap">
                    {detail.suggested_patch}
                  </pre>
                ) : (
                  <p className="text-xs text-muted-foreground font-mono">
                    No patch synthesized for this crash.
                  </p>
                )}
              </div>

              {/* Standalone Proof of Concept (PoC) */}
              <div className="border border-border rounded-lg bg-background p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                      🎯 Standalone PoC Reproducer
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      detail.poc_compiled ? "bg-accent-green/20 text-accent-green" : "bg-muted text-muted-foreground"
                    }`}>
                      {detail.poc_compiled ? "COMPILED" : "UNCOMPILED"}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      detail.poc_verified ? "bg-accent-green/20 text-accent-green" : "bg-muted text-muted-foreground"
                    }`}>
                      {detail.poc_verified ? "VERIFIED REPRODUCER" : "PENDING VERIFICATION"}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {detail.poc_code && (
                      <>
                        <button
                          onClick={() => copyToClipboard(detail.poc_code, "poc")}
                          className="px-2.5 py-1 text-[11px] bg-muted hover:bg-muted/80 text-foreground border border-border rounded transition font-mono"
                        >
                          {copiedKey === "poc" ? "✓ Copied" : "📋 Copy PoC"}
                        </button>
                        <button
                          onClick={downloadPoc}
                          className="px-2.5 py-1 text-[11px] bg-accent-green/20 hover:bg-accent-green/30 text-accent-green border border-accent-green/30 font-bold rounded transition"
                        >
                          💾 Download PoC (.c)
                        </button>
                      </>
                    )}
                  </div>
                </div>

                {detail.poc_code ? (
                  <pre className="p-3 bg-muted/40 border border-border rounded text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap max-h-60">
                    {detail.poc_code}
                  </pre>
                ) : (
                  <p className="text-xs text-muted-foreground font-mono">
                    No target-linked reproducer generated yet.
                  </p>
                )}
              </div>

              {/* Stack Trace */}
              <div className="border border-border rounded-lg bg-background p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                    ⚡ Stack Backtrace
                  </span>
                  {detail.stack_trace && (
                    <button
                      onClick={() => copyToClipboard(detail.stack_trace, "stack")}
                      className="px-2.5 py-1 text-[11px] bg-muted hover:bg-muted/80 text-foreground border border-border rounded transition font-mono"
                    >
                      {copiedKey === "stack" ? "✓ Copied" : "📋 Copy Stack Trace"}
                    </button>
                  )}
                </div>

                <pre className="p-3 bg-muted/40 border border-border rounded text-xs font-mono text-foreground overflow-x-auto whitespace-pre-wrap max-h-64">
                  {detail.stack_trace || "No stack trace available."}
                </pre>
              </div>

              {/* Sanitizer Output */}
              <div className="border border-border rounded-lg bg-background p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-accent-red">
                    🔴 AddressSanitizer / UndefinedBehavior Report
                  </span>
                  {detail.sanitizer_output && (
                    <button
                      onClick={() => copyToClipboard(detail.sanitizer_output, "asan")}
                      className="px-2.5 py-1 text-[11px] bg-muted hover:bg-muted/80 text-foreground border border-border rounded transition font-mono"
                    >
                      {copiedKey === "asan" ? "✓ Copied" : "📋 Copy ASan Log"}
                    </button>
                  )}
                </div>

                <pre className="p-3 bg-muted/40 border border-border rounded text-xs font-mono text-accent-red overflow-x-auto whitespace-pre-wrap max-h-72">
                  {detail.sanitizer_output || "No sanitizer log recorded."}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
