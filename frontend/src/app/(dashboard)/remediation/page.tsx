"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  ChevronLeft, FileText, Zap, Loader2, Copy, Check,
  AlertTriangle, BarChart3,
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface VulnSummary {
  id: string;
  cve_id: string;
  title: string;
  severity: string;
  triage_priority: string | null;
  status: string;
}

interface ListResponse {
  items: VulnSummary[];
  total: number;
}

interface TicketDraft {
  vuln_id: string;
  cve_id: string;
  format: string;
  markdown: string | null;
  jira_summary: string | null;
  jira_description: string | null;
  jira_priority: string | null;
  jira_issue_key: string | null;
  jira_issue_url: string | null;
}

interface TriageAdvice {
  markdown: string;
  total: number;
  immediate_count: number;
  this_week_count: number;
  this_month_count: number;
  monitor_count: number;
  accept_count: number;
  unscored_count: number;
}

const FORMAT_OPTIONS = [
  { value: "markdown", label: "Markdown" },
  { value: "jira", label: "Jira" },
  { value: "both", label: "Both" },
] as const;

// ── Copy button helper ────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard not available — silently ignore
    }
  }
  return (
    <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={handleCopy}>
      {copied ? <Check className="h-3 w-3 text-green-600" /> : <Copy className="h-3 w-3" />}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

// ── Inner component (uses useSearchParams, must be inside Suspense) ───────────

function RemediationInner() {
  const searchParams = useSearchParams();
  const preselectedId = searchParams.get("vuln_id") ?? "";

  // ── Findings list for the dropdown ──────────────────────────────────────
  const [vulns, setVulns] = useState<VulnSummary[]>([]);
  const [vulnsLoading, setVulnsLoading] = useState(true);

  const fetchVulns = useCallback(async () => {
    setVulnsLoading(true);
    try {
      const data = await api.get<ListResponse>("/vulnerabilities/?page=1&page_size=200");
      setVulns(data.items);
    } catch {
      // Best-effort — dropdown will just be empty
    } finally {
      setVulnsLoading(false);
    }
  }, []);

  useEffect(() => { fetchVulns(); }, [fetchVulns]);

  // ── Ticket drafter state ─────────────────────────────────────────────────
  const [selectedId, setSelectedId] = useState(preselectedId);
  const [format, setFormat] = useState<"markdown" | "jira" | "both">("markdown");
  const [drafting, setDrafting] = useState(false);
  const [ticket, setTicket] = useState<TicketDraft | null>(null);
  const [ticketError, setTicketError] = useState<string | null>(null);
  const [ticketTab, setTicketTab] = useState<"markdown" | "jira">("markdown");

  // ── Triage advice state ──────────────────────────────────────────────────
  const [adviseBusy, setAdviseBusy] = useState(false);
  const [advice, setAdvice] = useState<TriageAdvice | null>(null);
  const [adviceError, setAdviceError] = useState<string | null>(null);

  async function draftTicket() {
    if (!selectedId) return;
    setDrafting(true);
    setTicket(null);
    setTicketError(null);
    try {
      const result = await api.post<TicketDraft>(
        `/remediation/${selectedId}/ticket`,
        { format },
      );
      setTicket(result);
      // Default to the first available tab
      if (result.markdown) setTicketTab("markdown");
      else if (result.jira_summary) setTicketTab("jira");
    } catch (e) {
      setTicketError(
        e instanceof ApiError
          ? e.message
          : "Failed to draft ticket. Make sure an LLM is configured in Org Settings.",
      );
    } finally {
      setDrafting(false);
    }
  }

  async function generateAdvice() {
    setAdviseBusy(true);
    setAdvice(null);
    setAdviceError(null);
    try {
      const result = await api.post<TriageAdvice>("/remediation/triage-advice", {});
      setAdvice(result);
    } catch (e) {
      setAdviceError(
        e instanceof ApiError
          ? e.message
          : "Failed to generate advice. Make sure an LLM is configured and findings are scored.",
      );
    } finally {
      setAdviseBusy(false);
    }
  }

  const selectedVuln = vulns.find(v => v.id === selectedId);

  return (
    <div className="min-h-screen bg-muted/20">
      {/* Header */}
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground text-sm">
              <ChevronLeft className="h-4 w-4" /> Dashboard
            </Link>
            <span className="text-muted-foreground">/</span>
            <span className="font-semibold text-sm flex items-center gap-1.5">
              <FileText className="h-4 w-4 text-primary" /> Remediation
            </span>
          </div>
          <ThemeToggle />
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 py-8 space-y-6">
        <div>
          <h1 className="text-xl font-bold">Remediation</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Draft remediation tickets for individual findings or generate a board-ready triage plan across your entire portfolio.
            Requires an LLM to be configured in <Link href="/settings" className="underline">Org Settings</Link>.
          </p>
        </div>

        {/* ── Ticket Drafter ─────────────────────────────────────────────────── */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <FileText className="h-4 w-4 text-primary" /> Draft Remediation Ticket
            </CardTitle>
            <CardDescription>
              Select a finding and generate a structured ticket ready for your issue tracker.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Finding selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-foreground">Finding</label>
              {vulnsLoading ? (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" /> Loading findings…
                </div>
              ) : vulns.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No findings yet.{" "}
                  <Link href="/findings" className="underline">Upload or add findings</Link> first.
                </p>
              ) : (
                <select
                  value={selectedId}
                  onChange={e => { setSelectedId(e.target.value); setTicket(null); setTicketError(null); }}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="">Select a finding…</option>
                  {vulns.map(v => (
                    <option key={v.id} value={v.id}>
                      {v.cve_id} — {v.title.length > 60 ? `${v.title.slice(0, 60)}…` : v.title}
                      {v.triage_priority ? ` [${v.triage_priority.replace("_", " ")}]` : " [unscored]"}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* Selected finding chip */}
            {selectedVuln && (
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-muted-foreground">Selected:</span>
                <Badge variant={selectedVuln.severity as Parameters<typeof Badge>[0]["variant"]}>
                  {selectedVuln.severity}
                </Badge>
                {selectedVuln.triage_priority && (
                  <Badge variant={selectedVuln.triage_priority as Parameters<typeof Badge>[0]["variant"]}>
                    {selectedVuln.triage_priority.replace("_", " ")}
                  </Badge>
                )}
                <span className="text-muted-foreground font-mono">{selectedVuln.cve_id}</span>
                {!selectedVuln.triage_priority && (
                  <span className="text-amber-600 flex items-center gap-1">
                    <AlertTriangle className="h-3 w-3" />
                    Not scored — AI priority context will be limited
                  </span>
                )}
              </div>
            )}

            {/* Format selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-foreground">Output format</label>
              <div className="flex gap-2">
                {FORMAT_OPTIONS.map(f => (
                  <button
                    key={f.value}
                    onClick={() => setFormat(f.value)}
                    className={`flex-1 rounded-md border py-1.5 text-xs font-medium transition-colors ${
                      format === f.value
                        ? "border-primary bg-primary/5 text-primary"
                        : "text-muted-foreground hover:border-muted-foreground"
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Error */}
            {ticketError && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{ticketError}</AlertDescription>
              </Alert>
            )}

            {/* Draft button */}
            <Button
              onClick={draftTicket}
              disabled={!selectedId || drafting}
              className="w-full"
            >
              {drafting
                ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Drafting ticket…</>
                : <><FileText className="h-4 w-4 mr-2" /> Draft ticket</>}
            </Button>

            {/* Ticket output */}
            {ticket && (
              <div className="space-y-3 pt-2 border-t">
                {/* Tab switcher when both formats available */}
                {ticket.markdown && ticket.jira_summary && (
                  <div className="flex gap-1">
                    <button
                      onClick={() => setTicketTab("markdown")}
                      className={`px-3 py-1 text-xs rounded font-medium transition-colors ${
                        ticketTab === "markdown"
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted text-muted-foreground hover:bg-muted/80"
                      }`}
                    >
                      Markdown
                    </button>
                    <button
                      onClick={() => setTicketTab("jira")}
                      className={`px-3 py-1 text-xs rounded font-medium transition-colors ${
                        ticketTab === "jira"
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted text-muted-foreground hover:bg-muted/80"
                      }`}
                    >
                      Jira
                    </button>
                  </div>
                )}

                {/* Markdown output */}
                {ticket.markdown && (!ticket.jira_summary || ticketTab === "markdown") && (
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-muted-foreground">Markdown</span>
                      <CopyButton text={ticket.markdown} />
                    </div>
                    <pre className="rounded-md border bg-muted/40 p-4 text-xs whitespace-pre-wrap break-words overflow-y-auto max-h-[480px] font-mono leading-relaxed">
                      {ticket.markdown}
                    </pre>
                  </div>
                )}

                {/* Jira output */}
                {ticket.jira_summary && (!ticket.markdown || ticketTab === "jira") && (
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-muted-foreground">Summary</span>
                        <CopyButton text={ticket.jira_summary} />
                      </div>
                      <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
                        {ticket.jira_summary}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-muted-foreground">Description</span>
                        <CopyButton text={ticket.jira_description ?? ""} />
                      </div>
                      <pre className="rounded-md border bg-muted/40 p-3 text-xs whitespace-pre-wrap break-words overflow-y-auto max-h-[320px] font-mono">
                        {ticket.jira_description}
                      </pre>
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-muted-foreground">Priority:</span>
                      <span className="font-semibold">{ticket.jira_priority ?? "—"}</span>
                    </div>
                    {ticket.jira_issue_key && (
                      <Alert>
                        <Check className="h-4 w-4 text-green-600" />
                        <AlertDescription className="text-sm">
                          Jira issue created:{" "}
                          {ticket.jira_issue_url
                            ? <a href={ticket.jira_issue_url} target="_blank" rel="noopener noreferrer" className="underline font-medium">{ticket.jira_issue_key}</a>
                            : <strong>{ticket.jira_issue_key}</strong>}
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* ── Bulk Triage Advice ─────────────────────────────────────────────── */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" /> Bulk Triage Plan
            </CardTitle>
            <CardDescription>
              Generate a strategic, board-ready action plan across all scored findings in your org.
              Requires at least some findings to be AI-scored first.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {adviceError && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{adviceError}</AlertDescription>
              </Alert>
            )}

            <Button
              variant="outline"
              onClick={generateAdvice}
              disabled={adviseBusy}
              className="w-full"
            >
              {adviseBusy
                ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Generating plan…</>
                : <><Zap className="h-4 w-4 mr-2" /> Generate triage plan</>}
            </Button>

            {advice && (
              <div className="space-y-4 pt-2 border-t">
                {/* Priority breakdown */}
                <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
                  {[
                    { label: "Immediate", count: advice.immediate_count, className: "text-red-600" },
                    { label: "This week", count: advice.this_week_count, className: "text-orange-600" },
                    { label: "This month", count: advice.this_month_count, className: "text-yellow-600" },
                    { label: "Monitor", count: advice.monitor_count, className: "text-muted-foreground" },
                    { label: "Accept", count: advice.accept_count, className: "text-muted-foreground" },
                    { label: "Unscored", count: advice.unscored_count, className: "text-muted-foreground/60" },
                  ].map(({ label, count, className }) => (
                    <div key={label} className="rounded-md border bg-muted/20 p-2 text-center">
                      <div className={`text-lg font-bold ${className}`}>{count}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
                    </div>
                  ))}
                </div>

                {/* Markdown output */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-muted-foreground">Triage plan (Markdown)</span>
                    <CopyButton text={advice.markdown} />
                  </div>
                  <pre className="rounded-md border bg-muted/40 p-4 text-xs whitespace-pre-wrap break-words overflow-y-auto max-h-[520px] font-mono leading-relaxed">
                    {advice.markdown}
                  </pre>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

// ── Page wrapper (Suspense required for useSearchParams in App Router) ────────

export default function RemediationPage() {
  return (
    <Suspense fallback={
      <div className="flex min-h-screen items-center justify-center text-muted-foreground text-sm gap-2">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading…
      </div>
    }>
      <RemediationInner />
    </Suspense>
  );
}
