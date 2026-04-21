"use client";

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { api, ApiError, getValidToken } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ShieldAlert, Upload, Plus, RefreshCw, Zap, Trash2,
  ChevronLeft, ChevronRight, X, AlertTriangle, Loader2,
  ChevronDown, ChevronUp, Sparkles, FileText, Server,
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;
  cvss_score: number | null;
  epss_score: number | null;
  kev_listed: boolean;
  triage_priority: string | null;
  score_rationale: string | null;
  affected_component: string | null;
  published_at: string | null;
  created_at: string;
  is_duplicate: boolean;
  asset_id: string | null;
}

interface ListResponse {
  items: Vulnerability[];
  total: number;
  page: number;
  page_size: number;
}

interface IngestionResult {
  ingested: number;
  duplicates: number;
  errors: { row: number; cve_id: string | null; error: string }[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "critical", high: "high", medium: "medium",
  low: "low", informational: "informational",
};

const PRIORITY_LABELS: Record<string, string> = {
  immediate: "Immediate", this_week: "This week",
  this_month: "This month", monitor: "Monitor", accept: "Accept",
};

// Status values accepted by the backend Vulnerability schema.
const STATUS_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "triaged", label: "Triaged" },
  { value: "remediated", label: "Remediated" },
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "false_positive", label: "False positive" },
] as const;

// ── Manual Add Form ───────────────────────────────────────────────────────────

interface ManualFormData {
  cve_id: string; title: string; description: string;
  severity: string; source: string; affected_component: string;
  cvss_score: string; notes: string;
}

const EMPTY_FORM: ManualFormData = {
  cve_id: "", title: "", description: "", severity: "medium",
  source: "manual", affected_component: "", cvss_score: "", notes: "",
};

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function FindingsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const canEdit = user?.role === "admin" || user?.role === "analyst";

  // List state
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 25;
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);

  // Upload dialog
  const [uploadOpen, setUploadOpen] = useState(false);
  const [uploadFormat, setUploadFormat] = useState<"csv" | "json" | "tenable" | "nessus" | "qualys" | "rapid7">("csv");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadResult, setUploadResult] = useState<IngestionResult | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Manual add dialog
  const [addOpen, setAddOpen] = useState(false);
  const [form, setForm] = useState<ManualFormData>(EMPTY_FORM);
  const [addError, setAddError] = useState<string | null>(null);
  const [isAdding, setIsAdding] = useState(false);

  // Bulk action state
  const [enriching, setEnriching] = useState(false);
  const [scoring, setScoring] = useState(false);
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);

  // Row-level action indicator (enrich/score/delete/status)
  const [rowAction, setRowAction] = useState<Record<string, string>>({});

  // Row expansion (to show full AI rationale + details)
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  // Selection for bulk actions
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState<string | null>(null);
  const [bulkStatus, setBulkStatus] = useState<string>("");

  // ── Fetch list ───────────────────────────────────────────────────────────

  const fetchVulns = useCallback(async () => {
    setIsLoading(true);
    setListError(null);
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(PAGE_SIZE),
      });
      if (filterSeverity) params.set("severity", filterSeverity);
      if (filterStatus) params.set("status", filterStatus);
      const data = await api.get<ListResponse>(`/vulnerabilities?${params}`);
      setVulns(data.items);
      setTotal(data.total);
      // Prune selections that no longer exist on this page.
      setSelected(prev => {
        const next = new Set<string>();
        for (const v of data.items) if (prev.has(v.id)) next.add(v.id);
        return next;
      });
    } catch (e) {
      setListError(e instanceof ApiError ? e.message : "Failed to load findings.");
    } finally {
      setIsLoading(false);
    }
  }, [page, filterSeverity, filterStatus]);

  useEffect(() => { fetchVulns(); }, [fetchVulns]);

  // ── CSV / JSON Upload ────────────────────────────────────────────────────

  async function handleUpload() {
    if (!uploadFile) return;
    setIsUploading(true);
    setUploadError(null);
    setUploadResult(null);
    try {
      const fd = new FormData();
      fd.append("file", uploadFile);
      const endpointMap: Record<string, string> = {
        csv: "/vulnerabilities/ingest/csv",
        json: "/vulnerabilities/ingest/json",
        tenable: "/vulnerabilities/ingest/tenable",
        nessus: "/vulnerabilities/ingest/nessus",
        qualys: "/vulnerabilities/ingest/qualys",
        rapid7: "/vulnerabilities/ingest/rapid7",
      };
      const endpoint = endpointMap[uploadFormat] ?? "/vulnerabilities/ingest/csv";
      const token = await getValidToken();
      const res = await fetch(`/api/v1${endpoint}`, {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        credentials: "include",
        body: fd,
      });
      const data = await res.json();
      if (!res.ok) {
        throw new ApiError(res.status, data.detail ?? "Upload failed.");
      }
      setUploadResult(data as IngestionResult);
      if (data.ingested > 0) fetchVulns();
    } catch (e) {
      setUploadError(e instanceof ApiError ? e.message : "Upload failed.");
    } finally {
      setIsUploading(false);
    }
  }

  function resetUpload() {
    setUploadFile(null);
    setUploadResult(null);
    setUploadError(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  // ── Manual Add ───────────────────────────────────────────────────────────

  async function handleAdd() {
    setIsAdding(true);
    setAddError(null);
    try {
      const payload: Record<string, unknown> = {
        cve_id: form.cve_id.trim(),
        title: form.title.trim(),
        description: form.description.trim(),
        severity: form.severity,
        source: form.source,
        status: "open",
      };
      if (form.affected_component.trim()) payload.affected_component = form.affected_component.trim();
      if (form.notes.trim()) payload.notes = form.notes.trim();
      if (form.cvss_score.trim()) payload.cvss_score = parseFloat(form.cvss_score);
      await api.post("/vulnerabilities/", payload);
      setAddOpen(false);
      setForm(EMPTY_FORM);
      fetchVulns();
    } catch (e) {
      setAddError(e instanceof ApiError ? e.message : "Failed to add finding.");
    } finally {
      setIsAdding(false);
    }
  }

  // ── Bulk actions across the whole org ────────────────────────────────────

  async function handleEnrichAll() {
    setEnriching(true);
    setBulkMsg(null);
    try {
      const r = await api.post<{ enriched: number; errors: string[] }>("/vulnerabilities/enrich");
      setBulkMsg(`Enriched ${r.enriched} finding${r.enriched !== 1 ? "s" : ""}.${r.errors.length ? ` (${r.errors.length} errors)` : ""}`);
      fetchVulns();
    } catch (e) {
      setBulkMsg(e instanceof ApiError ? e.message : "Enrichment failed.");
    } finally {
      setEnriching(false);
    }
  }

  async function handleScoreAll() {
    setScoring(true);
    setBulkMsg(null);
    try {
      const r = await api.post<{ scored: number; errors: string[] }>("/vulnerabilities/score");
      setBulkMsg(`Scored ${r.scored} finding${r.scored !== 1 ? "s" : ""}.${r.errors.length ? ` (${r.errors.length} errors)` : ""}`);
      fetchVulns();
    } catch (e) {
      setBulkMsg(e instanceof ApiError ? e.message : "Scoring failed. Make sure an LLM is configured in Org Settings.");
    } finally {
      setScoring(false);
    }
  }

  // ── Row actions ──────────────────────────────────────────────────────────

  async function enrichRow(id: string) {
    setRowAction(r => ({ ...r, [id]: "enriching" }));
    try {
      await api.post(`/vulnerabilities/${id}/enrich`);
      fetchVulns();
    } finally {
      setRowAction(r => { const n = { ...r }; delete n[id]; return n; });
    }
  }

  async function scoreRow(id: string) {
    setRowAction(r => ({ ...r, [id]: "scoring" }));
    try {
      await api.post(`/vulnerabilities/${id}/score`);
      fetchVulns();
    } catch (e) {
      setBulkMsg(e instanceof ApiError ? e.message : "Score failed.");
    } finally {
      setRowAction(r => { const n = { ...r }; delete n[id]; return n; });
    }
  }

  async function deleteRow(id: string, cve: string) {
    if (!confirm(`Delete ${cve}? This cannot be undone.`)) return;
    setRowAction(r => ({ ...r, [id]: "deleting" }));
    try {
      await api.delete(`/vulnerabilities/${id}`);
      fetchVulns();
    } finally {
      setRowAction(r => { const n = { ...r }; delete n[id]; return n; });
    }
  }

  // Inline status update — analysts & admins can change a row's status.
  async function updateRowStatus(id: string, newStatus: string) {
    // Optimistic update so the select doesn't snap back before the call returns.
    setVulns(prev => prev.map(v => v.id === id ? { ...v, status: newStatus } : v));
    setRowAction(r => ({ ...r, [id]: "updating" }));
    setBulkMsg(null);
    try {
      await api.patch(`/vulnerabilities/${id}`, { status: newStatus });
    } catch (e) {
      setBulkMsg(e instanceof ApiError ? e.message : "Status update failed.");
      // Roll back on error.
      fetchVulns();
    } finally {
      setRowAction(r => { const n = { ...r }; delete n[id]; return n; });
    }
  }

  // ── Bulk actions for selected rows ───────────────────────────────────────

  const selectedIds = useMemo(() => Array.from(selected), [selected]);
  const allOnPageSelected =
    vulns.length > 0 && vulns.every(v => selected.has(v.id));
  const someOnPageSelected = vulns.some(v => selected.has(v.id));

  function toggleSelectAll() {
    setSelected(prev => {
      const next = new Set(prev);
      if (allOnPageSelected) {
        for (const v of vulns) next.delete(v.id);
      } else {
        for (const v of vulns) next.add(v.id);
      }
      return next;
    });
  }

  function toggleSelect(id: string) {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function clearSelection() {
    setSelected(new Set());
  }

  async function bulkUpdateStatus(newStatus: string) {
    if (selectedIds.length === 0 || !newStatus) return;
    setBulkBusy("status");
    setBulkMsg(null);
    const errors: string[] = [];
    // Sequential so partial failures don't leave orphaned in-progress rows.
    for (const id of selectedIds) {
      try {
        await api.patch(`/vulnerabilities/${id}`, { status: newStatus });
      } catch (e) {
        const vuln = vulns.find(v => v.id === id);
        errors.push(`${vuln?.cve_id ?? id}: ${e instanceof ApiError ? e.message : "failed"}`);
      }
    }
    setBulkBusy(null);
    setBulkStatus("");
    const successCount = selectedIds.length - errors.length;
    setBulkMsg(
      `${successCount} updated to "${STATUS_OPTIONS.find(s => s.value === newStatus)?.label ?? newStatus}"${errors.length ? ` · ${errors.length} failed` : ""}`,
    );
    clearSelection();
    fetchVulns();
  }

  async function bulkDelete() {
    if (selectedIds.length === 0) return;
    if (!confirm(`Delete ${selectedIds.length} finding${selectedIds.length !== 1 ? "s" : ""}? This cannot be undone.`)) return;
    setBulkBusy("delete");
    setBulkMsg(null);
    const errors: string[] = [];
    for (const id of selectedIds) {
      try {
        await api.delete(`/vulnerabilities/${id}`);
      } catch (e) {
        const vuln = vulns.find(v => v.id === id);
        errors.push(`${vuln?.cve_id ?? id}: ${e instanceof ApiError ? e.message : "failed"}`);
      }
    }
    setBulkBusy(null);
    const successCount = selectedIds.length - errors.length;
    setBulkMsg(`${successCount} deleted${errors.length ? ` · ${errors.length} failed` : ""}`);
    clearSelection();
    fetchVulns();
  }

  async function bulkEnrichSelected() {
    if (selectedIds.length === 0) return;
    setBulkBusy("enrich");
    setBulkMsg(null);
    const errors: string[] = [];
    for (const id of selectedIds) {
      try {
        await api.post(`/vulnerabilities/${id}/enrich`);
      } catch (e) {
        errors.push(`${id}: ${e instanceof ApiError ? e.message : "failed"}`);
      }
    }
    setBulkBusy(null);
    setBulkMsg(`Enriched ${selectedIds.length - errors.length} finding${selectedIds.length - errors.length !== 1 ? "s" : ""}${errors.length ? ` · ${errors.length} failed` : ""}`);
    clearSelection();
    fetchVulns();
  }

  async function bulkScoreSelected() {
    if (selectedIds.length === 0) return;
    setBulkBusy("score");
    setBulkMsg(null);
    const errors: string[] = [];
    for (const id of selectedIds) {
      try {
        await api.post(`/vulnerabilities/${id}/score`);
      } catch (e) {
        errors.push(`${id}: ${e instanceof ApiError ? e.message : "failed"}`);
      }
    }
    setBulkBusy(null);
    const successCount = selectedIds.length - errors.length;
    setBulkMsg(
      `Scored ${successCount} finding${successCount !== 1 ? "s" : ""}${errors.length ? ` · ${errors.length} failed (check that an LLM is configured)` : ""}`,
    );
    clearSelection();
    fetchVulns();
  }

  function toggleExpanded(id: string) {
    setExpanded(e => ({ ...e, [id]: !e[id] }));
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-muted/20">
      {/* Nav */}
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground text-sm">
              <ChevronLeft className="h-4 w-4" /> Dashboard
            </Link>
            <span className="text-muted-foreground">/</span>
            <span className="font-semibold text-sm flex items-center gap-1.5">
              <ShieldAlert className="h-4 w-4 text-primary" /> Vulnerability Queue
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-muted-foreground">{total} total findings</span>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-6 space-y-4">

        {/* Action bar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Upload dialog trigger */}
          <Dialog.Root open={uploadOpen} onOpenChange={o => { setUploadOpen(o); if (!o) resetUpload(); }}>
            <Dialog.Trigger asChild>
              <Button size="sm"><Upload className="h-4 w-4 mr-1.5" /> Upload CSV / JSON</Button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
              <Dialog.Content className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-full max-w-md rounded-lg border bg-background p-6 shadow-xl focus:outline-none">
                <div className="flex items-center justify-between mb-4">
                  <Dialog.Title className="font-semibold text-base">Upload findings</Dialog.Title>
                  <Dialog.Close asChild>
                    <button className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
                  </Dialog.Close>
                </div>

                <div className="space-y-4">
                  {/* Format selector — two rows */}
                  <div className="space-y-1.5">
                    <p className="text-xs text-muted-foreground font-medium">Native format</p>
                    <div className="flex gap-2">
                      {(["csv", "json"] as const).map(f => (
                        <button key={f} onClick={() => { setUploadFormat(f); resetUpload(); }}
                          className={`flex-1 rounded border py-1.5 text-sm font-medium transition-colors ${uploadFormat === f ? "border-primary bg-primary/5 text-primary" : "text-muted-foreground hover:border-muted-foreground"}`}>
                          {f.toUpperCase()}
                        </button>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground font-medium pt-1">Scanner export</p>
                    <div className="grid grid-cols-4 gap-2">
                      {(["tenable", "nessus", "qualys", "rapid7"] as const).map(f => (
                        <button key={f} onClick={() => { setUploadFormat(f); resetUpload(); }}
                          className={`rounded border py-1.5 text-xs font-medium transition-colors ${uploadFormat === f ? "border-primary bg-primary/5 text-primary" : "text-muted-foreground hover:border-muted-foreground"}`}>
                          {f.charAt(0).toUpperCase() + f.slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>

                  {uploadFormat === "csv" && (
                    <p className="text-xs text-muted-foreground">
                      Required columns: <code className="bg-muted px-1 rounded">cve_id, title, description, severity</code><br />
                      Optional: <code className="bg-muted px-1 rounded">affected_component, cvss_score, epss_score, notes, source_id</code>
                    </p>
                  )}
                  {uploadFormat === "json" && (
                    <p className="text-xs text-muted-foreground">
                      JSON array of objects with the same fields as CSV.
                    </p>
                  )}
                  {uploadFormat === "tenable" && (
                    <p className="text-xs text-muted-foreground">
                      Tenable.io / Tenable.sc CSV export. Rows without a CVE ID (non-CVE plugins) are skipped.
                    </p>
                  )}
                  {uploadFormat === "nessus" && (
                    <p className="text-xs text-muted-foreground">
                      Nessus Professional / Tenable.sc <code className="bg-muted px-1 rounded">.nessus</code> XML file. Each ReportItem with a CVE becomes one finding.
                    </p>
                  )}
                  {uploadFormat === "qualys" && (
                    <p className="text-xs text-muted-foreground">
                      Qualys VMDR CSV export. Findings without a CVE ID (QID-only) are skipped.
                    </p>
                  )}
                  {uploadFormat === "rapid7" && (
                    <p className="text-xs text-muted-foreground">
                      Rapid7 InsightVM / Nexpose vulnerability CSV export. Rows without a CVE ID are skipped.
                    </p>
                  )}

                  <div>
                    <Label htmlFor="upload-file" className="text-sm mb-1 block">Select file</Label>
                    <input
                      ref={fileInputRef}
                      id="upload-file"
                      type="file"
                      accept={uploadFormat === "json" ? ".json,application/json" : uploadFormat === "nessus" ? ".nessus,.xml,text/xml" : ".csv,text/csv"}
                      onChange={e => { setUploadFile(e.target.files?.[0] ?? null); setUploadResult(null); setUploadError(null); }}
                      className="block w-full text-sm text-muted-foreground file:mr-3 file:rounded file:border-0 file:bg-primary/10 file:px-3 file:py-1 file:text-xs file:font-medium file:text-primary hover:file:bg-primary/20"
                    />
                  </div>

                  {uploadError && (
                    <Alert variant="destructive"><AlertDescription>{uploadError}</AlertDescription></Alert>
                  )}

                  {uploadResult && (
                    <div className="rounded border bg-muted/40 p-3 text-sm space-y-1">
                      <p className="font-medium text-green-700">✓ Upload complete</p>
                      <p>Ingested: <strong>{uploadResult.ingested}</strong> &nbsp;|&nbsp; Duplicates skipped: <strong>{uploadResult.duplicates}</strong></p>
                      {uploadResult.errors.length > 0 && (
                        <div className="mt-2">
                          <p className="text-destructive text-xs font-medium">{uploadResult.errors.length} row error{uploadResult.errors.length !== 1 ? "s" : ""}:</p>
                          <ul className="mt-1 space-y-0.5 max-h-32 overflow-y-auto">
                            {uploadResult.errors.map((e, i) => (
                              <li key={i} className="text-xs text-muted-foreground">Row {e.row}{e.cve_id ? ` (${e.cve_id})` : ""}: {e.error}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  <Button className="w-full" disabled={!uploadFile || isUploading} onClick={handleUpload}>
                    {isUploading ? <><Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> Uploading…</> : `Import ${uploadFormat.charAt(0).toUpperCase() + uploadFormat.slice(1)}`}
                  </Button>
                </div>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>

          {/* Manual add dialog */}
          <Dialog.Root open={addOpen} onOpenChange={o => { setAddOpen(o); if (!o) { setForm(EMPTY_FORM); setAddError(null); } }}>
            <Dialog.Trigger asChild>
              <Button size="sm" variant="outline"><Plus className="h-4 w-4 mr-1.5" /> Add manually</Button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
              <Dialog.Content className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg rounded-lg border bg-background p-6 shadow-xl focus:outline-none max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between mb-4">
                  <Dialog.Title className="font-semibold text-base">Add finding manually</Dialog.Title>
                  <Dialog.Close asChild>
                    <button className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
                  </Dialog.Close>
                </div>
                <div className="space-y-3">
                  {addError && <Alert variant="destructive"><AlertDescription>{addError}</AlertDescription></Alert>}

                  <div className="grid grid-cols-2 gap-3">
                    <div className="col-span-2 space-y-1">
                      <Label htmlFor="cve_id" className="text-xs">CVE ID *</Label>
                      <Input id="cve_id" placeholder="CVE-2024-12345" value={form.cve_id}
                        onChange={e => setForm(f => ({ ...f, cve_id: e.target.value }))} />
                    </div>
                    <div className="col-span-2 space-y-1">
                      <Label htmlFor="title" className="text-xs">Title *</Label>
                      <Input id="title" placeholder="Short description" value={form.title}
                        onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
                    </div>
                    <div className="col-span-2 space-y-1">
                      <Label htmlFor="desc" className="text-xs">Description *</Label>
                      <textarea id="desc" rows={3} value={form.description}
                        onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                        className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring resize-none" />
                    </div>
                    <div className="space-y-1">
                      <Label htmlFor="severity" className="text-xs">Severity *</Label>
                      <select id="severity" value={form.severity}
                        onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                        className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                        {["critical","high","medium","low","informational"].map(s => (
                          <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                        ))}
                      </select>
                    </div>
                    <div className="space-y-1">
                      <Label htmlFor="cvss" className="text-xs">CVSS score</Label>
                      <Input id="cvss" type="number" min={0} max={10} step={0.1} placeholder="e.g. 9.8"
                        value={form.cvss_score} onChange={e => setForm(f => ({ ...f, cvss_score: e.target.value }))} />
                    </div>
                    <div className="col-span-2 space-y-1">
                      <Label htmlFor="component" className="text-xs">Affected component</Label>
                      <Input id="component" placeholder="e.g. OpenSSL 3.0" value={form.affected_component}
                        onChange={e => setForm(f => ({ ...f, affected_component: e.target.value }))} />
                    </div>
                    <div className="col-span-2 space-y-1">
                      <Label htmlFor="notes" className="text-xs">Notes</Label>
                      <textarea id="notes" rows={2} value={form.notes}
                        onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                        className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring resize-none" />
                    </div>
                  </div>

                  <Button className="w-full" disabled={!form.cve_id || !form.title || !form.description || isAdding} onClick={handleAdd}>
                    {isAdding ? <><Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> Saving…</> : "Add finding"}
                  </Button>
                </div>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>

          <div className="flex-1" />

          <Button size="sm" variant="outline" onClick={handleEnrichAll} disabled={enriching || vulns.length === 0}>
            {enriching ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1.5" />}
            Enrich all
          </Button>
          <Button size="sm" variant="outline" onClick={handleScoreAll} disabled={scoring || vulns.length === 0}>
            {scoring ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Zap className="h-4 w-4 mr-1.5" />}
            Score all (AI)
          </Button>
        </div>

        {/* Bulk message */}
        {bulkMsg && (
          <Alert variant="default" className="py-2">
            <AlertDescription className="text-sm flex items-center justify-between">
              {bulkMsg}
              <button onClick={() => setBulkMsg(null)} className="text-muted-foreground hover:text-foreground ml-2"><X className="h-3.5 w-3.5" /></button>
            </AlertDescription>
          </Alert>
        )}

        {/* Filters */}
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-muted-foreground font-medium">Filter:</span>
          <select value={filterSeverity} onChange={e => { setFilterSeverity(e.target.value); setPage(1); }}
            className="h-8 rounded-md border bg-background px-2 text-xs focus:outline-none focus:ring-2 focus:ring-ring">
            <option value="">All severities</option>
            {["critical","high","medium","low","informational"].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
          <select value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1); }}
            className="h-8 rounded-md border bg-background px-2 text-xs focus:outline-none focus:ring-2 focus:ring-ring">
            <option value="">All statuses</option>
            {STATUS_OPTIONS.map(s => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
          {(filterSeverity || filterStatus) && (
            <button onClick={() => { setFilterSeverity(""); setFilterStatus(""); setPage(1); }}
              className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1">
              <X className="h-3 w-3" /> Clear filters
            </button>
          )}
        </div>

        {/* Bulk action toolbar — visible when rows are selected */}
        {selected.size > 0 && canEdit && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-primary/40 bg-primary/5 px-3 py-2">
            <span className="text-xs font-medium text-primary">
              {selected.size} selected
            </span>
            <span className="text-muted-foreground/50">·</span>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-muted-foreground">Set status:</span>
              <select
                value={bulkStatus}
                onChange={e => setBulkStatus(e.target.value)}
                disabled={!!bulkBusy}
                className="h-7 rounded border bg-background px-2 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Choose…</option>
                {STATUS_OPTIONS.map(s => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
              <Button
                size="sm"
                variant="outline"
                className="h-7 px-2 text-xs"
                disabled={!bulkStatus || !!bulkBusy}
                onClick={() => bulkUpdateStatus(bulkStatus)}
              >
                {bulkBusy === "status" ? <Loader2 className="h-3 w-3 animate-spin" /> : "Apply"}
              </Button>
            </div>
            <span className="text-muted-foreground/50">·</span>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-xs"
              disabled={!!bulkBusy}
              onClick={bulkEnrichSelected}
            >
              {bulkBusy === "enrich" ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <RefreshCw className="h-3 w-3 mr-1" />}
              Enrich
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-xs"
              disabled={!!bulkBusy}
              onClick={bulkScoreSelected}
            >
              {bulkBusy === "score" ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Zap className="h-3 w-3 mr-1" />}
              Score
            </Button>
            {isAdmin && (
              <Button
                size="sm"
                variant="outline"
                className="h-7 px-2 text-xs text-destructive hover:text-destructive"
                disabled={!!bulkBusy}
                onClick={bulkDelete}
              >
                {bulkBusy === "delete" ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Trash2 className="h-3 w-3 mr-1" />}
                Delete
              </Button>
            )}
            <div className="flex-1" />
            <button
              onClick={clearSelection}
              className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
              disabled={!!bulkBusy}
            >
              <X className="h-3 w-3" /> Clear
            </button>
          </div>
        )}

        {/* Table */}
        <Card className="overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center py-20 text-muted-foreground text-sm gap-2">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading…
            </div>
          ) : listError ? (
            <div className="flex items-center justify-center py-20 text-destructive text-sm gap-2">
              <AlertTriangle className="h-4 w-4" /> {listError}
            </div>
          ) : vulns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-muted-foreground gap-3">
              <ShieldAlert className="h-10 w-10 opacity-20" />
              <p className="text-sm">No findings yet — upload a CSV or add one manually.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-[57px] z-10 bg-background/95 backdrop-blur-sm">
                  <tr className="border-b bg-muted/60">
                    {canEdit && (
                      <th className="px-3 py-2.5 text-left w-8">
                        <input
                          type="checkbox"
                          aria-label="Select all on page"
                          checked={allOnPageSelected}
                          ref={el => { if (el) el.indeterminate = !allOnPageSelected && someOnPageSelected; }}
                          onChange={toggleSelectAll}
                          className="h-4 w-4 rounded border-muted-foreground/30 accent-primary cursor-pointer"
                        />
                      </th>
                    )}
                    <th className="w-8"></th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground whitespace-nowrap">CVE ID</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground">Title</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground whitespace-nowrap">Severity</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground whitespace-nowrap">Status</th>
                    <th className="px-4 py-2.5 text-center text-xs font-semibold text-muted-foreground whitespace-nowrap">CVSS</th>
                    <th className="px-4 py-2.5 text-center text-xs font-semibold text-muted-foreground whitespace-nowrap">EPSS</th>
                    <th className="px-4 py-2.5 text-center text-xs font-semibold text-muted-foreground whitespace-nowrap">KEV</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground whitespace-nowrap">AI Priority</th>
                    <th className="px-4 py-2.5 text-right text-xs font-semibold text-muted-foreground whitespace-nowrap">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {vulns.map(v => {
                    const isExpanded = !!expanded[v.id];
                    const hasRationale = !!v.score_rationale;
                    const colSpan = canEdit ? 11 : 10;
                    return (
                      <Fragment key={v.id}>
                        <tr className="border-b hover:bg-primary/5 transition-colors">
                          {canEdit && (
                            <td className="px-3 py-3">
                              <input
                                type="checkbox"
                                aria-label={`Select ${v.cve_id}`}
                                checked={selected.has(v.id)}
                                onChange={() => toggleSelect(v.id)}
                                className="h-4 w-4 rounded border-muted-foreground/30 accent-primary cursor-pointer"
                              />
                            </td>
                          )}
                          <td className="px-1 py-3">
                            <button
                              onClick={() => toggleExpanded(v.id)}
                              className="text-muted-foreground hover:text-foreground p-1 rounded hover:bg-muted"
                              title={isExpanded ? "Hide details" : "Show details"}
                              aria-label={isExpanded ? "Collapse row" : "Expand row"}
                            >
                              {isExpanded
                                ? <ChevronUp className="h-4 w-4" />
                                : <ChevronDown className="h-4 w-4" />}
                            </button>
                          </td>
                          <td className="px-4 py-3 font-mono text-xs whitespace-nowrap">{v.cve_id}</td>
                          <td className="px-4 py-3 max-w-[280px]">
                            <p className="font-medium truncate" title={v.title}>{v.title}</p>
                            {v.affected_component && (
                              <p className="text-xs text-muted-foreground truncate">{v.affected_component}</p>
                            )}
                            {v.asset_id && (
                              <Link
                                href="/assets"
                                className="inline-flex items-center gap-1 mt-0.5 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary hover:bg-primary/20 transition-colors"
                                title="Linked to an asset — click to view assets"
                              >
                                <Server className="h-3 w-3 shrink-0" />
                                Linked asset
                              </Link>
                            )}
                            {hasRationale && !isExpanded && (
                              <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1 italic flex items-center gap-1">
                                <Sparkles className="h-3 w-3 text-primary shrink-0" />
                                <span className="truncate">{v.score_rationale}</span>
                              </p>
                            )}
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            <Badge variant={SEVERITY_COLORS[v.severity] as Parameters<typeof Badge>[0]["variant"]} className="gap-1">
                              <span className="text-[8px] leading-none">●</span>
                              {v.severity}
                            </Badge>
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            {canEdit ? (
                              <select
                                value={v.status}
                                onChange={e => updateRowStatus(v.id, e.target.value)}
                                disabled={!!rowAction[v.id]}
                                className="h-7 rounded border bg-background px-2 text-xs focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
                                title="Change status"
                              >
                                {STATUS_OPTIONS.map(s => (
                                  <option key={s.value} value={s.value}>{s.label}</option>
                                ))}
                              </select>
                            ) : (
                              <Badge variant={v.status.replace("-", "_") as Parameters<typeof Badge>[0]["variant"]}>
                                {v.status.replace(/_/g, " ")}
                              </Badge>
                            )}
                          </td>
                          <td className="px-4 py-3 text-center whitespace-nowrap">
                            {v.cvss_score != null ? (
                              <span className={`font-mono text-xs font-semibold ${v.cvss_score >= 9 ? "text-red-600" : v.cvss_score >= 7 ? "text-orange-600" : v.cvss_score >= 4 ? "text-yellow-600" : "text-blue-600"}`}>
                                {v.cvss_score.toFixed(1)}
                              </span>
                            ) : <span className="text-muted-foreground/50 text-xs">—</span>}
                          </td>
                          <td className="px-4 py-3 text-center whitespace-nowrap">
                            {v.epss_score != null ? (
                              <span className={`font-mono text-xs ${v.epss_score >= 0.5 ? "text-red-600 font-semibold" : "text-muted-foreground"}`}>
                                {(v.epss_score * 100).toFixed(1)}%
                              </span>
                            ) : <span className="text-muted-foreground/50 text-xs">—</span>}
                          </td>
                          <td className="px-4 py-3 text-center">
                            {v.kev_listed
                              ? <span className="text-xs font-semibold text-red-600" title="In CISA Known Exploited Vulnerabilities">Yes</span>
                              : <span className="text-xs text-muted-foreground/50">No</span>}
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            {v.triage_priority ? (
                              <Badge variant={v.triage_priority as Parameters<typeof Badge>[0]["variant"]} className="gap-1">
                                <span className="text-[8px] leading-none">●</span>
                                {PRIORITY_LABELS[v.triage_priority] ?? v.triage_priority}
                              </Badge>
                            ) : <span className="text-muted-foreground/50 text-xs">Unscored</span>}
                          </td>
                          <td className="px-4 py-3 text-right whitespace-nowrap">
                            <div className="flex items-center justify-end gap-1">
                              <Link href={`/remediation?vuln_id=${v.id}`} title="Draft remediation ticket">
                                <Button size="sm" variant="ghost" className="h-7 px-2 text-xs" aria-label="Draft remediation ticket">
                                  <FileText className="h-3 w-3" />
                                </Button>
                              </Link>
                              <Button size="sm" variant="ghost" className="h-7 px-2 text-xs"
                                disabled={!!rowAction[v.id]} onClick={() => enrichRow(v.id)}
                                title="Enrich with KEV/EPSS/NVD">
                                {rowAction[v.id] === "enriching"
                                  ? <Loader2 className="h-3 w-3 animate-spin" />
                                  : <RefreshCw className="h-3 w-3" />}
                              </Button>
                              <Button size="sm" variant="ghost" className="h-7 px-2 text-xs"
                                disabled={!!rowAction[v.id]} onClick={() => scoreRow(v.id)}
                                title="Score with AI">
                                {rowAction[v.id] === "scoring"
                                  ? <Loader2 className="h-3 w-3 animate-spin" />
                                  : <Zap className="h-3 w-3" />}
                              </Button>
                              {isAdmin && (
                                <Button size="sm" variant="ghost" className="h-7 px-2 text-xs text-destructive hover:text-destructive"
                                  disabled={!!rowAction[v.id]} onClick={() => deleteRow(v.id, v.cve_id)}
                                  title="Delete">
                                  {rowAction[v.id] === "deleting"
                                    ? <Loader2 className="h-3 w-3 animate-spin" />
                                    : <Trash2 className="h-3 w-3" />}
                                </Button>
                              )}
                            </div>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="border-b bg-muted/10">
                            <td colSpan={colSpan} className="px-6 py-4">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                <div className="space-y-2">
                                  <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Description</h4>
                                  <p className="text-sm whitespace-pre-wrap break-words">
                                    {v.description || <span className="text-muted-foreground italic">No description.</span>}
                                  </p>
                                  {v.published_at && (
                                    <p className="text-xs text-muted-foreground">
                                      Published: {new Date(v.published_at).toLocaleDateString()}
                                    </p>
                                  )}
                                </div>
                                <div className="space-y-2">
                                  <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
                                    <Sparkles className="h-3 w-3 text-primary" />
                                    AI scoring rationale
                                  </h4>
                                  {hasRationale ? (
                                    <div className="rounded-md border bg-background p-3">
                                      <p className="text-sm text-foreground/90 whitespace-pre-wrap">
                                        {v.score_rationale}
                                      </p>
                                      {v.triage_priority && (
                                        <div className="mt-2 pt-2 border-t flex items-center gap-2 text-xs">
                                          <span className="text-muted-foreground">Priority:</span>
                                          <Badge variant={v.triage_priority as Parameters<typeof Badge>[0]["variant"]}>
                                            {PRIORITY_LABELS[v.triage_priority] ?? v.triage_priority}
                                          </Badge>
                                        </div>
                                      )}
                                    </div>
                                  ) : (
                                    <p className="text-sm text-muted-foreground italic">
                                      This finding has not been scored yet. Click the{" "}
                                      <Zap className="inline h-3 w-3 text-primary" /> button to score with AI,
                                      or use “Score all (AI)” above.
                                    </p>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground text-xs">
              Page {page} of {totalPages} &nbsp;·&nbsp; {total} findings
            </span>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button size="sm" variant="outline" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
