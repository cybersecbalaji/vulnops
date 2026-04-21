"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Server, ChevronLeft, Plus, Trash2, X, Upload, Loader2,
  Globe, Shield, ChevronLeft as ChevronPrev, ChevronRight, Link2,
} from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";
import { ThemeToggle } from "@/components/theme-toggle";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Asset {
  id: string;
  name: string;
  asset_type: string;
  criticality: string;
  environment: string;
  internet_facing: boolean;
  ip_address: string | null;
  hostname: string | null;
  fqdn: string | null;
  operating_system: string | null;
  owner: string | null;
  tags: string | null;
  notes: string | null;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

interface AssetListResponse {
  items: Asset[];
  total: number;
  page: number;
  page_size: number;
}

interface ImportResult {
  imported: number;
  updated: number;
  skipped: number;
  errors: { row: number; name: string | null; error: string }[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ASSET_TYPES = [
  { value: "server", label: "Server" },
  { value: "database", label: "Database" },
  { value: "application", label: "Application" },
  { value: "network_device", label: "Network Device" },
  { value: "endpoint", label: "Endpoint" },
  { value: "cloud_service", label: "Cloud Service" },
  { value: "container", label: "Container" },
  { value: "other", label: "Other" },
];

const CRITICALITY_LEVELS = ["critical", "high", "medium", "low"];
const ENVIRONMENT_LEVELS = [
  { value: "production", label: "Production" },
  { value: "staging", label: "Staging" },
  { value: "development", label: "Development" },
  { value: "other", label: "Other" },
];

const critColors: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const PAGE_SIZE = 25;

const EMPTY_FORM = {
  name: "",
  asset_type: "server",
  criticality: "medium",
  environment: "production",
  internet_facing: false,
  ip_address: "",
  hostname: "",
  fqdn: "",
  operating_system: "",
  owner: "",
  tags: "",
  notes: "",
};

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AssetsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const canEdit = user?.role === "admin" || user?.role === "analyst";

  const [assets, setAssets] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);

  // Add asset dialog
  const [addOpen, setAddOpen] = useState(false);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [addError, setAddError] = useState<string | null>(null);
  const [isAdding, setIsAdding] = useState(false);

  // Import dialog
  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [isImporting, setIsImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Match vulnerabilities
  const [isMatchingVulns, setIsMatchingVulns] = useState(false);

  // Status banner
  const [msg, setMsg] = useState<string | null>(null);

  // ── Fetch ──────────────────────────────────────────────────────────────────

  const fetchAssets = useCallback(async () => {
    setIsLoading(true);
    setListError(null);
    try {
      const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
      const data = await api.get<AssetListResponse>(`/assets?${params}`);
      setAssets(data.items);
      setTotal(data.total);
    } catch (e) {
      setListError(e instanceof ApiError ? e.message : "Failed to load assets.");
    } finally {
      setIsLoading(false);
    }
  }, [page]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  // ── Add asset ─────────────────────────────────────────────────────────────

  async function handleAdd() {
    setIsAdding(true);
    setAddError(null);
    try {
      const payload: Record<string, unknown> = {
        name: form.name.trim(),
        asset_type: form.asset_type,
        criticality: form.criticality,
        environment: form.environment,
        internet_facing: form.internet_facing,
      };
      if (form.ip_address.trim()) payload.ip_address = form.ip_address.trim();
      if (form.hostname.trim()) payload.hostname = form.hostname.trim();
      if (form.fqdn.trim()) payload.fqdn = form.fqdn.trim();
      if (form.operating_system.trim()) payload.operating_system = form.operating_system.trim();
      if (form.owner.trim()) payload.owner = form.owner.trim();
      if (form.tags.trim()) payload.tags = form.tags.trim();
      if (form.notes.trim()) payload.notes = form.notes.trim();

      await api.post("/assets/", payload);
      setAddOpen(false);
      setForm({ ...EMPTY_FORM });
      setMsg("Asset added.");
      setTimeout(() => setMsg(null), 3000);
      fetchAssets();
    } catch (e) {
      setAddError(e instanceof ApiError ? e.message : "Failed to add asset.");
    } finally {
      setIsAdding(false);
    }
  }

  // ── Import CSV ────────────────────────────────────────────────────────────

  async function handleImport() {
    if (!importFile) return;
    setIsImporting(true);
    setImportError(null);
    setImportResult(null);
    try {
      const fd = new FormData();
      fd.append("file", importFile);
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL ?? ""}/api/v1/assets/import/csv`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${(await import("@/lib/auth")).getAccessToken() ?? ""}` },
          credentials: "include",
          body: fd,
        },
      );
      const data = await res.json();
      if (!res.ok) throw new ApiError(res.status, data.detail ?? "Import failed.");
      setImportResult(data as ImportResult);
      if (data.imported > 0 || data.updated > 0) fetchAssets();
    } catch (e) {
      setImportError(e instanceof ApiError ? e.message : "Import failed.");
    } finally {
      setIsImporting(false);
    }
  }

  // ── Match vulnerabilities ─────────────────────────────────────────────────

  async function handleMatchVulns() {
    setIsMatchingVulns(true);
    try {
      const data = await api.post<{ matched: number }>("/assets/match-vulnerabilities", {});
      setMsg(
        data.matched > 0
          ? `Matched ${data.matched} vulnerabilit${data.matched === 1 ? "y" : "ies"} to assets.`
          : "No new matches found — all vulnerabilities are already linked or have no matching asset."
      );
      setTimeout(() => setMsg(null), 5000);
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : "Match failed.");
      setTimeout(() => setMsg(null), 5000);
    } finally {
      setIsMatchingVulns(false);
    }
  }

  // ── Delete ────────────────────────────────────────────────────────────────

  async function deleteAsset(id: string, name: string) {
    if (!confirm(`Delete asset "${name}"? This cannot be undone.`)) return;
    try {
      await api.delete(`/assets/${id}`);
      setMsg("Asset deleted.");
      setTimeout(() => setMsg(null), 3000);
      fetchAssets();
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : "Delete failed.");
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-muted/20">
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground text-sm">
              <ChevronLeft className="h-4 w-4" /> Dashboard
            </Link>
            <span className="text-muted-foreground">/</span>
            <span className="font-semibold text-sm flex items-center gap-1.5">
              <Server className="h-4 w-4 text-primary" /> Asset Register
            </span>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            {canEdit && (
              <>
                {/* Match vulnerabilities button */}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={handleMatchVulns}
                  disabled={isMatchingVulns || assets.length === 0}
                  title="Auto-link unmatched vulnerabilities to assets by IP or hostname"
                >
                  {isMatchingVulns
                    ? <><Loader2 className="h-4 w-4 mr-1.5 animate-spin" />Matching…</>
                    : <><Link2 className="h-4 w-4 mr-1.5" />Match vulnerabilities</>}
                </Button>

                {/* Import dialog */}
                <Dialog.Root open={importOpen} onOpenChange={o => { setImportOpen(o); if (!o) { setImportFile(null); setImportResult(null); setImportError(null); if (fileInputRef.current) fileInputRef.current.value = ""; } }}>
                  <Dialog.Trigger asChild>
                    <Button size="sm" variant="outline"><Upload className="h-4 w-4 mr-1.5" /> Import CSV</Button>
                  </Dialog.Trigger>
                  <Dialog.Portal>
                    <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
                    <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border bg-background p-6 shadow-xl">
                      <div className="flex items-center justify-between mb-4">
                        <Dialog.Title className="text-base font-semibold">Import assets from CSV</Dialog.Title>
                        <Dialog.Close asChild>
                          <button className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
                        </Dialog.Close>
                      </div>
                      <div className="space-y-4">
                        <div className="rounded-md bg-muted/40 border p-3 text-xs text-muted-foreground space-y-1">
                          <p className="font-medium text-foreground">Supported formats (auto-detected):</p>
                          <ul className="list-disc list-inside space-y-0.5">
                            <li><strong>VulnOps generic</strong> — name, ip_address, hostname, asset_type, criticality…</li>
                            <li><strong>Qualys CMDB</strong> — IP, DNS, NetBIOS, OS, Tracking Method</li>
                            <li><strong>ServiceNow CMDB</strong> — u_ip_address, u_name, sys_class_name, u_environment</li>
                            <li><strong>Rapid7 InsightVM</strong> — Asset IP Address, Asset Name, Asset OS Name</li>
                            <li><strong>Microsoft Intune</strong> — Device name, Serial number, Primary user UPN</li>
                            <li><strong>Microsoft SCCM</strong> — NetBIOS Name, IP Addresses, Resource Domain</li>
                            <li><strong>Axonius</strong> — Name, Hostname, Network Interfaces: IPs, OS.Type</li>
                            <li><strong>CrowdStrike Falcon</strong> — Hostname, Local IP, Device ID, Platform Name</li>
                          </ul>
                          <p className="mt-1">Assets are upserted by IP / hostname — no duplicates across runs.</p>
                        </div>
                        <div>
                          <Label htmlFor="import-file" className="text-xs mb-1 block">Select CSV file</Label>
                          <input
                            ref={fileInputRef}
                            id="import-file"
                            type="file"
                            accept=".csv,text/csv"
                            onChange={e => { setImportFile(e.target.files?.[0] ?? null); setImportResult(null); setImportError(null); }}
                            className="block w-full text-sm text-muted-foreground file:mr-3 file:rounded file:border-0 file:bg-primary/10 file:px-3 file:py-1 file:text-xs file:font-medium file:text-primary hover:file:bg-primary/20"
                          />
                        </div>
                        {importError && <Alert variant="destructive"><AlertDescription>{importError}</AlertDescription></Alert>}
                        {importResult && (
                          <div className="rounded border bg-muted/40 p-3 text-sm space-y-1">
                            <p className="font-medium text-green-700">✓ Import complete</p>
                            <p>Created: <strong>{importResult.imported}</strong> &nbsp;·&nbsp; Updated: <strong>{importResult.updated}</strong> &nbsp;·&nbsp; Skipped: <strong>{importResult.skipped}</strong></p>
                            {importResult.errors.length > 0 && (
                              <div className="mt-2">
                                <p className="text-destructive text-xs font-medium">{importResult.errors.length} row error{importResult.errors.length !== 1 ? "s" : ""}:</p>
                                <ul className="mt-1 space-y-0.5 max-h-28 overflow-y-auto">
                                  {importResult.errors.map((e, i) => (
                                    <li key={i} className="text-xs text-muted-foreground">Row {e.row}: {e.error}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        )}
                        <Button className="w-full" disabled={!importFile || isImporting} onClick={handleImport}>
                          {isImporting ? <><Loader2 className="h-4 w-4 mr-1.5 animate-spin" />Importing…</> : "Import"}
                        </Button>
                      </div>
                    </Dialog.Content>
                  </Dialog.Portal>
                </Dialog.Root>

                {/* Add asset dialog */}
                <Dialog.Root open={addOpen} onOpenChange={o => { setAddOpen(o); if (!o) { setForm({ ...EMPTY_FORM }); setAddError(null); } }}>
                  <Dialog.Trigger asChild>
                    <Button size="sm"><Plus className="h-4 w-4 mr-1.5" /> Add asset</Button>
                  </Dialog.Trigger>
                  <Dialog.Portal>
                    <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
                    <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border bg-background p-6 shadow-xl max-h-[90vh] overflow-y-auto">
                      <div className="flex items-center justify-between mb-4">
                        <Dialog.Title className="text-base font-semibold">Add asset</Dialog.Title>
                        <Dialog.Close asChild>
                          <button className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
                        </Dialog.Close>
                      </div>
                      {addError && <Alert variant="destructive" className="mb-3"><AlertDescription>{addError}</AlertDescription></Alert>}
                      <div className="space-y-3">
                        {/* Name */}
                        <div>
                          <Label htmlFor="a-name" className="text-xs">Asset name *</Label>
                          <Input id="a-name" placeholder="e.g. prod-db-01, Customer Portal" value={form.name}
                            onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="mt-1" />
                        </div>

                        {/* Network identity */}
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <Label htmlFor="a-ip" className="text-xs">IP address</Label>
                            <Input id="a-ip" placeholder="192.168.1.10" value={form.ip_address}
                              onChange={e => setForm(f => ({ ...f, ip_address: e.target.value }))} className="mt-1" />
                          </div>
                          <div>
                            <Label htmlFor="a-host" className="text-xs">Hostname</Label>
                            <Input id="a-host" placeholder="prod-db-01" value={form.hostname}
                              onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))} className="mt-1" />
                          </div>
                          <div className="col-span-2">
                            <Label htmlFor="a-fqdn" className="text-xs">FQDN</Label>
                            <Input id="a-fqdn" placeholder="prod-db-01.example.com" value={form.fqdn}
                              onChange={e => setForm(f => ({ ...f, fqdn: e.target.value }))} className="mt-1" />
                          </div>
                        </div>

                        {/* Classification */}
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <Label htmlFor="a-type" className="text-xs">Type</Label>
                            <select id="a-type" value={form.asset_type}
                              onChange={e => setForm(f => ({ ...f, asset_type: e.target.value }))}
                              className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                              {ASSET_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                            </select>
                          </div>
                          <div>
                            <Label htmlFor="a-crit" className="text-xs">Criticality</Label>
                            <select id="a-crit" value={form.criticality}
                              onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))}
                              className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                              {CRITICALITY_LEVELS.map(l => <option key={l} value={l}>{l.charAt(0).toUpperCase() + l.slice(1)}</option>)}
                            </select>
                          </div>
                          <div>
                            <Label htmlFor="a-env" className="text-xs">Environment</Label>
                            <select id="a-env" value={form.environment}
                              onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}
                              className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring">
                              {ENVIRONMENT_LEVELS.map(e => <option key={e.value} value={e.value}>{e.label}</option>)}
                            </select>
                          </div>
                          <div className="flex items-end pb-1">
                            <label className="flex items-center gap-2 cursor-pointer text-sm">
                              <input type="checkbox" checked={form.internet_facing}
                                onChange={e => setForm(f => ({ ...f, internet_facing: e.target.checked }))}
                                className="h-4 w-4 rounded border-muted-foreground/30 accent-primary" />
                              <span>Internet-facing</span>
                            </label>
                          </div>
                        </div>

                        {/* Additional context */}
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <Label htmlFor="a-os" className="text-xs">Operating system</Label>
                            <Input id="a-os" placeholder="Ubuntu 22.04 LTS" value={form.operating_system}
                              onChange={e => setForm(f => ({ ...f, operating_system: e.target.value }))} className="mt-1" />
                          </div>
                          <div>
                            <Label htmlFor="a-owner" className="text-xs">Owner / team</Label>
                            <Input id="a-owner" placeholder="Platform team" value={form.owner}
                              onChange={e => setForm(f => ({ ...f, owner: e.target.value }))} className="mt-1" />
                          </div>
                          <div className="col-span-2">
                            <Label htmlFor="a-tags" className="text-xs">Tags (comma-separated)</Label>
                            <Input id="a-tags" placeholder="pci-scope, dmz, tier-1" value={form.tags}
                              onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} className="mt-1" />
                          </div>
                          <div className="col-span-2">
                            <Label htmlFor="a-notes" className="text-xs">Notes</Label>
                            <Input id="a-notes" placeholder="Any relevant context" value={form.notes}
                              onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} className="mt-1" />
                          </div>
                        </div>
                      </div>
                      <div className="flex justify-end gap-2 mt-5">
                        <Dialog.Close asChild>
                          <Button variant="outline" size="sm">Cancel</Button>
                        </Dialog.Close>
                        <Button size="sm" onClick={handleAdd} disabled={!form.name.trim() || isAdding}>
                          {isAdding ? <><Loader2 className="h-4 w-4 mr-1.5 animate-spin" />Saving…</> : "Add asset"}
                        </Button>
                      </div>
                    </Dialog.Content>
                  </Dialog.Portal>
                </Dialog.Root>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8 space-y-6">
        <div>
          <h1 className="text-xl font-bold">Asset Register</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Track business assets with network identity, environment, and criticality.
            Asset context is used by the AI scoring agent to weight vulnerability priority.
          </p>
        </div>

        {msg && (
          <Alert className="py-2">
            <AlertDescription className="text-sm flex items-center justify-between">
              {msg}
              <button onClick={() => setMsg(null)} className="text-muted-foreground hover:text-foreground ml-2"><X className="h-3.5 w-3.5" /></button>
            </AlertDescription>
          </Alert>
        )}

        {isLoading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground text-sm gap-2">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading…
          </div>
        ) : listError ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-20 text-destructive gap-3">
              <p className="text-sm">{listError}</p>
              <Button size="sm" variant="outline" onClick={fetchAssets}>Retry</Button>
            </CardContent>
          </Card>
        ) : assets.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-20 gap-4 text-muted-foreground">
              <Server className="h-10 w-10 opacity-20" />
              <p className="text-sm">No assets registered yet.</p>
              <p className="text-xs max-w-sm text-center">
                Add assets manually or import from Qualys CMDB, ServiceNow, or Rapid7 InsightVM CSV exports.
              </p>
              {canEdit && (
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => setImportOpen(true)}>
                    <Upload className="h-4 w-4 mr-1.5" /> Import CSV
                  </Button>
                  <Button size="sm" onClick={() => setAddOpen(true)}>
                    <Plus className="h-4 w-4 mr-1.5" /> Add first asset
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        ) : (
          <Card className="overflow-hidden">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                  <CardTitle className="text-sm">{total} asset{total !== 1 ? "s" : ""} registered</CardTitle>
                  <CardDescription className="text-xs mt-0.5">
                    Criticality, environment, and internet-facing status are used by the AI triage agent.
                  </CardDescription>
                </div>
                {/* Criticality summary pills */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  {(["critical", "high", "medium", "low"] as const).map(level => {
                    const count = assets.filter(a => a.criticality === level).length;
                    const colors: Record<string, string> = {
                      critical: "bg-red-100 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-400 dark:border-red-900",
                      high: "bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-950/50 dark:text-orange-400 dark:border-orange-900",
                      medium: "bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-950/50 dark:text-yellow-400 dark:border-yellow-900",
                      low: "bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-400 dark:border-blue-900",
                    };
                    return (
                      <span key={level} className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium ${colors[level]}`}>
                        {level.charAt(0).toUpperCase() + level.slice(1)}: {count}
                      </span>
                    );
                  })}
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b bg-muted/40">
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Name</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground whitespace-nowrap">IP / Host</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Type</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Criticality</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Environment</th>
                      <th className="px-4 py-2.5 text-center text-xs font-medium text-muted-foreground whitespace-nowrap">Internet-facing</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">OS</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Owner</th>
                      {canEdit && (
                        <th className="px-4 py-2.5 text-right text-xs font-medium text-muted-foreground">Actions</th>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {assets.map(a => (
                      <tr key={a.id} className="border-b last:border-0 hover:bg-muted/20 transition-colors">
                        <td className="px-4 py-3 font-medium max-w-[160px] truncate" title={a.name}>{a.name}</td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="font-mono text-xs">
                            {a.ip_address && <div>{a.ip_address}</div>}
                            {a.hostname && <div className="text-muted-foreground">{a.hostname}</div>}
                            {!a.ip_address && !a.hostname && <span className="text-muted-foreground/50">—</span>}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground capitalize">
                          {a.asset_type.replace(/_/g, " ")}
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant={critColors[a.criticality] as Parameters<typeof Badge>[0]["variant"]}>
                            {a.criticality}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground capitalize">
                          {a.environment}
                        </td>
                        <td className="px-4 py-3 text-center">
                          {a.internet_facing
                            ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-orange-600"><Globe className="h-3 w-3" />Yes</span>
                            : <span className="text-xs text-muted-foreground/50">No</span>}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground max-w-[140px] truncate" title={a.operating_system ?? ""}>
                          {a.operating_system || "—"}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground max-w-[120px] truncate" title={a.owner ?? ""}>
                          {a.owner || "—"}
                        </td>
                        {canEdit && (
                          <td className="px-4 py-3 text-right">
                            {isAdmin && (
                              <Button size="sm" variant="ghost"
                                className="h-7 px-2 text-xs text-destructive hover:text-destructive"
                                onClick={() => deleteAsset(a.id, a.name)}>
                                <Trash2 className="h-3 w-3" />
                              </Button>
                            )}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground text-xs">
              Page {page} of {totalPages} &nbsp;·&nbsp; {total} assets
            </span>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>
                <ChevronPrev className="h-4 w-4" />
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
