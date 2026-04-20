"use client";

import { type ElementType, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  BarChart3, ChevronLeft, Download, RefreshCw, Loader2,
  ShieldAlert, Bug, AlertTriangle,
} from "lucide-react";
import { getAccessToken } from "@/lib/auth";
import { ThemeToggle } from "@/components/theme-toggle";

interface DashboardStats {
  total: number;
  duplicate_count: number;
  kev_count: number;
  scored_count: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];
const PRIORITY_LABELS: Record<string, string> = {
  immediate: "Immediate",
  this_week: "This week",
  this_month: "This month",
  monitor: "Monitor",
  accept: "Accept",
};
const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  in_progress: "In progress",
  remediated: "Remediated",
  accepted: "Accepted",
  false_positive: "False positive",
};

export default function ReportsPage() {
  const { user } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  const fetchStats = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.get<DashboardStats>("/reports/dashboard");
      setStats(data);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load report data.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { fetchStats(); }, [fetchStats]);

  async function downloadPDF() {
    setDownloading(true);
    try {
      // Use fetch directly to handle binary response — get token from in-memory store
      const token = getAccessToken();
      const resp = await fetch("/api/v1/reports/dashboard/pdf", {
        credentials: "include",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!resp.ok) throw new Error("Download failed");
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "vulnops-report.pdf";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert("PDF download failed — ensure backend is running.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className="min-h-screen bg-muted/20">
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground text-sm">
              <ChevronLeft className="h-4 w-4" /> Dashboard
            </Link>
            <span className="text-muted-foreground">/</span>
            <span className="font-semibold text-sm flex items-center gap-1.5">
              <BarChart3 className="h-4 w-4 text-primary" /> Reports
            </span>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <Button variant="outline" size="sm" onClick={fetchStats} disabled={isLoading}>
              <RefreshCw className={`h-4 w-4 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button size="sm" onClick={downloadPDF} disabled={downloading || isLoading || !stats}>
              {downloading
                ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
                : <Download className="h-4 w-4 mr-1.5" />}
              Download PDF
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 py-8 space-y-6">
        <div>
          <h1 className="text-xl font-bold">Vulnerability Report</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Board-ready summary of your org&apos;s current vulnerability posture. Data refreshes in real time.
          </p>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20 gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading…
          </div>
        ) : error ? (
          <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
        ) : stats ? (
          <>
            {/* Top-level stats */}
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatCard label="Total Findings" value={stats.total} icon={Bug} />
              <StatCard
                label="KEV Listed"
                value={stats.kev_count}
                icon={ShieldAlert}
                className={stats.kev_count > 0 ? "text-red-600" : ""}
                description="In CISA Known Exploited"
              />
              <StatCard label="AI Scored" value={stats.scored_count} icon={BarChart3} />
              <StatCard label="Duplicates" value={stats.duplicate_count} icon={AlertTriangle} />
            </div>

            {/* By severity */}
            <div className="grid gap-4 sm:grid-cols-3">
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm">By Severity</CardTitle>
                  <CardDescription className="text-xs">Distribution across severity levels</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {SEVERITY_ORDER.map(sev => {
                    const count = stats.by_severity[sev] ?? 0;
                    const pct = stats.total > 0 ? Math.round((count / stats.total) * 100) : 0;
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="capitalize font-medium">{sev}</span>
                          <span className="text-muted-foreground">{count}</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${
                              sev === "critical" ? "bg-red-500" :
                              sev === "high" ? "bg-orange-500" :
                              sev === "medium" ? "bg-yellow-500" :
                              sev === "low" ? "bg-blue-500" : "bg-gray-400"
                            }`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </CardContent>
              </Card>

              {/* By priority */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm">By AI Priority</CardTitle>
                  <CardDescription className="text-xs">Triage priority from AI scoring</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {Object.entries(PRIORITY_LABELS).map(([key, label]) => {
                    const count = stats.by_priority[key] ?? 0;
                    return (
                      <div key={key} className="flex items-center justify-between text-xs">
                        <span>{label}</span>
                        <span className={`font-semibold ${
                          key === "immediate" ? "text-red-600" :
                          key === "this_week" ? "text-orange-600" :
                          key === "this_month" ? "text-yellow-600" : "text-muted-foreground"
                        }`}>{count}</span>
                      </div>
                    );
                  })}
                  <div className="flex items-center justify-between text-xs pt-1 border-t">
                    <span className="text-muted-foreground">Unscored</span>
                    <span className="text-muted-foreground">
                      {stats.total - stats.scored_count}
                    </span>
                  </div>
                </CardContent>
              </Card>

              {/* By status */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm">By Status</CardTitle>
                  <CardDescription className="text-xs">Remediation workflow progress</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {Object.entries(STATUS_LABELS).map(([key, label]) => {
                    const count = stats.by_status[key] ?? 0;
                    return (
                      <div key={key} className="flex items-center justify-between text-xs">
                        <span>{label}</span>
                        <span className={`font-semibold ${
                          key === "remediated" ? "text-green-600" :
                          key === "open" ? "text-slate-600" : "text-muted-foreground"
                        }`}>{count}</span>
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            </div>

            {/* Summary text */}
            {stats.total === 0 ? (
              <Alert>
                <AlertDescription className="text-sm">
                  No findings yet. Upload a CSV or add findings manually in the{" "}
                  <Link href="/findings" className="underline">Vulnerability Queue</Link>.
                </AlertDescription>
              </Alert>
            ) : (
              <Card className="bg-muted/40">
                <CardContent className="pt-4">
                  <p className="text-sm text-muted-foreground">
                    <span className="font-semibold text-foreground">{user?.email?.split("@")[0]}</span>
                    &apos;s org has{" "}
                    <span className="font-semibold text-foreground">{stats.total}</span> finding{stats.total !== 1 ? "s" : ""}.
                    {stats.kev_count > 0 && (
                      <span className="text-red-600 font-medium">
                        {" "}{stats.kev_count} {stats.kev_count === 1 ? "is" : "are"} in the CISA KEV catalog — act immediately.
                      </span>
                    )}
                    {(stats.by_priority["immediate"] ?? 0) > 0 && (
                      <span>
                        {" "}{stats.by_priority["immediate"]} AI-scored finding{(stats.by_priority["immediate"] ?? 0) !== 1 ? "s" : ""} require{(stats.by_priority["immediate"] ?? 0) === 1 ? "s" : ""} immediate action.
                      </span>
                    )}
                  </p>
                </CardContent>
              </Card>
            )}
          </>
        ) : null}
      </main>
    </div>
  );
}

function StatCard({
  label, value, icon: Icon, className = "", description,
}: {
  label: string; value: number; icon: ElementType;
  className?: string; description?: string;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${className}`}>{value}</div>
        {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
      </CardContent>
    </Card>
  );
}
