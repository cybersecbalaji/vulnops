"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ShieldAlert,
  Bug,
  Server,
  BarChart3,
  LogOut,
  Settings,
  Users,
  FileText,
  ArrowRight,
} from "lucide-react";
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

export default function DashboardPage() {
  const { user, logout, isLoading } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      const data = await api.get<DashboardStats>("/reports/dashboard");
      setStats(data);
    } catch {
      // Stats are best-effort; don't block the page on failure
    }
  }, []);

  useEffect(() => {
    if (!isLoading && user) fetchStats();
  }, [isLoading, user, fetchStats]);

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-muted-foreground text-sm">Loading…</div>
      </div>
    );
  }

  const roleBadge: Record<string, string> = {
    admin: "bg-red-100 text-red-700",
    analyst: "bg-blue-100 text-blue-700",
    readonly: "bg-gray-100 text-gray-600",
  };

  const immediateCount = stats?.by_priority?.["immediate"] ?? null;
  const remediatedCount = stats?.by_status?.["remediated"] ?? null;

  const statCards = [
    {
      label: "Total Findings",
      value: stats ? String(stats.total) : "—",
      icon: Bug,
      description: "Ingested from all sources",
      accent: "border-l-4 border-l-primary/60",
    },
    {
      label: "Immediate",
      value: immediateCount !== null ? String(immediateCount) : "—",
      icon: ShieldAlert,
      description: "AI-scored: act within 7 days",
      className: immediateCount !== null && immediateCount > 0 ? "text-red-600" : "",
      accent: "border-l-4 border-l-red-500/60",
    },
    {
      label: "KEV Listed",
      value: stats ? String(stats.kev_count) : "—",
      icon: Server,
      description: "In CISA Known Exploited Vulnerabilities",
      className: stats && stats.kev_count > 0 ? "text-red-600" : "",
      accent: "border-l-4 border-l-orange-500/60",
    },
    {
      label: "Remediated",
      value: remediatedCount !== null ? String(remediatedCount) : "—",
      icon: BarChart3,
      description: "Marked as remediated",
      accent: "border-l-4 border-l-green-500/60",
    },
  ];

  const quickLinks = [
    { label: "Vulnerability Queue", href: "/findings", icon: Bug, description: "Triage and prioritize findings" },
    { label: "Asset Register", href: "/assets", icon: Server, description: "Manage business context" },
    { label: "Reports", href: "/reports", icon: BarChart3, description: "Board-ready summaries" },
    { label: "Remediation", href: "/remediation", icon: FileText, description: "Draft tickets and triage plans" },
    ...(user?.role === "admin"
      ? [
          { label: "Team Members", href: "/settings/users", icon: Users, description: "Manage access" },
          { label: "Org Settings", href: "/settings", icon: Settings, description: "AI provider, thresholds" },
        ]
      : []),
  ];

  return (
    <div className="min-h-screen bg-muted/20">
      {/* Top navigation */}
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-primary" />
            <span className="font-bold text-lg">VulnOps</span>
            <span className="hidden text-sm text-muted-foreground sm:inline">
              Triage Console
            </span>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 text-sm text-muted-foreground">
              <span>{user?.email}</span>
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-medium ${roleBadge[user?.role ?? "readonly"]}`}
              >
                {user?.role}
              </span>
            </div>
            <ThemeToggle />
            <Button variant="outline" size="sm" onClick={() => logout()}>
              <LogOut className="h-4 w-4 mr-1.5" />
              Sign out
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8 space-y-8">
        {/* Welcome banner */}
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">
              Welcome back{user?.email ? `, ${user.email.split("@")[0]}` : ""}
            </h1>
            <p className="mt-1 text-muted-foreground text-sm">
              Your vulnerability triage console is ready. Upload findings, enrich
              with KEV/EPSS/NVD data, score with AI, and generate board-ready reports.
            </p>
          </div>
          {stats && (
            <div className="rounded-lg border bg-muted/30 px-4 py-2 text-right text-xs text-muted-foreground">
              <span className="font-medium text-foreground">{stats.scored_count}</span> findings scored
              &nbsp;·&nbsp;
              <span className="font-medium text-foreground">{stats.by_status?.["open"] ?? 0}</span> open
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {statCards.map((stat) => (
            <Card key={stat.label} className={stat.accent}>
              <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  {stat.label}
                </CardTitle>
                <stat.icon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className={`text-2xl font-bold ${stat.className ?? ""}`}>
                  {stat.value}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {stat.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Quick links */}
        <div>
          <h2 className="text-lg font-semibold mb-4">Quick access</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {quickLinks.map((link) => (
              <a key={link.href} href={link.href}>
                <Card className="group hover:border-primary/50 hover:shadow-md transition-all cursor-pointer h-full">
                  <CardHeader>
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="rounded-md bg-primary/10 p-2 group-hover:bg-primary/20 transition-colors">
                          <link.icon className="h-5 w-5 text-primary" />
                        </div>
                        <div>
                          <CardTitle className="text-base">{link.label}</CardTitle>
                          <CardDescription className="text-xs mt-0.5">
                            {link.description}
                          </CardDescription>
                        </div>
                      </div>
                      <ArrowRight className="h-4 w-4 text-muted-foreground/40 shrink-0 group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
                    </div>
                  </CardHeader>
                </Card>
              </a>
            ))}
          </div>
        </div>

      </main>
    </div>
  );
}
