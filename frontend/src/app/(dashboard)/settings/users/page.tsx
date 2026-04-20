"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Users, ChevronLeft, RefreshCw, Loader2, CheckCircle2, XCircle,
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

interface TeamMember {
  id: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

const ROLES = ["admin", "analyst", "readonly"] as const;

const roleColors: Record<string, string> = {
  admin: "bg-red-100 text-red-700",
  analyst: "bg-blue-100 text-blue-700",
  readonly: "bg-gray-100 text-gray-600",
};

export default function TeamMembersPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [members, setMembers] = useState<TeamMember[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const fetchMembers = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.get<TeamMember[]>("/users");
      setMembers(data);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load team members.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { fetchMembers(); }, [fetchMembers]);

  async function updateRole(memberId: string, newRole: string) {
    setUpdating(memberId);
    setMsg(null);
    try {
      await api.patch(`/users/${memberId}`, { role: newRole });
      setMsg({ ok: true, text: "Role updated." });
      fetchMembers();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Update failed." });
    } finally {
      setUpdating(null);
    }
  }

  async function toggleActive(memberId: string, currentActive: boolean) {
    setUpdating(memberId);
    setMsg(null);
    try {
      await api.patch(`/users/${memberId}`, { is_active: !currentActive });
      setMsg({ ok: true, text: currentActive ? "Member deactivated." : "Member reactivated." });
      fetchMembers();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Update failed." });
    } finally {
      setUpdating(null);
    }
  }

  function formatDate(dateStr: string | null) {
    if (!dateStr) return "Never";
    return new Date(dateStr).toLocaleDateString(undefined, {
      month: "short", day: "numeric", year: "numeric",
    });
  }

  return (
    <div className="min-h-screen bg-muted/20">
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground text-sm">
              <ChevronLeft className="h-4 w-4" /> Dashboard
            </Link>
            <span className="text-muted-foreground">/</span>
            <span className="font-semibold text-sm flex items-center gap-1.5">
              <Users className="h-4 w-4 text-primary" /> Team Members
            </span>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <Button variant="outline" size="sm" onClick={fetchMembers} disabled={isLoading}>
              <RefreshCw className={`h-4 w-4 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 py-8 space-y-6">
        <div>
          <h1 className="text-xl font-bold">Team Members</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage who has access to your VulnOps workspace and their permission level.
          </p>
        </div>

        {!isAdmin && (
          <Alert>
            <AlertDescription className="text-sm">
              You have read-only access to this page. Contact an admin to change roles.
            </AlertDescription>
          </Alert>
        )}

        {msg && (
          <Alert variant={msg.ok ? "default" : "destructive"} className="py-2">
            <AlertDescription className="text-sm flex items-center gap-2">
              {msg.ok
                ? <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0" />
                : <XCircle className="h-4 w-4 shrink-0" />}
              {msg.text}
            </AlertDescription>
          </Alert>
        )}

        {isLoading ? (
          <div className="flex items-center justify-center py-20 gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading…
          </div>
        ) : error ? (
          <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
        ) : (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">{members.length} member{members.length !== 1 ? "s" : ""}</CardTitle>
              <CardDescription className="text-xs">
                All users in your organization. Admins can manage roles and active status.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b bg-muted/40">
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Email</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Role</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Status</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Joined</th>
                      <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Last login</th>
                      {isAdmin && <th className="px-4 py-2.5 text-right text-xs font-medium text-muted-foreground">Actions</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {members.map(m => (
                      <tr key={m.id} className="border-b last:border-0 hover:bg-muted/20 transition-colors">
                        <td className="px-4 py-3 text-sm">
                          <span className="font-medium">{m.email}</span>
                          {m.id === user?.id && (
                            <span className="ml-2 text-xs text-muted-foreground">(you)</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {isAdmin && m.id !== user?.id ? (
                            <select
                              value={m.role}
                              onChange={e => updateRole(m.id, e.target.value)}
                              disabled={!!updating}
                              className="rounded border bg-background px-2 py-0.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
                            >
                              {ROLES.map(r => (
                                <option key={r} value={r}>{r}</option>
                              ))}
                            </select>
                          ) : (
                            <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${roleColors[m.role] ?? "bg-gray-100 text-gray-600"}`}>
                              {m.role}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs font-medium ${m.is_active ? "text-green-600" : "text-muted-foreground line-through"}`}>
                            {m.is_active ? "Active" : "Inactive"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(m.created_at)}</td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(m.last_login)}</td>
                        {isAdmin && (
                          <td className="px-4 py-3 text-right">
                            {m.id !== user?.id && (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="text-xs h-7 px-2"
                                disabled={!!updating}
                                onClick={() => toggleActive(m.id, m.is_active)}
                              >
                                {updating === m.id
                                  ? <Loader2 className="h-3 w-3 animate-spin" />
                                  : m.is_active ? "Deactivate" : "Reactivate"}
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

        <Card className="bg-muted/30">
          <CardContent className="pt-4">
            <p className="text-xs text-muted-foreground">
              <strong>Roles:</strong>{" "}
              <span className="font-medium text-foreground">Admin</span> — full access including settings and user management.{" "}
              <span className="font-medium text-foreground">Analyst</span> — can triage, enrich, score and create tickets.{" "}
              <span className="font-medium text-foreground">Read-only</span> — view findings and reports only.
            </p>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
