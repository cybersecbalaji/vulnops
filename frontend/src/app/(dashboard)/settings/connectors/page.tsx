"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  ChevronLeft,
  Loader2,
  Plus,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Trash2,
  Wifi,
  X,
} from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Provider {
  provider: string;
  required_config_keys: string[];
}

interface ScannerConnection {
  id: string;
  name: string;
  provider: string;
  enabled: boolean;
  last_sync_at: string | null;
  last_sync_status: string | null;
  last_sync_error: string | null;
  last_sync_count: number | null;
  created_at: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string | null }) {
  if (!status)
    return (
      <Badge variant="default" className="text-muted-foreground bg-muted ring-0">
        Never synced
      </Badge>
    );
  if (status === "ok")
    return (
      <Badge variant="remediated">
        <CheckCircle2 className="h-3 w-3 mr-1" /> OK
      </Badge>
    );
  if (status === "running")
    return (
      <Badge variant="in_progress">
        <Loader2 className="h-3 w-3 mr-1 animate-spin" /> Running
      </Badge>
    );
  return (
    <Badge variant="critical">
      <XCircle className="h-3 w-3 mr-1" /> Error
    </Badge>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// ── Simple modal overlay (no shadcn Dialog needed) ─────────────────────────

function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  footer: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative z-10 bg-background rounded-xl border shadow-2xl w-full max-w-md mx-4 p-6 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold">{title}</h2>
            {description && (
              <p className="text-sm text-muted-foreground mt-0.5">{description}</p>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground ml-4"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div>{children}</div>
        <div className="flex justify-end gap-2 pt-2">{footer}</div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ConnectorsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [connections, setConnections] = useState<ScannerConnection[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Add modal state
  const [showAdd, setShowAdd] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null);
  const [connName, setConnName] = useState("");
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  // Per-row loading state
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [rowMessage, setRowMessage] = useState<Record<string, string>>({});

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [conns, provs] = await Promise.all([
        api.get<ScannerConnection[]>("/scanner-connections/"),
        api.get<Provider[]>("/scanner-connections/providers"),
      ]);
      setConnections(conns);
      setProviders(provs);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load connections.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // ── Add connector ───────────────────────────────────────────────────────────

  function openAdd(prov: Provider) {
    setSelectedProvider(prov);
    setConnName("");
    setConfigValues(Object.fromEntries(prov.required_config_keys.map((k) => [k, ""])));
    setAddError(null);
    setShowAdd(true);
  }

  async function handleAdd() {
    if (!selectedProvider) return;
    setAdding(true);
    setAddError(null);
    try {
      await api.post("/scanner-connections/", {
        name: connName,
        provider: selectedProvider.provider,
        config: configValues,
      });
      setShowAdd(false);
      await loadData();
    } catch (e) {
      setAddError(e instanceof ApiError ? e.message : "Failed to create connection.");
    } finally {
      setAdding(false);
    }
  }

  // ── Test ────────────────────────────────────────────────────────────────────

  async function handleTest(id: string) {
    setTestingId(id);
    setRowMessage((m) => ({ ...m, [id]: "" }));
    try {
      const res = await api.post<{ connected: boolean; status: string }>(
        `/scanner-connections/${id}/test`,
        {}
      );
      setRowMessage((m) => ({
        ...m,
        [id]: res.connected ? "Connection OK" : "Connection failed",
      }));
    } catch (e) {
      setRowMessage((m) => ({
        ...m,
        [id]: e instanceof ApiError ? e.message : "Test failed",
      }));
    } finally {
      setTestingId(null);
    }
  }

  // ── Sync ────────────────────────────────────────────────────────────────────

  async function handleSync(id: string) {
    setSyncingId(id);
    setRowMessage((m) => ({ ...m, [id]: "" }));
    try {
      const res = await api.post<{ message: string; ingested: number }>(
        `/scanner-connections/${id}/sync`,
        {}
      );
      setRowMessage((m) => ({ ...m, [id]: res.message }));
      await loadData();
    } catch (e) {
      setRowMessage((m) => ({
        ...m,
        [id]: e instanceof ApiError ? e.message : "Sync failed",
      }));
    } finally {
      setSyncingId(null);
    }
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  async function handleDelete(id: string) {
    if (!confirm("Delete this scanner connection? This cannot be undone.")) return;
    setDeletingId(id);
    try {
      await api.delete(`/scanner-connections/${id}`);
      await loadData();
    } catch (e) {
      setRowMessage((m) => ({
        ...m,
        [id]: e instanceof ApiError ? e.message : "Delete failed",
      }));
    } finally {
      setDeletingId(null);
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Link href="/settings">
          <Button variant="ghost" size="sm">
            <ChevronLeft className="h-4 w-4 mr-1" />
            Settings
          </Button>
        </Link>
      </div>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scanner Connectors</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Connect to your scanners for automatic finding sync.
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={loadData} disabled={isLoading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Existing connections */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading…
        </div>
      ) : connections.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No scanner connections configured. Add one below.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {connections.map((conn) => (
            <Card key={conn.id}>
              <CardContent className="py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium truncate">{conn.name}</span>
                      <Badge variant="default" className="font-mono text-xs">
                        {conn.provider}
                      </Badge>
                      <StatusBadge status={conn.last_sync_status} />
                    </div>
                    <div className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      Last sync: {formatDate(conn.last_sync_at)}
                      {conn.last_sync_count != null && (
                        <> &middot; {conn.last_sync_count} findings ingested</>
                      )}
                    </div>
                    {conn.last_sync_error && (
                      <div className="text-xs text-red-600 dark:text-red-400 mt-1 truncate max-w-lg">
                        {conn.last_sync_error}
                      </div>
                    )}
                    {rowMessage[conn.id] && (
                      <div className="text-xs text-muted-foreground mt-1">
                        {rowMessage[conn.id]}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleTest(conn.id)}
                      disabled={testingId === conn.id}
                      title="Test connection"
                    >
                      {testingId === conn.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Wifi className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleSync(conn.id)}
                      disabled={syncingId === conn.id || !isAdmin}
                      title="Sync now"
                    >
                      {syncingId === conn.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <RefreshCw className="h-4 w-4" />
                      )}
                    </Button>
                    {isAdmin && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:text-destructive"
                        onClick={() => handleDelete(conn.id)}
                        disabled={deletingId === conn.id}
                        title="Delete"
                      >
                        {deletingId === conn.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Add connector — provider cards */}
      {isAdmin && (
        <div>
          <h2 className="text-lg font-semibold mb-3">Add connector</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {providers.map((prov) => (
              <Card
                key={prov.provider}
                className="cursor-pointer hover:border-primary/60 transition-colors"
                onClick={() => openAdd(prov)}
              >
                <CardHeader className="pb-2">
                  <CardTitle className="text-base capitalize">{prov.provider}</CardTitle>
                  <CardDescription className="text-xs">
                    Requires: {prov.required_config_keys.join(", ")}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Button size="sm" variant="ghost" className="w-full">
                    <Plus className="h-3 w-3 mr-1" /> Add
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Add connector modal */}
      <Modal
        open={showAdd}
        onClose={() => setShowAdd(false)}
        title={`Add ${selectedProvider?.provider ?? ""} connector`}
        description="Credentials are stored encrypted. They will not be shown again."
        footer={
          <>
            <Button variant="ghost" onClick={() => setShowAdd(false)} disabled={adding}>
              Cancel
            </Button>
            <Button onClick={handleAdd} disabled={adding || !connName.trim()}>
              {adding && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Add connector
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="conn-name">Connection name</Label>
            <Input
              id="conn-name"
              placeholder="e.g. Production Tenable"
              value={connName}
              onChange={(e) => setConnName(e.target.value)}
            />
          </div>

          {selectedProvider?.required_config_keys.map((key) => (
            <div key={key} className="space-y-1.5">
              <Label htmlFor={`cfg-${key}`} className="font-mono text-sm">
                {key}
              </Label>
              <Input
                id={`cfg-${key}`}
                type={
                  key.toLowerCase().includes("key") ||
                  key.toLowerCase().includes("secret") ||
                  key.toLowerCase().includes("password")
                    ? "password"
                    : "text"
                }
                placeholder={key}
                value={configValues[key] ?? ""}
                onChange={(e) =>
                  setConfigValues((v) => ({ ...v, [key]: e.target.value }))
                }
              />
            </div>
          ))}

          {addError && (
            <Alert variant="destructive">
              <AlertDescription>{addError}</AlertDescription>
            </Alert>
          )}
        </div>
      </Modal>
    </div>
  );
}
