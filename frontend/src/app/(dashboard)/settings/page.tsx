"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  ShieldAlert, ChevronLeft, Save, Zap, CheckCircle2,
  XCircle, Loader2, Eye, EyeOff,
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

interface OrgSettings {
  ai_provider: string;
  ai_model: string;
  has_ai_api_key: boolean;
  ollama_base_url: string | null;
  jira_base_url: string | null;
  jira_project_key: string | null;
  has_jira_api_key: boolean;
  epss_immediate_threshold: number;
  epss_this_week_threshold: number;
  cvss_immediate_threshold: number;
  cvss_this_week_threshold: number;
  kev_sla_days: number;
  non_kev_critical_sla_days: number;
}

const PROVIDER_MODELS: Record<string, string[]> = {
  anthropic: ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
  openai:    ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4"],
  gemini:    ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
  ollama:    ["llama3.2", "llama3.1", "mistral", "mixtral", "custom"],
};

export default function SettingsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [settings, setSettings] = useState<OrgSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // LLM form
  const [provider, setProvider] = useState("anthropic");
  const [model, setModel] = useState("claude-sonnet-4-6");
  const [customModel, setCustomModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [ollamaUrl, setOllamaUrl] = useState("");
  const [llmSaving, setLlmSaving] = useState(false);
  const [llmMsg, setLlmMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // LLM test
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);

  // Thresholds
  const [thresholds, setThresholds] = useState({
    epss_immediate_threshold: 0.5,
    epss_this_week_threshold: 0.3,
    cvss_immediate_threshold: 9.0,
    cvss_this_week_threshold: 7.0,
    kev_sla_days: 7,
    non_kev_critical_sla_days: 30,
  });
  const [thresholdSaving, setThresholdSaving] = useState(false);
  const [thresholdMsg, setThresholdMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const fetchSettings = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await api.get<OrgSettings>("/org/settings");
      setSettings(data);
      setProvider(data.ai_provider);
      setModel(data.ai_model);
      setOllamaUrl(data.ollama_base_url ?? "");
      setThresholds({
        epss_immediate_threshold: data.epss_immediate_threshold,
        epss_this_week_threshold: data.epss_this_week_threshold,
        cvss_immediate_threshold: data.cvss_immediate_threshold,
        cvss_this_week_threshold: data.cvss_this_week_threshold,
        kev_sla_days: data.kev_sla_days,
        non_kev_critical_sla_days: data.non_kev_critical_sla_days,
      });
    } catch (e) {
      setLoadError(e instanceof ApiError ? e.message : "Failed to load settings.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { fetchSettings(); }, [fetchSettings]);

  // When provider changes, set a sensible default model
  function handleProviderChange(p: string) {
    setProvider(p);
    setModel(PROVIDER_MODELS[p]?.[0] ?? "");
    setCustomModel("");
    setLlmMsg(null);
    setTestResult(null);
  }

  const effectiveModel = model === "custom" ? customModel : model;

  async function saveLLM() {
    setLlmSaving(true);
    setLlmMsg(null);
    try {
      const body: Record<string, string> = { ai_provider: provider, ai_model: effectiveModel };
      if (apiKey.trim()) body.ai_api_key = apiKey.trim();
      if (provider === "ollama" && ollamaUrl.trim()) body.ollama_base_url = ollamaUrl.trim();
      await api.patch("/org/settings", body);
      setLlmMsg({ ok: true, text: "LLM settings saved." });
      setApiKey("");
      fetchSettings();
    } catch (e) {
      setLlmMsg({ ok: false, text: e instanceof ApiError ? e.message : "Save failed." });
    } finally {
      setLlmSaving(false);
    }
  }

  async function testLLM() {
    setTesting(true);
    setTestResult(null);
    try {
      // Pass the unsaved key from the input if present, so users can test before saving
      const body = apiKey.trim() ? { ai_api_key: apiKey.trim() } : {};
      const res = await api.post<{ success: boolean; provider: string; model: string; message: string }>("/org/settings/test-llm", body);
      setTestResult({ ok: res.success, text: res.message });
    } catch (e) {
      setTestResult({ ok: false, text: e instanceof ApiError ? e.message : "Test failed." });
    } finally {
      setTesting(false);
    }
  }

  async function saveThresholds() {
    setThresholdSaving(true);
    setThresholdMsg(null);
    try {
      await api.patch("/org/settings", thresholds);
      setThresholdMsg({ ok: true, text: "Thresholds saved." });
      fetchSettings();
    } catch (e) {
      setThresholdMsg({ ok: false, text: e instanceof ApiError ? e.message : "Save failed." });
    } finally {
      setThresholdSaving(false);
    }
  }

  const models = PROVIDER_MODELS[provider] ?? [];

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
              <ShieldAlert className="h-4 w-4 text-primary" /> Org Settings
            </span>
          </div>
          <div className="flex items-center gap-2">
            {!isAdmin && (
              <span className="text-xs text-muted-foreground bg-muted px-2 py-1 rounded">
                Read-only — admin access required to edit
              </span>
            )}
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 py-8 space-y-6">
        {isLoading ? (
          <div className="flex items-center justify-center py-20 gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading…
          </div>
        ) : loadError ? (
          <Alert variant="destructive"><AlertDescription>{loadError}</AlertDescription></Alert>
        ) : (
          <>
            {/* ── AI / LLM Configuration ── */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="h-4 w-4 text-primary" /> AI Provider
                </CardTitle>
                <CardDescription>
                  Used for vulnerability scoring (triage priority) and remediation drafting.
                  The API key is encrypted with your org key and never returned in plaintext.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Provider */}
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  {Object.keys(PROVIDER_MODELS).map(p => (
                    <button
                      key={p}
                      onClick={() => isAdmin && handleProviderChange(p)}
                      disabled={!isAdmin}
                      className={`rounded-lg border py-3 text-sm font-medium transition-colors ${
                        provider === p
                          ? "border-primary bg-primary/5 text-primary"
                          : "text-muted-foreground hover:border-muted-foreground disabled:opacity-50 disabled:cursor-not-allowed"
                      }`}
                    >
                      {p.charAt(0).toUpperCase() + p.slice(1)}
                    </button>
                  ))}
                </div>

                {/* Model */}
                <div className="space-y-1.5">
                  <Label className="text-xs">Model</Label>
                  <select
                    value={model}
                    onChange={e => setModel(e.target.value)}
                    disabled={!isAdmin}
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
                  >
                    {models.map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                  {model === "custom" && (
                    <Input
                      placeholder="Enter model name"
                      value={customModel}
                      onChange={e => setCustomModel(e.target.value)}
                      disabled={!isAdmin}
                      className="mt-1.5"
                    />
                  )}
                </div>

                {/* Ollama URL */}
                {provider === "ollama" && (
                  <div className="space-y-1.5">
                    <Label className="text-xs">Ollama base URL</Label>
                    <Input
                      placeholder="http://host.docker.internal:11434"
                      value={ollamaUrl}
                      onChange={e => setOllamaUrl(e.target.value)}
                      disabled={!isAdmin}
                    />
                  </div>
                )}

                {/* API Key */}
                {provider !== "ollama" && (
                  <div className="space-y-1.5">
                    <Label className="text-xs">
                      API key
                      {settings?.has_ai_api_key && (
                        <span className="ml-2 text-green-600 font-normal">✓ key stored — enter new value to replace</span>
                      )}
                    </Label>
                    <div className="relative">
                      <Input
                        type={showKey ? "text" : "password"}
                        placeholder={settings?.has_ai_api_key ? "••••••••••••••••" : "Paste your API key here"}
                        value={apiKey}
                        onChange={e => setApiKey(e.target.value)}
                        disabled={!isAdmin}
                        className="pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowKey(v => !v)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      >
                        {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {provider === "anthropic" && "Get your key at console.anthropic.com"}
                      {provider === "openai" && "Get your key at platform.openai.com"}
                      {provider === "gemini" && "Get your key at aistudio.google.com"}
                    </p>
                  </div>
                )}

                {/* Feedback */}
                {llmMsg && (
                  <Alert variant={llmMsg.ok ? "default" : "destructive"} className="py-2">
                    <AlertDescription className="text-sm flex items-center gap-2">
                      {llmMsg.ok
                        ? <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0" />
                        : <XCircle className="h-4 w-4 shrink-0" />}
                      {llmMsg.text}
                    </AlertDescription>
                  </Alert>
                )}
                {testResult && (
                  <Alert variant={testResult.ok ? "default" : "destructive"} className="py-2">
                    <AlertDescription className="text-sm flex items-center gap-2">
                      {testResult.ok
                        ? <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0" />
                        : <XCircle className="h-4 w-4 shrink-0" />}
                      {testResult.text}
                    </AlertDescription>
                  </Alert>
                )}

                {isAdmin && (
                  <div className="space-y-1.5">
                    <div className="flex gap-2">
                      <Button onClick={saveLLM} disabled={llmSaving} size="sm">
                        {llmSaving ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Save className="h-4 w-4 mr-1.5" />}
                        Save
                      </Button>
                      <Button
                        onClick={testLLM}
                        disabled={
                          testing ||
                          (provider !== "ollama" && !settings?.has_ai_api_key && !apiKey.trim())
                        }
                        variant="outline"
                        size="sm"
                      >
                        {testing ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Zap className="h-4 w-4 mr-1.5" />}
                        {apiKey.trim()
                          ? "Test typed key"
                          : settings?.has_ai_api_key
                            ? "Test stored key"
                            : "Test connection"}
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {provider === "ollama"
                        ? "Ollama runs locally — no API key is required."
                        : apiKey.trim()
                          ? "Clicking Test will validate the key you just typed by making a real call to the provider."
                          : settings?.has_ai_api_key
                            ? "Clicking Test will validate the stored key. Paste a new key above to test it instead."
                            : "Paste an API key above — a real call to the provider is made to validate it."}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* ── Scoring Thresholds ── */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Scoring Thresholds</CardTitle>
                <CardDescription>
                  Controls when rule-based scoring escalates a finding to Immediate or This Week priority,
                  before the AI triage agent runs.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
                  <ThresholdField
                    label="EPSS → Immediate"
                    description="EPSS score (exploit probability) above this → Immediate"
                    value={thresholds.epss_immediate_threshold}
                    min={0} max={1} step={0.05}
                    format={v => `${(v * 100).toFixed(0)}%`}
                    onChange={v => setThresholds(t => ({ ...t, epss_immediate_threshold: v }))}
                    disabled={!isAdmin}
                  />
                  <ThresholdField
                    label="EPSS → This week"
                    description="EPSS score above this → This week"
                    value={thresholds.epss_this_week_threshold}
                    min={0} max={1} step={0.05}
                    format={v => `${(v * 100).toFixed(0)}%`}
                    onChange={v => setThresholds(t => ({ ...t, epss_this_week_threshold: v }))}
                    disabled={!isAdmin}
                  />
                  <ThresholdField
                    label="CVSS → Immediate"
                    description="CVSS base score above this → Immediate"
                    value={thresholds.cvss_immediate_threshold}
                    min={0} max={10} step={0.5}
                    format={v => v.toFixed(1)}
                    onChange={v => setThresholds(t => ({ ...t, cvss_immediate_threshold: v }))}
                    disabled={!isAdmin}
                  />
                  <ThresholdField
                    label="CVSS → This week"
                    description="CVSS base score above this → This week"
                    value={thresholds.cvss_this_week_threshold}
                    min={0} max={10} step={0.5}
                    format={v => v.toFixed(1)}
                    onChange={v => setThresholds(t => ({ ...t, cvss_this_week_threshold: v }))}
                    disabled={!isAdmin}
                  />
                  <div className="space-y-1.5">
                    <Label className="text-xs">KEV SLA (days)</Label>
                    <p className="text-xs text-muted-foreground">Remediation deadline for KEV-listed CVEs</p>
                    <Input
                      type="number" min={1} max={365}
                      value={thresholds.kev_sla_days}
                      onChange={e => setThresholds(t => ({ ...t, kev_sla_days: parseInt(e.target.value) || 7 }))}
                      disabled={!isAdmin}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Non-KEV Critical SLA (days)</Label>
                    <p className="text-xs text-muted-foreground">Remediation deadline for critical CVEs not in KEV</p>
                    <Input
                      type="number" min={1} max={365}
                      value={thresholds.non_kev_critical_sla_days}
                      onChange={e => setThresholds(t => ({ ...t, non_kev_critical_sla_days: parseInt(e.target.value) || 30 }))}
                      disabled={!isAdmin}
                    />
                  </div>
                </div>

                {thresholdMsg && (
                  <Alert variant={thresholdMsg.ok ? "default" : "destructive"} className="py-2">
                    <AlertDescription className="text-sm flex items-center gap-2">
                      {thresholdMsg.ok
                        ? <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0" />
                        : <XCircle className="h-4 w-4 shrink-0" />}
                      {thresholdMsg.text}
                    </AlertDescription>
                  </Alert>
                )}

                {isAdmin && (
                  <Button onClick={saveThresholds} disabled={thresholdSaving} size="sm">
                    {thresholdSaving ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Save className="h-4 w-4 mr-1.5" />}
                    Save thresholds
                  </Button>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </main>
    </div>
  );
}

// ── Threshold slider component ────────────────────────────────────────────────

function ThresholdField({
  label, description, value, min, max, step, format, onChange, disabled,
}: {
  label: string; description: string; value: number;
  min: number; max: number; step: number;
  format: (v: number) => string;
  onChange: (v: number) => void; disabled: boolean;
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <Label className="text-xs">{label}</Label>
        <span className="text-xs font-mono font-semibold text-primary">{format(value)}</span>
      </div>
      <p className="text-xs text-muted-foreground">{description}</p>
      <input
        type="range" min={min} max={max} step={step} value={value}
        onChange={e => onChange(parseFloat(e.target.value))}
        disabled={disabled}
        className="w-full accent-primary disabled:opacity-50"
      />
    </div>
  );
}
