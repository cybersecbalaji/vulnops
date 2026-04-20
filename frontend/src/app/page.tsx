"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import {
  Upload, Sparkles, ShieldAlert, Server, FileText, ClipboardList,
  ArrowRight, Shield, CheckCircle2, Zap, Lock,
} from "lucide-react";

// ── Feature data ──────────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon: Upload,
    title: "Scanner import",
    desc: "Import directly from Nessus, Tenable, Qualys, or Rapid7 — no manual reformatting. CMDB imports from Intune, SCCM, Axonius, and CrowdStrike supported.",
  },
  {
    icon: Sparkles,
    title: "AI-powered triage",
    desc: "Every finding is scored by an LLM with full rationale and a five-tier priority. Supports OpenAI, Anthropic, Gemini, and more.",
  },
  {
    icon: ShieldAlert,
    title: "KEV + EPSS enrichment",
    desc: "Auto-enriched with CISA KEV catalog and FIRST EPSS probability scores. Know which vulns are actively exploited.",
  },
  {
    icon: Server,
    title: "Asset context",
    desc: "Link findings to your asset register. Internet-facing critical assets score higher — so your team focuses on what actually matters.",
  },
  {
    icon: FileText,
    title: "Remediation tickets",
    desc: "One-click Markdown or Jira ticket drafts from the AI rationale. Generate board-ready reports in seconds.",
  },
  {
    icon: ClipboardList,
    title: "Full audit trail",
    desc: "Every action logged with timestamp, user, and org scope. Satisfy compliance and demonstrate due diligence.",
  },
];

const STEPS = [
  {
    n: "01",
    title: "Ingest",
    desc: "Upload from any scanner or paste a CVE list. Supports Nessus, Tenable, Qualys, Rapid7, and generic CSV/JSON.",
  },
  {
    n: "02",
    title: "Prioritise",
    desc: "AI scores each finding against your asset context, EPSS probability, CISA KEV status, and CVSS score.",
  },
  {
    n: "03",
    title: "Act",
    desc: "Draft remediation tickets, generate board reports, and track every finding through to closure.",
  },
];

const STATS = [
  { value: "1,100+", label: "KEV CVEs tracked" },
  { value: "5", label: "AI providers supported" },
  { value: "8", label: "Scanner & CMDB formats" },
  { value: "100%", label: "Audit logged" },
];

// ── Page ──────────────────────────────────────────────────────────────────────

export default function HomePage() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  // Authenticated users go straight to dashboard
  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      router.replace("/dashboard");
    }
  }, [isAuthenticated, isLoading, router]);

  if (isLoading) {
    return <div className="min-h-screen bg-slate-950" />;
  }

  if (isAuthenticated) {
    return null;
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* ── Navbar ── */}
      <nav className="sticky top-0 z-50 border-b border-slate-800/60 bg-slate-950/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600">
              <Shield className="h-4.5 w-4.5 text-white" />
            </div>
            <span className="text-base font-bold tracking-tight text-white">VulnOps</span>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login">
              <Button variant="ghost" size="sm" className="text-slate-300 hover:text-white hover:bg-slate-800">
                Sign in
              </Button>
            </Link>
            <Link href="/register">
              <Button size="sm" className="bg-blue-600 hover:bg-blue-500 text-white border-0">
                Get started free
              </Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* ── Hero ── */}
      <section className="relative overflow-hidden border-b border-slate-800/40">
        {/* Background gradient orbs */}
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -top-40 left-1/4 h-[500px] w-[500px] rounded-full bg-blue-600/10 blur-3xl" />
          <div className="absolute top-20 right-1/4 h-[400px] w-[400px] rounded-full bg-violet-600/8 blur-3xl" />
        </div>

        <div className="relative mx-auto max-w-7xl px-6 pb-24 pt-20 text-center">
          {/* Eyebrow badge */}
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-500/10 px-4 py-1.5 text-xs font-medium text-blue-300">
            <Zap className="h-3 w-3" />
            AI-powered vulnerability triage
          </div>

          {/* Main headline */}
          <h1 className="text-5xl font-extrabold tracking-tight text-white sm:text-6xl lg:text-7xl">
            Know what to fix.
            <br />
            <span className="bg-gradient-to-r from-blue-400 via-violet-400 to-cyan-400 bg-clip-text text-transparent">
              Fix what matters.
            </span>
          </h1>

          <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-400 leading-relaxed">
            VulnOps cuts through scanner noise with AI-powered triage — scoring every vulnerability
            against your asset context, EPSS probability, and CISA KEV status so your team always
            knows exactly what to remediate first.
          </p>

          {/* CTA buttons */}
          <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
            <Link href="/register">
              <Button size="lg" className="h-12 bg-blue-600 hover:bg-blue-500 text-white px-8 border-0 text-base font-semibold">
                Get started free
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
            <Link href="/login">
              <Button size="lg" variant="outline" className="h-12 px-8 text-base border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white">
                Sign in to your workspace
              </Button>
            </Link>
          </div>

          {/* Trust signals */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-6 text-xs text-slate-500">
            {["No credit card required", "Self-hostable", "Multi-tenant by design"].map(t => (
              <span key={t} className="flex items-center gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-green-500/70" />
                {t}
              </span>
            ))}
          </div>

          {/* Dashboard mockup */}
          <div className="relative mx-auto mt-16 max-w-4xl">
            <div className="overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900 shadow-2xl shadow-black/60">
              {/* Fake browser chrome */}
              <div className="flex items-center gap-1.5 border-b border-slate-700/60 bg-slate-800/60 px-4 py-2.5">
                <span className="h-3 w-3 rounded-full bg-red-500/70" />
                <span className="h-3 w-3 rounded-full bg-yellow-500/70" />
                <span className="h-3 w-3 rounded-full bg-green-500/70" />
                <span className="ml-3 flex-1 rounded bg-slate-700/60 px-3 py-0.5 text-left text-xs text-slate-500 font-mono">
                  vulnops.app/findings
                </span>
              </div>
              {/* Findings table mockup */}
              <div className="p-4 text-left text-xs">
                {/* Mini stat bar */}
                <div className="mb-3 flex items-center gap-4 rounded-lg border border-slate-700/40 bg-slate-800/40 px-3 py-2 text-xs">
                  <span className="text-slate-400">247 <span className="text-slate-500">findings</span></span>
                  <span className="text-red-400 font-semibold">12 <span className="font-normal text-slate-500">immediate</span></span>
                  <span className="text-orange-400 font-semibold">8 <span className="font-normal text-slate-500">KEV listed</span></span>
                  <span className="text-green-400 font-semibold">61 <span className="font-normal text-slate-500">remediated</span></span>
                </div>
                {/* Table header */}
                <div className="mb-1.5 grid grid-cols-[1.6fr_68px_52px_52px_52px_80px_84px] gap-2 border-b border-slate-700/40 pb-2 font-semibold text-slate-500 uppercase tracking-wide" style={{fontSize: "10px"}}>
                  <span>CVE / Title</span>
                  <span>Severity</span>
                  <span>CVSS</span>
                  <span>EPSS</span>
                  <span>KEV</span>
                  <span>AI Priority</span>
                  <span>Status</span>
                </div>
                {/* Mock rows */}
                {[
                  {
                    cve: "CVE-2021-44228", title: "Log4Shell — Apache Log4j RCE",
                    sev: "critical", sevColor: "text-red-400 bg-red-950/60",
                    cvss: "10.0", cvssColor: "text-red-400",
                    epss: "97.3%", epssColor: "text-red-400 font-semibold",
                    kev: true,
                    pri: "● Immediate", priColor: "text-red-400",
                    status: "open", statusColor: "text-slate-400",
                  },
                  {
                    cve: "CVE-2024-3400", title: "PAN-OS Zero-Day — Command Injection",
                    sev: "critical", sevColor: "text-red-400 bg-red-950/60",
                    cvss: "10.0", cvssColor: "text-red-400",
                    epss: "94.1%", epssColor: "text-red-400 font-semibold",
                    kev: true,
                    pri: "● Immediate", priColor: "text-red-400",
                    status: "triaged", statusColor: "text-yellow-400",
                  },
                  {
                    cve: "CVE-2023-34048", title: "VMware vCenter DCERPC Heap Overflow",
                    sev: "critical", sevColor: "text-red-400 bg-red-950/60",
                    cvss: "9.8", cvssColor: "text-red-400",
                    epss: "88.6%", epssColor: "text-red-400 font-semibold",
                    kev: true,
                    pri: "● Immediate", priColor: "text-red-400",
                    status: "remediated", statusColor: "text-green-400",
                  },
                  {
                    cve: "CVE-2022-0847", title: "Dirty Pipe — Linux Kernel PrivEsc",
                    sev: "high", sevColor: "text-orange-400 bg-orange-950/60",
                    cvss: "7.8", cvssColor: "text-orange-400",
                    epss: "31.4%", epssColor: "text-orange-400",
                    kev: false,
                    pri: "● This week", priColor: "text-orange-400",
                    status: "open", statusColor: "text-slate-400",
                  },
                  {
                    cve: "CVE-2023-44487", title: "HTTP/2 Rapid Reset DDoS",
                    sev: "high", sevColor: "text-orange-400 bg-orange-950/60",
                    cvss: "7.5", cvssColor: "text-orange-400",
                    epss: "12.8%", epssColor: "text-slate-400",
                    kev: false,
                    pri: "● This week", priColor: "text-orange-400",
                    status: "open", statusColor: "text-slate-400",
                  },
                ].map(row => (
                  <div key={row.cve} className="grid grid-cols-[1.6fr_68px_52px_52px_52px_80px_84px] items-center gap-2 border-b border-slate-800/40 py-1.5 last:border-0">
                    <div className="min-w-0">
                      <span className="font-mono text-slate-300">{row.cve}</span>
                      <p className="mt-0.5 text-slate-500 truncate">{row.title}</p>
                    </div>
                    <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-semibold capitalize ${row.sevColor}`}>
                      ● {row.sev}
                    </span>
                    <span className={`font-mono font-semibold ${row.cvssColor}`}>{row.cvss}</span>
                    <span className={`font-mono ${row.epssColor}`}>{row.epss}</span>
                    <span className={row.kev ? "font-semibold text-red-400" : "text-slate-600"}>
                      {row.kev ? "Yes" : "No"}
                    </span>
                    <span className={`font-medium ${row.priColor}`}>{row.pri}</span>
                    <span className={`capitalize font-medium ${row.statusColor}`}>{row.status}</span>
                  </div>
                ))}
              </div>
            </div>
            {/* Glow under card */}
            <div className="pointer-events-none absolute -bottom-4 left-1/2 h-12 w-3/4 -translate-x-1/2 rounded-full bg-blue-600/20 blur-2xl" />
          </div>
        </div>
      </section>

      {/* ── Trust bar ── */}
      <section className="border-b border-slate-800/40 bg-slate-900/40 py-8">
        <div className="mx-auto max-w-7xl px-6 text-center">
          <p className="mb-6 text-xs font-medium uppercase tracking-widest text-slate-500">
            Works with the scanners your team already uses
          </p>
          <div className="flex flex-wrap items-center justify-center gap-8">
            {["Nessus", "Tenable.io", "Qualys VMDR", "Rapid7 InsightVM", "CrowdStrike", "Microsoft Intune"].map(name => (
              <span key={name} className="text-sm font-semibold text-slate-400 tracking-wide">{name}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Feature grid ── */}
      <section className="border-b border-slate-800/40 py-24">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-3xl font-bold text-white sm:text-4xl">
              Everything your team needs to prioritise faster
            </h2>
            <p className="mt-4 text-slate-400">
              From ingestion to closure — VulnOps handles the full vulnerability lifecycle so your team
              can focus on fixing, not triaging.
            </p>
          </div>

          <div className="mt-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(f => (
              <div key={f.title} className="group rounded-xl border border-slate-800/60 bg-slate-900/50 p-6 transition-colors hover:border-slate-700 hover:bg-slate-900">
                <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-blue-600/15 ring-1 ring-blue-500/20 group-hover:bg-blue-600/25 transition-colors">
                  <f.icon className="h-5 w-5 text-blue-400" />
                </div>
                <h3 className="mb-2 font-semibold text-white">{f.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section className="border-b border-slate-800/40 py-24 bg-slate-900/20">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-3xl font-bold text-white sm:text-4xl">How it works</h2>
            <p className="mt-4 text-slate-400">Three steps from raw scanner output to prioritised, actionable findings.</p>
          </div>

          <div className="relative mt-16 grid gap-8 sm:grid-cols-3">
            {/* Connector line (desktop only) */}
            <div className="pointer-events-none absolute left-[16.66%] right-[16.66%] top-6 hidden h-px bg-gradient-to-r from-transparent via-slate-700 to-transparent sm:block" />

            {STEPS.map(step => (
              <div key={step.n} className="relative text-center">
                <div className="mx-auto mb-5 flex h-12 w-12 items-center justify-center rounded-full border border-slate-700 bg-slate-900 text-sm font-bold text-blue-400">
                  {step.n}
                </div>
                <h3 className="mb-3 text-lg font-semibold text-white">{step.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Stats banner ── */}
      <section className="border-b border-slate-800/40 py-16">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
            {STATS.map(s => (
              <div key={s.label} className="text-center">
                <p className="text-4xl font-extrabold text-white">{s.value}</p>
                <p className="mt-1 text-sm text-slate-400">{s.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Security section ── */}
      <section className="border-b border-slate-800/40 py-20">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid items-center gap-12 lg:grid-cols-2">
            <div>
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-green-500/30 bg-green-500/10 px-3 py-1 text-xs font-medium text-green-400">
                <Lock className="h-3 w-3" />
                Built for security teams
              </div>
              <h2 className="text-3xl font-bold text-white sm:text-4xl">
                Security by design
              </h2>
              <p className="mt-4 text-slate-400 leading-relaxed">
                VulnOps is purpose-built for security teams that care about data integrity.
                All sensitive fields are encrypted at rest with per-org keys. Every action is
                logged immutably. API access is scoped by role.
              </p>
              <ul className="mt-6 space-y-3">
                {[
                  "Field-level encryption — sensitive data encrypted with per-org Fernet keys",
                  "RS256 JWT authentication with short-lived access tokens",
                  "Role-based access control: admin · analyst · read-only",
                  "Full audit log — every mutation recorded with user, timestamp, and org scope",
                  "Multi-tenant isolation — org scoping enforced at the DB layer",
                ].map(item => (
                  <li key={item} className="flex items-start gap-2.5 text-sm text-slate-300">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-500" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            {/* Security feature cards */}
            <div className="grid grid-cols-2 gap-4">
              {[
                { icon: Lock, title: "Encrypted at rest", desc: "Per-org encryption keys, never shared" },
                { icon: Shield, title: "JWT auth", desc: "RS256 tokens, 15-min TTL" },
                { icon: ClipboardList, title: "Audit log", desc: "Immutable, tamper-evident trail" },
                { icon: CheckCircle2, title: "RBAC", desc: "Granular role enforcement" },
              ].map(c => (
                <div key={c.title} className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-5">
                  <c.icon className="mb-3 h-6 w-6 text-green-400" />
                  <p className="font-semibold text-white text-sm">{c.title}</p>
                  <p className="mt-1 text-xs text-slate-400">{c.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA footer ── */}
      <section className="py-24">
        <div className="mx-auto max-w-3xl px-6 text-center">
          <h2 className="text-4xl font-extrabold text-white sm:text-5xl">
            Start triaging smarter today
          </h2>
          <p className="mt-5 text-lg text-slate-400">
            Join security teams who use VulnOps to cut remediation time by focusing on what actually matters.
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
            <Link href="/register">
              <Button size="lg" className="h-12 bg-blue-600 hover:bg-blue-500 text-white px-10 border-0 text-base font-semibold">
                Get started free
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
            <Link href="/login">
              <Button size="lg" variant="outline" className="h-12 px-8 text-base border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white">
                Sign in
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-slate-800/40 py-8">
        <div className="mx-auto max-w-7xl px-6 flex flex-wrap items-center justify-between gap-4 text-sm text-slate-500">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded bg-blue-600">
              <Shield className="h-3.5 w-3.5 text-white" />
            </div>
            <span className="font-semibold text-slate-400">VulnOps</span>
            <span>· AI-powered vulnerability triage</span>
          </div>
          <div className="flex gap-6">
            <Link href="/login" className="hover:text-slate-300 transition-colors">Sign in</Link>
            <Link href="/register" className="hover:text-slate-300 transition-colors">Register</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
