"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  Shield, FileInput, Radar, ListOrdered, GitPullRequestArrow,
  BarChart3, ScrollText, Plug, Lock, KeyRound, ShieldCheck,
  FileCheck2, ArrowUpRight, GitFork, ArrowRight, BookOpen,
} from "lucide-react";

// ── Data ──────────────────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon: FileInput,
    title: "Ingest",
    desc: "Pull findings from scanner APIs directly — no CSV exports, no manual reformatting. Nessus, Tenable, Qualys, and more.",
  },
  {
    icon: Radar,
    title: "Enrich",
    desc: "Auto-enriched with CISA KEV catalog and FIRST EPSS probability scores. Know which vulns are actively exploited.",
  },
  {
    icon: ListOrdered,
    title: "Prioritize",
    desc: "LLM triage agent scores every finding against your asset context, EPSS, KEV status, and CVSS with full written rationale.",
  },
  {
    icon: GitPullRequestArrow,
    title: "Remediate",
    desc: "One-click Markdown or Jira ticket drafts from the AI rationale. Move from finding to fix without switching tabs.",
  },
  {
    icon: BarChart3,
    title: "Report",
    desc: "Board-ready dashboard stats and PDF exports aggregated across all scanners. Demonstrate progress, not just coverage.",
  },
  {
    icon: ScrollText,
    title: "Audit",
    desc: "Every action logged with timestamp, user, and org scope. Immutable. Satisfies compliance without a separate tool.",
  },
];

const CONNECTORS = [
  { name: "tenable.io", status: "live" },
  { name: "qualys vmdr", status: "live" },
  { name: "rapid7 insightvm", status: "beta" },
  { name: "nessus professional", status: "beta" },
  { name: "microsoft defender", status: "beta" },
];

const STEPS = [
  {
    n: "01",
    title: "Deploy",
    desc: "Clone the repo, run setup.py, docker compose up. Running in under five minutes on any VPS or cloud instance.",
  },
  {
    n: "02",
    title: "Connect",
    desc: "Add your scanner API credentials in Settings. Credentials are encrypted per-org — they never leave your instance.",
  },
  {
    n: "03",
    title: "Triage",
    desc: "Findings are synced, enriched, and scored automatically. Your team sees only what needs attention, ranked by real risk.",
  },
];

const SECURITY_CLAIMS = [
  { icon: Lock, label: "Encrypted at rest", sub: "Per-org Fernet keys" },
  { icon: KeyRound, label: "Per-org DEK", sub: "No shared key material" },
  { icon: ShieldCheck, label: "RS256 JWT auth", sub: "15-min access tokens" },
  { icon: FileCheck2, label: "Full audit log", sub: "Immutable, append-only" },
];

const REPO_URL = "https://github.com/cybersecbalaji/vulnops";

// ── Component ─────────────────────────────────────────────────────────────────

export default function HomePage() {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const [stars, setStars] = useState<string>("—");

  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      router.replace("/dashboard");
    }
  }, [isAuthenticated, isLoading, router]);

  useEffect(() => {
    fetch("https://api.github.com/repos/cybersecbalaji/vulnops", { cache: "no-store" })
      .then((r) => r.json())
      .then((d) => {
        if (typeof d.stargazers_count === "number") {
          const n = d.stargazers_count;
          setStars(n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n));
        }
      })
      .catch(() => {});
  }, []);

  if (isAuthenticated) {
    return <div className="min-h-screen bg-surface-warm" />;
  }

  return (
    <div className="min-h-screen bg-surface-warm text-gray-900 dark:text-gray-50">

      {/* ── Nav ── */}
      <header className="sticky top-0 z-50 border-b border-gray-200/70 bg-surface-warm/80 backdrop-blur-md dark:border-gray-800/80">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-2.5">
            <Shield strokeWidth={1.5} className="h-5 w-5 text-brand dark:text-brand-fg" />
            <span className="text-sm font-semibold tracking-tight">VulnOps</span>
            <span className="hidden rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 font-mono text-[10px] text-amber-800 sm:inline dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-400">
              Apache 2.0
            </span>
          </div>

          <nav className="hidden items-center gap-6 text-sm text-gray-500 md:flex dark:text-gray-400">
            <a href="#features" className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors">Product</a>
            <a href="#connectors" className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors">Integrations</a>
            <a href="#deploy" className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors">Self-host</a>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors"
            >
              GitHub
            </a>
          </nav>

          <div className="flex items-center gap-2">
            <ThemeToggle />
            <Link href="/login">
              <button className="hidden rounded-md px-3 py-1.5 text-sm text-gray-600 transition-colors hover:bg-gray-100 hover:text-gray-900 sm:block dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-50">
                Sign in
              </button>
            </Link>
            <Link href="/register">
              <button className="rounded-md bg-gray-900 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-gray-700 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-100">
                Get started
              </button>
            </Link>
          </div>
        </div>
      </header>

      {/* ── Hero ── */}
      <section className="relative overflow-hidden">
        {/* Warm amber glow behind headline */}
        <div className="amber-glow pointer-events-none absolute inset-x-0 top-0 h-[600px]" />
        {/* Dot grid */}
        <div className="hero-dot-grid pointer-events-none absolute inset-0" />

        <div className="relative mx-auto max-w-5xl px-6 pb-16 pt-24 text-center">
          {/* Eyebrow */}
          <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-amber-300/60 bg-amber-50 px-3.5 py-1 font-mono text-xs font-medium text-amber-800 dark:border-amber-800/60 dark:bg-amber-950/40 dark:text-amber-400">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-600 dark:bg-amber-400" />
            Open source · Self-hosted · Scanner APIs
          </div>

          {/* Headline */}
          <h1 className="mx-auto max-w-3xl text-5xl font-bold leading-[1.08] tracking-[-0.035em] text-gray-900 sm:text-6xl lg:text-[72px] dark:text-gray-50">
            Triage vulnerabilities
            <br />
            at the speed of <span className="text-brand dark:text-brand-fg">scale.</span>
          </h1>

          {/* Subline */}
          <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-gray-600 dark:text-gray-400">
            The open-source vulnerability triage console.
            Self-host in minutes on your own infrastructure.
          </p>

          {/* CTAs */}
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link href="/register">
              <button className="inline-flex h-11 items-center gap-2 rounded-md bg-gray-900 px-5 text-sm font-semibold text-white transition-colors hover:bg-gray-700 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-100">
                Start self-hosting
                <ArrowRight strokeWidth={1.5} className="h-4 w-4" />
              </button>
            </Link>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-11 items-center gap-2 rounded-md border border-gray-300 bg-white px-5 text-sm font-medium text-gray-700 transition-colors hover:border-amber-400 hover:text-amber-800 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 dark:hover:border-amber-500 dark:hover:text-amber-400"
            >
              <GitFork strokeWidth={1.5} className="h-4 w-4" />
              Star on GitHub
              {stars !== "—" && (
                <span className="ml-0.5 rounded bg-amber-50 px-1.5 py-0.5 font-mono text-xs text-amber-800 dark:bg-amber-950/40 dark:text-amber-400">
                  {stars}
                </span>
              )}
            </a>
          </div>

          {/* Terminal command snippet */}
          <div className="mx-auto mt-8 inline-flex items-center gap-3 rounded-md border border-gray-200 border-l-2 border-l-amber-600 bg-white px-4 py-2.5 shadow-sm dark:border-gray-800 dark:border-l-amber-500 dark:bg-gray-900">
            <span className="font-mono text-xs text-amber-700 dark:text-amber-400">$</span>
            <span className="font-mono text-xs text-gray-800 dark:text-gray-200">
              docker compose up -d
            </span>
            <span className="font-mono text-xs text-gray-400 dark:text-gray-500">
              # running in &lt;5 min
            </span>
          </div>
        </div>
      </section>

      {/* ── Product mockup (enriched + AI-scored findings) ── */}
      <section className="relative pb-24">
        <div className="relative mx-auto max-w-5xl px-6">
          {/* Amber glow under mockup */}
          <div className="amber-glow pointer-events-none absolute inset-x-0 top-1/4 h-[70%] blur-2xl" />

          <div className="relative overflow-hidden rounded-xl border border-gray-200 bg-white shadow-[0_10px_60px_-15px_rgba(180,83,9,0.25)] dark:border-gray-800 dark:bg-gray-950 dark:shadow-[0_10px_60px_-15px_rgba(245,158,11,0.15)]">
            {/* Browser chrome */}
            <div className="flex items-center gap-1.5 border-b border-gray-200 bg-gray-50/80 px-4 py-2.5 dark:border-gray-800 dark:bg-gray-900">
              <span className="h-2.5 w-2.5 rounded-full bg-gray-300 dark:bg-gray-700" />
              <span className="h-2.5 w-2.5 rounded-full bg-gray-300 dark:bg-gray-700" />
              <span className="h-2.5 w-2.5 rounded-full bg-gray-300 dark:bg-gray-700" />
              <span className="ml-3 flex-1 rounded bg-white px-3 py-0.5 text-left font-mono text-xs text-gray-500 dark:bg-gray-800 dark:text-gray-500">
                app.vulnops.dev/findings
              </span>
            </div>

            {/* Findings table mockup */}
            <div className="p-4 text-left text-xs">
              {/* Stat bar */}
              <div className="mb-3 flex flex-wrap items-center gap-4 rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-xs dark:border-gray-800 dark:bg-gray-900">
                <span className="text-gray-600 dark:text-gray-300">
                  247 <span className="text-gray-400 dark:text-gray-500">findings</span>
                </span>
                <span className="font-semibold text-red-600 dark:text-red-400">
                  12 <span className="font-normal text-gray-400 dark:text-gray-500">immediate</span>
                </span>
                <span className="font-semibold text-amber-700 dark:text-amber-400">
                  8 <span className="font-normal text-gray-400 dark:text-gray-500">KEV listed</span>
                </span>
                <span className="font-semibold text-emerald-700 dark:text-emerald-400">
                  61 <span className="font-normal text-gray-400 dark:text-gray-500">remediated</span>
                </span>
              </div>

              {/* Table header */}
              <div
                className="mb-1.5 grid grid-cols-[1.6fr_76px_52px_56px_46px_88px_80px] gap-2 border-b border-gray-200 pb-2 font-semibold uppercase tracking-wide text-gray-500 dark:border-gray-800 dark:text-gray-500"
                style={{ fontSize: "10px" }}
              >
                <span>CVE / Title</span>
                <span>Severity</span>
                <span>CVSS</span>
                <span>EPSS</span>
                <span>KEV</span>
                <span>AI Priority</span>
                <span>Status</span>
              </div>

              {/* Rows */}
              {[
                {
                  cve: "CVE-2021-44228", title: "Log4Shell — Apache Log4j RCE",
                  sev: "critical",
                  sevBg: "text-red-700 bg-red-50 border border-red-200 dark:text-red-400 dark:bg-red-950/50 dark:border-red-900/60",
                  cvss: "10.0", cvssColor: "text-red-700 dark:text-red-400",
                  epss: "97.3%", epssColor: "text-red-700 font-semibold dark:text-red-400",
                  kev: true,
                  pri: "● Immediate", priColor: "text-red-700 dark:text-red-400",
                  status: "open", statusColor: "text-gray-500 dark:text-gray-400",
                },
                {
                  cve: "CVE-2024-3400", title: "PAN-OS Zero-Day — Command Injection",
                  sev: "critical",
                  sevBg: "text-red-700 bg-red-50 border border-red-200 dark:text-red-400 dark:bg-red-950/50 dark:border-red-900/60",
                  cvss: "10.0", cvssColor: "text-red-700 dark:text-red-400",
                  epss: "94.1%", epssColor: "text-red-700 font-semibold dark:text-red-400",
                  kev: true,
                  pri: "● Immediate", priColor: "text-red-700 dark:text-red-400",
                  status: "triaged", statusColor: "text-amber-700 dark:text-amber-400",
                },
                {
                  cve: "CVE-2023-34048", title: "VMware vCenter DCERPC Heap Overflow",
                  sev: "critical",
                  sevBg: "text-red-700 bg-red-50 border border-red-200 dark:text-red-400 dark:bg-red-950/50 dark:border-red-900/60",
                  cvss: "9.8", cvssColor: "text-red-700 dark:text-red-400",
                  epss: "88.6%", epssColor: "text-red-700 font-semibold dark:text-red-400",
                  kev: true,
                  pri: "● Immediate", priColor: "text-red-700 dark:text-red-400",
                  status: "remediated", statusColor: "text-emerald-700 dark:text-emerald-400",
                },
                {
                  cve: "CVE-2022-0847", title: "Dirty Pipe — Linux Kernel PrivEsc",
                  sev: "high",
                  sevBg: "text-orange-700 bg-orange-50 border border-orange-200 dark:text-orange-400 dark:bg-orange-950/50 dark:border-orange-900/60",
                  cvss: "7.8", cvssColor: "text-orange-700 dark:text-orange-400",
                  epss: "31.4%", epssColor: "text-orange-700 dark:text-orange-400",
                  kev: false,
                  pri: "● This week", priColor: "text-orange-700 dark:text-orange-400",
                  status: "open", statusColor: "text-gray-500 dark:text-gray-400",
                },
                {
                  cve: "CVE-2023-44487", title: "HTTP/2 Rapid Reset DDoS",
                  sev: "high",
                  sevBg: "text-orange-700 bg-orange-50 border border-orange-200 dark:text-orange-400 dark:bg-orange-950/50 dark:border-orange-900/60",
                  cvss: "7.5", cvssColor: "text-orange-700 dark:text-orange-400",
                  epss: "12.8%", epssColor: "text-gray-500 dark:text-gray-400",
                  kev: false,
                  pri: "● This week", priColor: "text-orange-700 dark:text-orange-400",
                  status: "open", statusColor: "text-gray-500 dark:text-gray-400",
                },
              ].map((row) => (
                <div
                  key={row.cve}
                  className="grid grid-cols-[1.6fr_76px_52px_56px_46px_88px_80px] items-center gap-2 border-b border-gray-100 py-2 last:border-0 dark:border-gray-800/60"
                >
                  <div className="min-w-0">
                    <span className="font-mono text-gray-800 dark:text-gray-200">{row.cve}</span>
                    <p className="mt-0.5 truncate text-gray-500 dark:text-gray-500">{row.title}</p>
                  </div>
                  <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-semibold capitalize ${row.sevBg}`}>
                    ● {row.sev}
                  </span>
                  <span className={`font-mono font-semibold ${row.cvssColor}`}>{row.cvss}</span>
                  <span className={`font-mono ${row.epssColor}`}>{row.epss}</span>
                  <span className={row.kev ? "font-semibold text-amber-700 dark:text-amber-400" : "text-gray-400 dark:text-gray-600"}>
                    {row.kev ? "Yes" : "No"}
                  </span>
                  <span className={`font-medium ${row.priColor}`}>{row.pri}</span>
                  <span className={`font-medium capitalize ${row.statusColor}`}>{row.status}</span>
                </div>
              ))}
            </div>
          </div>

          <p className="mt-6 text-center font-mono text-xs text-gray-500 dark:text-gray-400">
            app.vulnops.dev/findings · automatically ranked by KEV + EPSS + asset context
          </p>
        </div>
      </section>

      {/* ── Scanner logo strip ── */}
      <section className="border-y border-gray-200 bg-white py-10 dark:border-gray-800 dark:bg-gray-900/30">
        <div className="mx-auto max-w-7xl px-6 text-center">
          <p className="mb-6 font-mono text-xs uppercase tracking-widest text-amber-700 dark:text-amber-500">
            Integrates with the tools you already run
          </p>
          <div className="flex flex-wrap items-center justify-center gap-10">
            {["Tenable", "Qualys", "Rapid7", "Nessus", "Microsoft Defender"].map((name) => (
              <span key={name} className="text-sm font-semibold tracking-wide text-gray-500 transition-colors hover:text-gray-900 dark:text-gray-500 dark:hover:text-gray-200">
                {name}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Feature grid ── */}
      <section id="features" className="bg-white py-24 dark:bg-gray-900/30">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mx-auto max-w-xl text-center">
            <p className="mb-3 font-mono text-xs uppercase tracking-widest text-amber-700 dark:text-amber-500">
              Capabilities
            </p>
            <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
              Everything your team needs
            </h2>
            <p className="mt-4 text-gray-600 dark:text-gray-400">
              From ingestion to closure — the full vulnerability lifecycle in one tool.
            </p>
          </div>

          <div className="mt-16 grid gap-px overflow-hidden rounded-xl border border-gray-200 bg-gray-200 sm:grid-cols-2 lg:grid-cols-3 dark:border-gray-800 dark:bg-gray-800">
            {FEATURES.map((f) => (
              <div
                key={f.title}
                className="group relative bg-white p-8 transition-all hover:bg-amber-50/30 dark:bg-gray-900 dark:hover:bg-amber-950/10"
              >
                <div className="mb-5 inline-flex h-10 w-10 items-center justify-center rounded-lg border border-amber-200 bg-amber-50 transition-colors group-hover:border-amber-400 group-hover:bg-amber-100 dark:border-amber-900/60 dark:bg-amber-950/30 dark:group-hover:border-amber-700 dark:group-hover:bg-amber-950/60">
                  <f.icon
                    strokeWidth={1.5}
                    className="h-5 w-5 text-amber-700 dark:text-amber-400"
                  />
                </div>
                <h3 className="mb-2 text-base font-semibold text-gray-900 dark:text-gray-50">
                  {f.title}
                </h3>
                <p className="text-sm leading-relaxed text-gray-600 dark:text-gray-400">
                  {f.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Scanner connectors ── */}
      <section id="connectors" className="bg-surface-warm py-24">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid items-center gap-16 lg:grid-cols-2">
            <div>
              <div className="mb-5 inline-flex h-10 w-10 items-center justify-center rounded-lg border border-amber-200 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/30">
                <Plug strokeWidth={1.5} className="h-5 w-5 text-amber-700 dark:text-amber-400" />
              </div>
              <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
                Connect your scanners.
                <br />
                <span className="text-brand dark:text-brand-fg">Skip the CSVs.</span>
              </h2>
              <p className="mt-5 max-w-md leading-relaxed text-gray-600 dark:text-gray-400">
                VulnOps pulls findings directly from scanner APIs on a schedule you control.
                Credentials are stored encrypted per-org using field-level Fernet encryption —
                they never leave your instance.
              </p>
              <Link href="/register">
                <button className="mt-8 inline-flex items-center gap-2 text-sm font-semibold text-amber-800 underline-offset-4 hover:underline dark:text-amber-400">
                  Set up a connector
                  <ArrowUpRight strokeWidth={1.5} className="h-4 w-4" />
                </button>
              </Link>
            </div>

            <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-premium dark:border-gray-800 dark:bg-gray-900">
              <p className="mb-4 font-mono text-xs uppercase tracking-widest text-amber-700 dark:text-amber-500">
                Available connectors
              </p>
              <div className="space-y-3">
                {CONNECTORS.map((c) => {
                  const isLive = c.status === "live";
                  return (
                    <div
                      key={c.name}
                      className="flex items-center justify-between border-b border-gray-100 pb-3 last:border-0 last:pb-0 dark:border-gray-800"
                    >
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            isLive
                              ? "bg-amber-600 dark:bg-amber-400 ring-2 ring-amber-200 dark:ring-amber-900/60"
                              : "bg-gray-300 dark:bg-gray-600"
                          }`}
                        />
                        <span className="font-mono text-sm text-gray-800 dark:text-gray-200">
                          {c.name}
                        </span>
                      </div>
                      <span
                        className={`font-mono text-xs ${
                          isLive
                            ? "text-amber-700 dark:text-amber-400"
                            : "text-gray-400 dark:text-gray-500"
                        }`}
                      >
                        {c.status}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section id="deploy" className="bg-white py-24 dark:bg-gray-900/30">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mx-auto max-w-xl text-center">
            <p className="mb-3 font-mono text-xs uppercase tracking-widest text-amber-700 dark:text-amber-500">
              Getting started
            </p>
            <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
              Up and running in minutes
            </h2>
            <p className="mt-4 text-gray-600 dark:text-gray-400">
              Three steps from clone to production.
            </p>
          </div>

          <div className="mt-16 grid gap-8 sm:grid-cols-3">
            {STEPS.map((s) => (
              <div key={s.n} className="relative rounded-xl border border-gray-200 bg-white p-8 transition-shadow hover:shadow-premium dark:border-gray-800 dark:bg-gray-900">
                <p className="mb-5 font-mono text-2xl font-bold text-amber-700 dark:text-amber-400">
                  {s.n}
                </p>
                <h3 className="mb-3 text-lg font-semibold text-gray-900 dark:text-gray-50">
                  {s.title}
                </h3>
                <p className="text-sm leading-relaxed text-gray-600 dark:text-gray-400">
                  {s.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Built in the open (replaces pricing) ── */}
      <section className="bg-surface-warm py-24">
        <div className="mx-auto max-w-4xl px-6 text-center">
          <p className="mb-4 font-mono text-xs uppercase tracking-widest text-amber-700 dark:text-amber-500">
            An experimental side project
          </p>
          <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
            Built in the open. <span className="text-brand dark:text-brand-fg">Free forever.</span>
          </h2>
          <p className="mx-auto mt-5 max-w-xl text-lg text-gray-600 dark:text-gray-400">
            VulnOps is an open-source side project. No hosted edition, no pricing tiers,
            no lock-in. Clone it, run it on your own infrastructure, fork it if you need to.
          </p>

          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-11 items-center gap-2 rounded-md bg-gray-900 px-5 text-sm font-semibold text-white transition-colors hover:bg-gray-700 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-100"
            >
              <GitFork strokeWidth={1.5} className="h-4 w-4" />
              Clone the repo
            </a>
            <a
              href={`${REPO_URL}#readme`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-11 items-center gap-2 rounded-md border border-gray-300 bg-white px-5 text-sm font-medium text-gray-700 transition-colors hover:border-amber-400 hover:text-amber-800 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 dark:hover:border-amber-500 dark:hover:text-amber-400"
            >
              <BookOpen strokeWidth={1.5} className="h-4 w-4" />
              Read the docs
              <ArrowUpRight strokeWidth={1.5} className="h-4 w-4" />
            </a>
          </div>

          {/* Open-source facts strip */}
          <div className="mx-auto mt-12 grid max-w-2xl grid-cols-3 gap-6 border-t border-gray-200 pt-8 dark:border-gray-800">
            {[
              { n: "Apache 2.0", l: "Permissive license" },
              { n: "0", l: "Telemetry / callbacks" },
              { n: "∞", l: "Users · scans · orgs" },
            ].map((s) => (
              <div key={s.l} className="text-center">
                <p className="font-mono text-xl font-bold text-amber-700 dark:text-amber-400">{s.n}</p>
                <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">{s.l}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Security strip ── */}
      <section className="bg-white py-16 dark:bg-gray-900/30">
        <div className="mx-auto max-w-7xl px-6">
          <p className="mb-10 text-center font-mono text-xs uppercase tracking-widest text-amber-700 dark:text-amber-500">
            Built for security teams
          </p>
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
            {SECURITY_CLAIMS.map((c) => (
              <div key={c.label} className="text-center">
                <div className="mx-auto mb-3 inline-flex h-10 w-10 items-center justify-center rounded-lg border border-amber-200 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/30">
                  <c.icon
                    strokeWidth={1.5}
                    className="h-5 w-5 text-amber-700 dark:text-amber-400"
                  />
                </div>
                <p className="text-sm font-semibold text-gray-900 dark:text-gray-50">{c.label}</p>
                <p className="mt-0.5 font-mono text-xs text-gray-500 dark:text-gray-500">{c.sub}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section className="relative overflow-hidden bg-surface-warm py-24">
        <div className="amber-glow pointer-events-none absolute inset-0" />
        <div className="relative mx-auto max-w-2xl px-6 text-center">
          <h2 className="text-4xl font-bold tracking-[-0.035em] text-gray-900 dark:text-gray-50 sm:text-5xl">
            Ship the fix,<br />
            <span className="text-brand dark:text-brand-fg">not the spreadsheet.</span>
          </h2>
          <p className="mx-auto mt-5 max-w-md text-lg text-gray-600 dark:text-gray-400">
            Open source. Free forever. Running on your infra.
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link href="/register">
              <button className="inline-flex h-11 items-center gap-2 rounded-md bg-gray-900 px-6 text-sm font-semibold text-white transition-colors hover:bg-gray-700 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-100">
                Get started free
                <ArrowRight strokeWidth={1.5} className="h-4 w-4" />
              </button>
            </Link>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-11 items-center gap-2 rounded-md border border-gray-300 bg-white px-6 text-sm font-medium text-gray-700 transition-colors hover:border-amber-400 hover:text-amber-800 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 dark:hover:border-amber-500 dark:hover:text-amber-400"
            >
              <GitFork strokeWidth={1.5} className="h-4 w-4" />
              Star on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-gray-200 bg-white py-12 dark:border-gray-800 dark:bg-gray-900/50">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <div className="mb-4 flex items-center gap-2">
                <Shield strokeWidth={1.5} className="h-4 w-4 text-brand dark:text-brand-fg" />
                <span className="text-sm font-semibold text-gray-900 dark:text-gray-50">VulnOps</span>
              </div>
              <p className="text-xs leading-relaxed text-gray-500 dark:text-gray-400">
                Open-source vulnerability triage console. An experimental side project.
              </p>
            </div>

            <div>
              <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-gray-900 dark:text-gray-50">
                Product
              </p>
              <ul className="space-y-2.5">
                {[
                  { label: "Sign in", href: "/login" },
                  { label: "Register", href: "/register" },
                  { label: "Integrations", href: "#connectors" },
                ].map((l) => (
                  <li key={l.label}>
                    <Link href={l.href} className="text-xs text-gray-500 hover:text-amber-800 transition-colors dark:text-gray-400 dark:hover:text-amber-400">
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-gray-900 dark:text-gray-50">
                Open Source
              </p>
              <ul className="space-y-2.5">
                {[
                  { label: "GitHub", href: REPO_URL },
                  { label: "Apache 2.0 License", href: `${REPO_URL}/blob/main/LICENSE` },
                  { label: "Contributing", href: `${REPO_URL}/blob/main/CONTRIBUTING.md` },
                  { label: "Security Policy", href: `${REPO_URL}/blob/main/SECURITY.md` },
                ].map((l) => (
                  <li key={l.label}>
                    <a
                      href={l.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-gray-500 hover:text-amber-800 transition-colors dark:text-gray-400 dark:hover:text-amber-400"
                    >
                      {l.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-gray-900 dark:text-gray-50">
                Legal
              </p>
              <ul className="space-y-2.5">
                {[
                  { label: "Privacy Policy", href: "#" },
                  { label: "Terms of Service", href: "#" },
                ].map((l) => (
                  <li key={l.label}>
                    <a href={l.href} className="text-xs text-gray-500 hover:text-amber-800 transition-colors dark:text-gray-400 dark:hover:text-amber-400">
                      {l.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="mt-10 border-t border-gray-200 pt-6 dark:border-gray-800">
            <p className="font-mono text-xs text-gray-500 dark:text-gray-500">
              © {new Date().getFullYear()} VulnOps — Apache 2.0
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
