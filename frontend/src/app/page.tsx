"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  Shield, FileInput, Radar, ListOrdered, GitPullRequestArrow,
  BarChart3, ScrollText, Plug, Lock, KeyRound, ShieldCheck,
  FileCheck2, ArrowUpRight, Github, ArrowRight,
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
    fetch("https://api.github.com/repos/tekybala/vulnops", { cache: "no-store" })
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
    return <div className="min-h-screen bg-white dark:bg-[#0A0A0B]" />;
  }

  return (
    <div className="min-h-screen bg-white text-gray-900 dark:bg-[#0A0A0B] dark:text-gray-50">

      {/* ── Nav ── */}
      <header className="sticky top-0 z-50 border-b border-gray-200 bg-white/80 backdrop-blur-md dark:border-gray-800 dark:bg-[#0A0A0B]/80">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          {/* Wordmark */}
          <div className="flex items-center gap-2.5">
            <Shield strokeWidth={1.5} className="h-5 w-5 text-gray-900 dark:text-gray-50" />
            <span className="text-sm font-semibold tracking-tight">VulnOps</span>
            <span className="hidden rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] text-gray-400 sm:inline dark:border-gray-700 dark:bg-gray-900 dark:text-gray-500">
              Apache 2.0
            </span>
          </div>

          {/* Nav links */}
          <nav className="hidden items-center gap-6 text-sm text-gray-500 md:flex dark:text-gray-400">
            <a href="#features" className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors">Product</a>
            <a href="#connectors" className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors">Integrations</a>
            <a href="#deploy" className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors">Self-host</a>
            <a
              href="https://github.com/tekybala/vulnops"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-gray-900 dark:hover:text-gray-50 transition-colors"
            >
              GitHub
            </a>
          </nav>

          {/* Actions */}
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
      <section className="relative overflow-hidden border-b border-gray-200 dark:border-gray-800">
        {/* Dot grid background */}
        <div className="hero-dot-grid pointer-events-none absolute inset-0" />

        <div className="relative mx-auto max-w-5xl px-6 pb-28 pt-24 text-center">
          {/* Eyebrow pill */}
          <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-violet-200 bg-violet-50 px-3.5 py-1 font-mono text-xs font-medium text-violet-700 dark:border-violet-800/50 dark:bg-violet-950/40 dark:text-violet-400">
            Open source · Now with scanner APIs
          </div>

          {/* Headline */}
          <h1
            className="mx-auto max-w-3xl text-5xl font-bold leading-[1.08] tracking-[-0.035em] text-gray-900 sm:text-6xl lg:text-[72px] dark:text-gray-50"
          >
            Triage vulnerabilities
            <br />
            at the speed of scale.
          </h1>

          {/* Subline */}
          <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-gray-500 dark:text-gray-400">
            The open-source vulnerability triage console.
            Self-host in minutes, or use our hosted edition.
          </p>

          {/* CTAs */}
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link href="/register">
              <button className="inline-flex h-11 items-center gap-2 rounded-md bg-gray-900 px-5 text-sm font-semibold text-white transition-colors hover:bg-gray-700 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-100">
                Start self-hosting
                <ArrowRight strokeWidth={1.5} className="h-4 w-4" />
              </button>
            </Link>
            <Link href="/login">
              <button className="inline-flex h-11 items-center gap-2 rounded-md border border-gray-200 px-5 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900">
                View live demo
                <ArrowUpRight strokeWidth={1.5} className="h-4 w-4" />
              </button>
            </Link>
            <a
              href="https://github.com/tekybala/vulnops"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-11 items-center gap-2 rounded-md border border-gray-200 px-5 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900"
            >
              <Github strokeWidth={1.5} className="h-4 w-4" />
              Star on GitHub
              {stars !== "—" && (
                <span className="ml-0.5 rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs text-gray-500 dark:bg-gray-800 dark:text-gray-400">
                  {stars}
                </span>
              )}
            </a>
          </div>

          {/* Docker compose snippet */}
          <div className="mx-auto mt-8 inline-flex items-center gap-3 rounded-lg border border-gray-200 bg-gray-50 px-4 py-2.5 dark:border-gray-800 dark:bg-gray-900">
            <span className="font-mono text-xs text-gray-400 dark:text-gray-500">$</span>
            <span className="font-mono text-xs text-gray-700 dark:text-gray-300">
              docker compose up -d
            </span>
            <span className="font-mono text-xs text-gray-400 dark:text-gray-500">
              # running in &lt;5 min
            </span>
          </div>
        </div>
      </section>

      {/* ── Scanner logo strip ── */}
      <section className="border-b border-gray-200 py-8 dark:border-gray-800">
        <div className="mx-auto max-w-7xl px-6 text-center">
          <p className="mb-6 font-mono text-xs uppercase tracking-widest text-gray-400 dark:text-gray-500">
            Integrates with the tools you already run
          </p>
          <div className="flex flex-wrap items-center justify-center gap-8 opacity-50 grayscale">
            {["Tenable", "Qualys", "Rapid7", "Nessus", "Microsoft Defender"].map((name) => (
              <span key={name} className="text-sm font-semibold tracking-wide text-gray-600 dark:text-gray-400">
                {name}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Feature grid ── */}
      <section id="features" className="border-b border-gray-200 py-24 dark:border-gray-800">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mx-auto max-w-xl text-center">
            <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
              Everything your team needs
            </h2>
            <p className="mt-4 text-gray-500 dark:text-gray-400">
              From ingestion to closure — the full vulnerability lifecycle in one tool.
            </p>
          </div>

          <div className="mt-16 grid gap-px border border-gray-200 sm:grid-cols-2 lg:grid-cols-3 dark:border-gray-800">
            {FEATURES.map((f) => (
              <div
                key={f.title}
                className="group bg-white p-8 transition-shadow hover:shadow-premium dark:bg-[#0A0A0B]"
              >
                <f.icon
                  strokeWidth={1.5}
                  className="mb-5 h-6 w-6 text-gray-400 transition-colors group-hover:text-gray-700 dark:text-gray-500 dark:group-hover:text-gray-300"
                />
                <h3 className="mb-2 text-sm font-semibold text-gray-900 dark:text-gray-50">
                  {f.title}
                </h3>
                <p className="text-sm leading-relaxed text-gray-500 dark:text-gray-400">
                  {f.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Scanner connectors ── */}
      <section id="connectors" className="border-b border-gray-200 py-24 dark:border-gray-800">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid items-center gap-16 lg:grid-cols-2">
            {/* Left */}
            <div>
              <Plug
                strokeWidth={1.5}
                className="mb-5 h-6 w-6 text-gray-400 dark:text-gray-500"
              />
              <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
                Connect your scanners.
                <br />
                Skip the CSVs.
              </h2>
              <p className="mt-5 max-w-md text-gray-500 leading-relaxed dark:text-gray-400">
                VulnOps pulls findings directly from scanner APIs on a schedule you control.
                Credentials are stored encrypted per-org using field-level Fernet encryption
                — they never leave your instance.
              </p>
              <Link href="/register">
                <button className="mt-8 inline-flex items-center gap-2 text-sm font-medium text-gray-900 underline-offset-4 hover:underline dark:text-gray-50">
                  Set up a connector
                  <ArrowUpRight strokeWidth={1.5} className="h-4 w-4" />
                </button>
              </Link>
            </div>

            {/* Right — provider list */}
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-6 dark:border-gray-800 dark:bg-gray-900">
              <p className="mb-4 font-mono text-xs uppercase tracking-widest text-gray-400 dark:text-gray-500">
                Available connectors
              </p>
              <div className="space-y-3">
                {CONNECTORS.map((c) => (
                  <div
                    key={c.name}
                    className="flex items-center justify-between border-b border-gray-200 pb-3 last:border-0 last:pb-0 dark:border-gray-800"
                  >
                    <div className="flex items-center gap-2.5">
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          c.status === "live"
                            ? "bg-emerald-500"
                            : "bg-gray-300 dark:bg-gray-600"
                        }`}
                      />
                      <span className="font-mono text-sm text-gray-700 dark:text-gray-300">
                        {c.name}
                      </span>
                    </div>
                    <span
                      className={`font-mono text-xs ${
                        c.status === "live"
                          ? "text-emerald-600 dark:text-emerald-400"
                          : "text-gray-400 dark:text-gray-500"
                      }`}
                    >
                      {c.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section id="deploy" className="border-b border-gray-200 py-24 dark:border-gray-800">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mx-auto max-w-xl text-center">
            <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
              Up and running in minutes
            </h2>
            <p className="mt-4 text-gray-500 dark:text-gray-400">
              Three steps from clone to production.
            </p>
          </div>

          <div className="mt-16 grid gap-px border border-gray-200 sm:grid-cols-3 dark:border-gray-800">
            {STEPS.map((s) => (
              <div key={s.n} className="bg-white p-8 dark:bg-[#0A0A0B]">
                <p className="mb-5 font-mono text-xs text-gray-400 dark:text-gray-500">{s.n}</p>
                <h3 className="mb-3 text-lg font-semibold text-gray-900 dark:text-gray-50">
                  {s.title}
                </h3>
                <p className="text-sm leading-relaxed text-gray-500 dark:text-gray-400">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Self-host vs hosted ── */}
      <section className="border-b border-gray-200 py-24 dark:border-gray-800">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mx-auto max-w-xl text-center">
            <h2 className="text-3xl font-bold tracking-[-0.025em] text-gray-900 dark:text-gray-50 sm:text-4xl">
              Your data, your infra — or ours.
            </h2>
            <p className="mt-4 text-gray-500 dark:text-gray-400">
              Same code, same features. The hosted edition runs the OSS build.
            </p>
          </div>

          <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:gap-8">
            {/* Self-host card */}
            <div className="rounded-lg border border-gray-200 p-8 dark:border-gray-800">
              <div className="mb-1 text-xs font-mono uppercase tracking-widest text-gray-400 dark:text-gray-500">
                Self-host
              </div>
              <div className="mt-3 text-2xl font-bold text-gray-900 dark:text-gray-50">
                Free forever.
              </div>
              <div className="mt-1 font-mono text-sm text-gray-500 dark:text-gray-400">
                Apache 2.0
              </div>
              <ul className="mt-6 space-y-2.5">
                {[
                  "Unlimited users and scans",
                  "All connectors included",
                  "No telemetry, no callbacks",
                  "Full source on GitHub",
                  "Docker Compose or bare-metal",
                ].map((item) => (
                  <li key={item} className="flex items-center gap-2.5 text-sm text-gray-600 dark:text-gray-400">
                    <span className="h-1 w-1 rounded-full bg-gray-400 dark:bg-gray-500" />
                    {item}
                  </li>
                ))}
              </ul>
              <a
                href="https://github.com/tekybala/vulnops"
                target="_blank"
                rel="noopener noreferrer"
                className="mt-8 inline-flex items-center gap-2 rounded-md border border-gray-200 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900"
              >
                <Github strokeWidth={1.5} className="h-4 w-4" />
                Clone the repo
              </a>
            </div>

            {/* Hosted card */}
            <div className="rounded-lg border border-gray-200 p-8 dark:border-gray-800">
              <div className="flex items-center gap-2">
                <div className="text-xs font-mono uppercase tracking-widest text-gray-400 dark:text-gray-500">
                  Hosted
                </div>
                <span className="rounded-full bg-violet-50 px-2 py-0.5 font-mono text-[10px] font-medium text-violet-700 dark:bg-violet-950/40 dark:text-violet-400">
                  Coming soon
                </span>
              </div>
              <div className="mt-3 text-2xl font-bold text-gray-900 dark:text-gray-50">
                Zero ops.
              </div>
              <div className="mt-1 font-mono text-sm text-gray-500 dark:text-gray-400">
                Managed by us
              </div>
              <ul className="mt-6 space-y-2.5">
                {[
                  "Same feature set as self-host",
                  "Automatic updates and backups",
                  "SSO on request",
                  "SLA and support tiers",
                  "Affordable monthly pricing",
                ].map((item) => (
                  <li key={item} className="flex items-center gap-2.5 text-sm text-gray-600 dark:text-gray-400">
                    <span className="h-1 w-1 rounded-full bg-gray-400 dark:bg-gray-500" />
                    {item}
                  </li>
                ))}
              </ul>
              <Link href="/register">
                <button className="mt-8 inline-flex items-center gap-2 rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-gray-700 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-100">
                  Join the waitlist
                  <ArrowRight strokeWidth={1.5} className="h-4 w-4" />
                </button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ── Security strip ── */}
      <section className="border-b border-gray-200 py-16 dark:border-gray-800">
        <div className="mx-auto max-w-7xl px-6">
          <p className="mb-8 text-center font-mono text-xs uppercase tracking-widest text-gray-400 dark:text-gray-500">
            Built for security teams
          </p>
          <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
            {SECURITY_CLAIMS.map((c) => (
              <div key={c.label} className="text-center">
                <c.icon
                  strokeWidth={1.5}
                  className="mx-auto mb-2.5 h-5 w-5 text-gray-400 dark:text-gray-500"
                />
                <p className="text-sm font-medium text-gray-900 dark:text-gray-50">{c.label}</p>
                <p className="mt-0.5 font-mono text-xs text-gray-400 dark:text-gray-500">{c.sub}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section className="py-24">
        <div className="mx-auto max-w-2xl px-6 text-center">
          <h2 className="text-4xl font-bold tracking-[-0.035em] text-gray-900 dark:text-gray-50 sm:text-5xl">
            Ship the fix,<br />not the spreadsheet.
          </h2>
          <p className="mx-auto mt-5 max-w-md text-lg text-gray-500 dark:text-gray-400">
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
              href="https://github.com/tekybala/vulnops"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-11 items-center gap-2 rounded-md border border-gray-200 px-6 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-900"
            >
              <Github strokeWidth={1.5} className="h-4 w-4" />
              Star on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-gray-200 py-12 dark:border-gray-800">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
            {/* Brand */}
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Shield strokeWidth={1.5} className="h-4 w-4 text-gray-900 dark:text-gray-50" />
                <span className="text-sm font-semibold text-gray-900 dark:text-gray-50">VulnOps</span>
              </div>
              <p className="text-xs leading-relaxed text-gray-400 dark:text-gray-500">
                Open-source vulnerability triage console for security teams.
              </p>
            </div>

            {/* Product */}
            <div>
              <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-gray-900 dark:text-gray-50">
                Product
              </p>
              <ul className="space-y-2.5">
                {[
                  { label: "Sign in", href: "/login" },
                  { label: "Register", href: "/register" },
                ].map((l) => (
                  <li key={l.label}>
                    <Link href={l.href} className="text-xs text-gray-500 hover:text-gray-900 transition-colors dark:text-gray-400 dark:hover:text-gray-50">
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            {/* Open Source */}
            <div>
              <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-gray-900 dark:text-gray-50">
                Open Source
              </p>
              <ul className="space-y-2.5">
                {[
                  { label: "GitHub", href: "https://github.com/tekybala/vulnops" },
                  { label: "Apache 2.0 License", href: "https://github.com/tekybala/vulnops/blob/main/LICENSE" },
                  { label: "Contributing", href: "https://github.com/tekybala/vulnops/blob/main/CONTRIBUTING.md" },
                  { label: "Security Policy", href: "https://github.com/tekybala/vulnops/blob/main/SECURITY.md" },
                ].map((l) => (
                  <li key={l.label}>
                    <a
                      href={l.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-gray-500 hover:text-gray-900 transition-colors dark:text-gray-400 dark:hover:text-gray-50"
                    >
                      {l.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Legal */}
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
                    <a href={l.href} className="text-xs text-gray-500 hover:text-gray-900 transition-colors dark:text-gray-400 dark:hover:text-gray-50">
                      {l.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="mt-10 border-t border-gray-200 pt-6 dark:border-gray-800">
            <p className="font-mono text-xs text-gray-400 dark:text-gray-500">
              © {new Date().getFullYear()} VulnOps — Apache 2.0
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
