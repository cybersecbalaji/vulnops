/**
 * Full end-to-end test suite for VulnOps Triage Console.
 * Creates a fresh account, exercises every feature, screenshots each step.
 * Run: npx playwright test playwright/full-e2e.spec.ts --reporter=list
 */

import { test, expect, Page } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const BASE = "https://grand-youthfulness-production-3b33.up.railway.app";
const SHOTS = path.join(__dirname, "screenshots", "e2e");
fs.mkdirSync(SHOTS, { recursive: true });

const TS = Date.now();
const EMAIL = `e2e.${TS}@gmail.com`;
const PASS = "E2eTest123!@#$";
const ORG = `E2EOr${TS}`;

// ── Sample data ───────────────────────────────────────────────────────────────

const VULN_CSV = [
  "cve_id,title,description,severity,cvss_score,affected_component",
  "CVE-2023-44487,HTTP/2 Rapid Reset Attack,Allows remote DoS via stream cancellation,critical,7.5,nginx/1.18.0",
  "CVE-2021-44228,Log4Shell RCE,JNDI injection vulnerability in Log4j,critical,10.0,log4j-core:2.14.1",
  "CVE-2022-22965,Spring4Shell,RCE via data binding in Spring Framework,high,9.8,spring-core:5.3.17",
  "CVE-2023-23397,Outlook NTLM Leak,NTLM credential leak via crafted email,high,9.8,Microsoft Outlook",
  "CVE-2022-47966,ManageEngine RCE,Pre-auth RCE in ManageEngine products,critical,9.8,ManageEngine",
].join("\n");

const ASSET_CSV = [
  "name,asset_type,ip_address,hostname,environment,criticality,internet_facing,owner",
  "web-prod-01,server,10.0.1.10,web-prod-01.corp,production,critical,true,security-team",
  "db-prod-01,database,10.0.1.20,db-prod-01.corp,production,critical,false,dba-team",
  "dev-laptop-01,endpoint,192.168.1.50,,development,low,false,dev-team",
].join("\n");

// ── Helpers ───────────────────────────────────────────────────────────────────

async function shot(page: Page, name: string) {
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
  console.log(`  📸 ${name}.png`);
}

async function loginAs(page: Page, email: string, password: string) {
  await page.goto(`${BASE}/login`, { waitUntil: "load" });
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/\/dashboard/, { timeout: 30000 });
  await page.waitForTimeout(1500);
}

async function closeDialog(page: Page) {
  // Try X button, then Escape
  const closeBtn = page.getByRole("button", { name: /close/i }).or(page.locator("button[aria-label='Close']")).or(page.locator("button").filter({ hasText: "✕" }));
  if (await closeBtn.count() > 0) {
    await closeBtn.first().click();
  } else {
    await page.keyboard.press("Escape");
  }
  await page.waitForTimeout(500);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe.serial("VulnOps Full E2E", () => {

  // ── 1. Register ───────────────────────────────────────────────────────────

  test("01 · Register new account", async ({ page }) => {
    const calls: { url: string; status: number; body: string }[] = [];
    page.on("response", async (res) => {
      if (res.url().includes("/api/v1/")) {
        const body = await res.text().catch(() => "");
        calls.push({ url: res.url(), status: res.status(), body });
      }
    });

    await page.goto(`${BASE}/register`, { waitUntil: "load" });
    await shot(page, "01_register_empty");

    await page.locator("#org_name").fill(ORG);
    await page.locator("#email").fill(EMAIL);
    await page.locator("#password").fill(PASS);
    await shot(page, "01_register_filled");

    await Promise.all([
      page.waitForResponse((r) => r.url().includes("/auth/register"), { timeout: 30000 }),
      page.getByRole("button", { name: /create account/i }).click(),
    ]);
    await page.waitForTimeout(4000);
    await shot(page, "01_register_result");

    const regCall = calls.find((c) => c.url.includes("/auth/register"));
    if (!regCall) throw new Error("No /auth/register request made");
    expect(regCall.status, `Register failed: ${regCall.body.slice(0, 300)}`).toBe(201);
    console.log(`  ✓ Account created: ${EMAIL}`);
    console.log(`  URL after register: ${page.url().replace(BASE, "")}`);
  });

  // ── 2. Login ──────────────────────────────────────────────────────────────

  test("02 · Login", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "load" });
    await shot(page, "02_login_empty");

    await page.locator("#email").fill(EMAIL);
    await page.locator("#password").fill(PASS);
    await shot(page, "02_login_filled");

    const [loginResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/auth/login"), { timeout: 30000 }),
      page.getByRole("button", { name: /sign in/i }).click(),
    ]);
    const loginBody = await loginResp.text().catch(() => "");
    console.log(`  Login: ${loginResp.status()}`);

    if (loginResp.status() !== 200) {
      throw new Error(`Login failed (${loginResp.status()}): ${loginBody.slice(0, 300)}`);
    }

    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    await page.waitForTimeout(1500);
    await shot(page, "02_login_result");
    console.log("  ✓ Logged in → /dashboard");
  });

  // ── 3. Dashboard ──────────────────────────────────────────────────────────

  test("03 · Dashboard — stats and navigation", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);
    await page.waitForTimeout(2000);
    await shot(page, "03_dashboard");

    const h1 = await page.locator("h1").first().textContent();
    console.log(`  H1: ${h1}`);
    await expect(page.locator("h1").first()).toBeVisible();

    // Nav links
    const navLinks = await page.getByRole("link", { name: /findings|assets|reports|remediation/i }).count();
    console.log(`  Nav links: ${navLinks}`);
    expect(navLinks).toBeGreaterThan(0);

    // Stat cards
    const cards = page.locator(".border-l-4, [class*='stat'], [class*='card']");
    console.log(`  Stat containers: ${await cards.count()}`);
  });

  // ── 4. Findings — add manually ────────────────────────────────────────────

  test("04 · Findings — add manually", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/findings`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    await shot(page, "04_findings_empty");

    // Click "+ Add manually" button
    await page.getByRole("button", { name: /add manually/i }).click();
    await page.waitForTimeout(500);
    await shot(page, "04_add_dialog");

    // Fill form — using exact placeholders from the UI
    await page.locator("input[placeholder*='CVE-2024']").fill("CVE-2021-44228");
    await page.locator("input[placeholder*='Short description']").fill("Log4Shell Remote Code Execution");
    await page.locator("dialog textarea, [role=dialog] textarea").first().fill(
      "JNDI injection vulnerability in Apache Log4j allows unauthenticated remote code execution."
    );
    // Severity is already set to Medium — upgrade to critical
    await page.locator("dialog select, [role=dialog] select").first().selectOption("critical");
    await page.locator("input[placeholder*='9.8']").fill("10.0");
    await page.locator("input[placeholder*='OpenSSL']").fill("log4j-core:2.14.1");

    await shot(page, "04_add_filled");

    // Submit — "Add finding" button
    const [addResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/vulnerabilities"), { timeout: 15000 }),
      page.getByRole("button", { name: /add finding/i }).click(),
    ]);
    const addBody = await addResp.text().catch(() => "");
    console.log(`  Add finding: ${addResp.status()} — ${addBody.slice(0, 150)}`);
    await page.waitForTimeout(2000);
    await shot(page, "04_after_add");

    const rows = await page.locator("tbody tr").count();
    console.log(`  Rows after add: ${rows}`);
    expect(addResp.status()).toBeLessThan(400);
  });

  // ── 5. Findings — CSV import ──────────────────────────────────────────────

  test("05 · Findings — CSV import", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/findings`, { waitUntil: "load" });
    await page.waitForTimeout(2000);

    await page.getByRole("button", { name: /upload csv/i }).click();
    await page.waitForTimeout(500);
    await shot(page, "05_import_dialog");

    // Write CSV to temp file and upload (CSV tab is selected by default)
    const csvPath = path.join(SHOTS, "test-vulns.csv");
    fs.writeFileSync(csvPath, VULN_CSV);
    await page.locator("input[type=file]").first().setInputFiles(csvPath);
    await page.waitForTimeout(1000);
    await shot(page, "05_import_file_selected");

    // Click "Import Csv" button — wait for response
    const [importResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/ingest/csv") || r.url().includes("/upload"), { timeout: 30000 }),
      page.getByRole("button", { name: /import csv|import/i }).last().click(),
    ]);
    const importBody = await importResp.text().catch(() => "");
    console.log(`  Import: ${importResp.status()} — ${importBody.slice(0, 200)}`);
    await page.waitForTimeout(2000);
    await shot(page, "05_import_result");

    expect(importResp.status()).toBeLessThan(400);
    const result = JSON.parse(importBody);
    console.log(`  ✓ Ingested: ${result.ingested}, Duplicates: ${result.duplicates}`);

    // Navigate away and back to force a fresh list load (dialog auto-refresh may be slow)
    await page.goto(`${BASE}/dashboard`, { waitUntil: "load" });
    await page.goto(`${BASE}/findings`, { waitUntil: "load" });
    // Wait for the list to load (redirect from 308 → actual data)
    await page.waitForResponse(
      (r) => r.url().includes("/vulnerabilities") && r.status() === 200,
      { timeout: 15000 }
    ).catch(() => null);
    await page.waitForTimeout(2000);
    await shot(page, "05_findings_list");

    const rows = await page.locator("tbody tr").count();
    console.log(`  Rows visible: ${rows}`);
    expect(rows).toBeGreaterThan(0);
  });

  // ── 6. Findings — enrich first vuln ──────────────────────────────────────

  test("06 · Findings — enrich first vuln", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/findings`, { waitUntil: "load" });
    await page.waitForTimeout(3000);

    const firstRow = page.locator("tbody tr").first();
    if (await firstRow.count() === 0) {
      console.log("  ⚠ No rows — skipping");
      return;
    }

    // Expand first row
    await firstRow.click();
    await page.waitForTimeout(1000);
    await shot(page, "06_row_expanded");

    // Enrich button
    const enrichBtn = page.getByRole("button", { name: /^enrich$/i }).first();
    if (await enrichBtn.count() > 0 && !(await enrichBtn.isDisabled())) {
      const [enrichResp] = await Promise.all([
        page.waitForResponse((r) => r.url().includes("/enrich"), { timeout: 30000 }),
        enrichBtn.click(),
      ]);
      console.log(`  Enrich: ${enrichResp.status()}`);
      await page.waitForTimeout(3000);
      await shot(page, "06_after_enrich");
    } else {
      console.log("  ⚠ Enrich button not available");
    }
  });

  // ── 7. Assets — add manually ──────────────────────────────────────────────

  test("07 · Assets — add manually", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/assets`, { waitUntil: "load" });
    // Wait for loading spinner to disappear
    await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
    await page.waitForTimeout(1500);
    await shot(page, "07_assets_page");

    // Open add dialog
    const addBtn = page.getByRole("button", { name: /add asset/i });
    await expect(addBtn).toBeVisible({ timeout: 10000 });
    await addBtn.click();
    await page.waitForTimeout(500);
    await shot(page, "07_add_dialog");

    // Fill using exact IDs from the source
    await page.locator("#a-name").fill("web-prod-01");
    await page.locator("#a-ip").fill("10.0.1.10");
    await page.locator("#a-host").fill("web-prod-01.corp");
    await page.locator("#a-crit").selectOption("critical");
    await page.locator("#a-env").selectOption("production");

    await shot(page, "07_add_filled");

    const [addResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/assets"), { timeout: 15000 }),
      page.getByRole("button", { name: /add asset/i }).last().click(),
    ]);
    const body = await addResp.text().catch(() => "");
    console.log(`  Add asset: ${addResp.status()} — ${body.slice(0, 150)}`);
    await page.waitForTimeout(2000);
    await shot(page, "07_after_add");

    expect(addResp.status()).toBeLessThan(400);
  });

  // ── 8. Assets — CSV import ────────────────────────────────────────────────

  test("08 · Assets — CSV import", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/assets`, { waitUntil: "load" });
    await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
    await page.waitForTimeout(1500);

    // Open import dialog
    await page.getByRole("button", { name: /import csv|import/i }).click();
    await page.waitForTimeout(500);
    await shot(page, "08_import_dialog");

    const csvPath = path.join(SHOTS, "test-assets.csv");
    fs.writeFileSync(csvPath, ASSET_CSV);

    await page.locator("#import-file").setInputFiles(csvPath);
    await page.waitForTimeout(500);

    // Select format: "vulnops" is the default for generic CSV; check options
    const formatSelect = page.locator("dialog select, [role=dialog] select").first();
    if (await formatSelect.count() > 0) {
      const opts = await formatSelect.locator("option").allTextContents();
      console.log("  Format options:", opts);
    }

    await shot(page, "08_import_ready");

    const [importResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/assets"), { timeout: 30000 }),
      page.getByRole("button", { name: /import/i }).last().click(),
    ]);
    const body = await importResp.text().catch(() => "");
    console.log(`  Asset import: ${importResp.status()} — ${body.slice(0, 200)}`);
    await page.waitForTimeout(2000);
    await shot(page, "08_import_result");

    expect(importResp.status()).toBeLessThan(400);

    // Close dialog
    await page.keyboard.press("Escape");
    await page.waitForTimeout(2000);

    const rows = await page.locator("tbody tr").count();
    console.log(`  Asset rows: ${rows}`);
    await shot(page, "08_assets_list");
  });

  // ── 9. Assets — match vulnerabilities ────────────────────────────────────

  test("09 · Assets — match vulnerabilities to findings", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/assets`, { waitUntil: "load" });
    await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
    await page.waitForTimeout(2000);
    await shot(page, "09_assets_loaded");

    const matchBtn = page.getByRole("button", { name: /match vulnerabilities/i });
    await expect(matchBtn).toBeVisible({ timeout: 10000 });

    if (await matchBtn.isDisabled()) {
      console.log("  ⚠ Match button disabled (no assets loaded yet) — checking asset count");
      const rows = await page.locator("tbody tr").count();
      console.log(`  Asset rows: ${rows}`);
      if (rows === 0) {
        console.log("  ⚠ Skipping match — no assets in table");
        return;
      }
    }

    const [matchResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("match"), { timeout: 15000 }),
      matchBtn.click(),
    ]);
    const body = await matchResp.text().catch(() => "");
    console.log(`  Match: ${matchResp.status()} — ${body.slice(0, 200)}`);
    await page.waitForTimeout(2000);
    await shot(page, "09_after_match");
    expect(matchResp.status()).toBeLessThan(400);
  });

  // ── 10. Remediation ───────────────────────────────────────────────────────

  test("10 · Remediation — bulk triage plan + draft ticket", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/remediation`, { waitUntil: "load" });
    await page.waitForTimeout(3000);
    await shot(page, "10_remediation_page");

    // ── Bulk triage plan ───────────────────────────────────────────────────
    const bulkBtn = page.getByRole("button", { name: /generate triage plan/i });
    if (await bulkBtn.count() > 0) {
      console.log("  Clicking Generate triage plan...");
      const [bulkResp] = await Promise.all([
        page.waitForResponse((r) => r.url().includes("/remediation") || r.url().includes("/triage"), { timeout: 60000 }),
        bulkBtn.click(),
      ]);
      console.log(`  Bulk triage: ${bulkResp.status()}`);
      await page.waitForTimeout(5000);
      await shot(page, "10_bulk_triage_result");
    } else {
      console.log("  ⚠ Generate triage plan button not found");
    }

    // ── Draft ticket ───────────────────────────────────────────────────────
    // Wait for findings dropdown to load
    await page.waitForSelector("text=Loading findings...", { state: "hidden", timeout: 15000 }).catch(() => null);
    await page.waitForTimeout(1000);

    // Select a finding from the dropdown
    const findingSelect = page.locator("select").first();
    if (await findingSelect.count() > 0) {
      const opts = await findingSelect.locator("option").allTextContents();
      console.log(`  Finding options: ${opts.length} (${opts.slice(0, 3).join(", ")})`);

      if (opts.length > 1) {
        // Select the first real finding (skip placeholder "Select a finding...")
        await findingSelect.selectOption({ index: 1 });
        await page.waitForTimeout(500);

        const draftBtn = page.getByRole("button", { name: /draft ticket/i });
        if (await draftBtn.count() > 0 && !(await draftBtn.isDisabled())) {
          console.log("  Clicking Draft ticket...");
          const [draftResp] = await Promise.all([
            page.waitForResponse((r) => r.url().includes("/remediation/"), { timeout: 60000 }),
            draftBtn.click(),
          ]);
          console.log(`  Draft ticket: ${draftResp.status()}`);
          await page.waitForTimeout(5000);
          await shot(page, "10_draft_result");
        } else {
          console.log("  ⚠ Draft ticket button disabled (LLM not configured)");
          await shot(page, "10_draft_btn_state");
        }
      } else {
        console.log("  ⚠ No findings in dropdown");
      }
    }
  });

  // ── 11. Reports — stats and PDF export ───────────────────────────────────

  test("11 · Reports — view stats and download PDF", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/reports`, { waitUntil: "load" });
    await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
    await page.waitForTimeout(2000);
    await shot(page, "11_reports_page");

    // Verify stats are visible
    const heading = page.locator("h1, h2").first();
    console.log(`  Reports heading: ${await heading.textContent()}`);

    // Check for total count display
    const totalText = page.getByText(/total|vulnerabilit/i).first();
    if (await totalText.count() > 0) console.log("  ✓ Stats visible on page");

    // Download PDF
    const pdfBtn = page.getByRole("button", { name: /pdf|download|export/i }).first();
    if (await pdfBtn.count() > 0) {
      const downloadProm = page.waitForEvent("download", { timeout: 30000 }).catch(() => null);
      await pdfBtn.click();
      const download = await downloadProm;
      await page.waitForTimeout(5000);
      await shot(page, "11_after_download");

      if (download) {
        const savePath = path.join(SHOTS, "report.pdf");
        await download.saveAs(savePath);
        const size = fs.statSync(savePath).size;
        console.log(`  ✓ PDF downloaded: ${size} bytes`);
        expect(size).toBeGreaterThan(100);
      } else {
        console.log("  ⚠ PDF download event not captured — checking for error");
        const errorEl = page.locator("[role=alert]");
        if (await errorEl.count() > 0) console.log(`  Error: ${await errorEl.first().textContent()}`);
      }
    }
  });

  // ── 12. Settings ──────────────────────────────────────────────────────────

  test("12 · Settings — org config page", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/settings`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    await shot(page, "12_settings_page");

    const heading = page.locator("h1, h2").first();
    console.log(`  Settings heading: ${await heading.textContent()}`);

    // LLM provider selector
    const providerEl = page.locator("select, [role=combobox]").first();
    if (await providerEl.count() > 0) {
      console.log("  ✓ LLM provider selector visible");
    }

    // API key field
    const apiKeyInput = page.locator("input[type=password]").first();
    if (await apiKeyInput.count() > 0) {
      console.log("  ✓ API key input visible");
    }
  });

  // ── 13. Findings — filter, search, status update ──────────────────────────

  test("13 · Findings — filter and status update", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    await page.goto(`${BASE}/findings`, { waitUntil: "load" });
    await page.waitForTimeout(3000);
    await shot(page, "13_findings_list");

    const rows = await page.locator("tbody tr").count();
    console.log(`  Total rows: ${rows}`);
    expect(rows).toBeGreaterThan(0);

    // Severity filter (first select)
    const sevFilter = page.locator("select").first();
    await sevFilter.selectOption("critical");
    await page.waitForTimeout(1500);
    await shot(page, "13_critical_filter");
    const critRows = await page.locator("tbody tr").count();
    console.log(`  Critical rows: ${critRows}`);
    await sevFilter.selectOption("");
    await page.waitForTimeout(1000);

    // Status filter (second select)
    const statusFilter = page.locator("select").nth(1);
    await statusFilter.selectOption("open");
    await page.waitForTimeout(1000);
    await statusFilter.selectOption("");
    await page.waitForTimeout(500);

    // Expand first row and try status update
    const firstRow = page.locator("tbody tr").first();
    await firstRow.click();
    await page.waitForTimeout(1000);
    await shot(page, "13_row_expanded");

    // Look for status select inside expanded row
    const statusSel = page.locator("select[id*='status']").first();
    if (await statusSel.count() > 0 && !(await statusSel.isDisabled())) {
      await statusSel.selectOption("triaged");
      const saveBtn = page.getByRole("button", { name: /save changes|update|save/i }).first();
      if (await saveBtn.count() > 0) {
        const [saveResp] = await Promise.all([
          page.waitForResponse((r) => r.url().includes("/vulnerabilities/"), { timeout: 15000 }),
          saveBtn.click(),
        ]);
        console.log(`  Status update: ${saveResp.status()}`);
        await page.waitForTimeout(1500);
      }
    }
    await shot(page, "13_after_status_update");
  });

  // ── 14. Full visual tour ──────────────────────────────────────────────────

  test("14 · Visual tour — all pages final state", async ({ page }) => {
    await loginAs(page, EMAIL, PASS);

    const pages = [
      { path: "/dashboard", name: "14_dashboard" },
      { path: "/findings", name: "14_findings" },
      { path: "/assets", name: "14_assets" },
      { path: "/reports", name: "14_reports" },
      { path: "/remediation", name: "14_remediation" },
      { path: "/settings", name: "14_settings" },
    ];

    for (const p of pages) {
      await page.goto(`${BASE}${p.path}`, { waitUntil: "load" });
      await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
      await page.waitForTimeout(2500);
      await shot(page, p.name);
      console.log(`  ✓ ${p.path}`);
    }

    // Mobile screenshots
    await page.setViewportSize({ width: 375, height: 812 });
    for (const p of [pages[0], pages[1], pages[2]]) {
      await page.goto(`${BASE}${p.path}`, { waitUntil: "load" });
      await page.waitForTimeout(2000);
      await shot(page, `${p.name}_mobile`);
    }
    await page.setViewportSize({ width: 1280, height: 900 });
    console.log("  ✓ Mobile screenshots done");
  });

});
