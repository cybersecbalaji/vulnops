/**
 * Live workflow check — navigates the real Railway app, tests every feature,
 * screenshots every step. Run: npx playwright test playwright/live-check.spec.ts --reporter=list
 */
import { test, Page } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const BASE = "https://grand-youthfulness-production-3b33.up.railway.app";
const DIR = path.join(__dirname, "screenshots", "live");
fs.mkdirSync(DIR, { recursive: true });

const TS = Date.now();
const EMAIL = `live.${TS}@gmail.com`;
const PASS = "LiveTest123!@#$";
const ORG = `LiveOrg${TS}`;

const VULN_CSV = [
  "cve_id,title,description,severity,cvss_score,affected_component",
  "CVE-2021-44228,Log4Shell,JNDI injection RCE in Log4j 2.x,critical,10.0,log4j-core:2.14.1",
  "CVE-2022-22965,Spring4Shell,RCE in Spring Framework via data binding,high,9.8,spring-core:5.3.17",
  "CVE-2023-44487,HTTP/2 Rapid Reset,DoS via rapid stream cancellation,high,7.5,nginx/1.18",
].join("\n");

const ASSET_CSV = [
  "name,asset_type,ip_address,hostname,environment,criticality,internet_facing,owner",
  "web-prod-01,server,10.0.1.10,web-prod-01.corp,production,critical,true,security-team",
  "db-prod-01,database,10.0.1.20,db-prod-01.corp,production,critical,false,dba-team",
].join("\n");

async function shot(page: Page, name: string) {
  const p = path.join(DIR, `${name}.png`);
  await page.screenshot({ path: p, fullPage: true });
  console.log(`📸 ${name}`);
}

async function waitForListLoad(page: Page, keyword: string, timeout = 15000) {
  // Wait for a 200 response from an API endpoint containing keyword
  await page.waitForResponse(
    (r) => r.url().includes(keyword) && r.status() === 200,
    { timeout }
  ).catch(() => null);
  await page.waitForTimeout(1500);
}

test("Live app workflow check", async ({ page }) => {
  test.setTimeout(300000); // 5 min

  // ══════════════════════════════════════════════════════
  // 1. HOMEPAGE
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 1. HOMEPAGE ═══");
  await page.goto(BASE, { waitUntil: "load" });
  await page.waitForTimeout(2000);
  await shot(page, "01_homepage");
  const h1 = await page.locator("h1").first().textContent().catch(() => "none");
  console.log(`H1: ${h1}`);

  // ══════════════════════════════════════════════════════
  // 2. REGISTER
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 2. REGISTER ═══");
  await page.goto(`${BASE}/register`, { waitUntil: "load" });
  await page.waitForTimeout(1000);
  await shot(page, "02_register");

  await page.locator("#org_name").fill(ORG);
  await page.locator("#email").fill(EMAIL);
  await page.locator("#password").fill(PASS);

  const [regResp] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/auth/register"), { timeout: 20000 }),
    page.getByRole("button", { name: /create account/i }).click(),
  ]);
  const regBody = await regResp.text().catch(() => "");
  console.log(`Register: ${regResp.status()} — ${regBody.slice(0, 120)}`);
  await page.waitForTimeout(3000);
  await shot(page, "02_register_result");
  console.log(`URL: ${page.url().replace(BASE, "")}`);

  // ══════════════════════════════════════════════════════
  // 3. LOGIN (we're already logged in after register — just verify dashboard)
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 3. DASHBOARD (already logged in after register) ═══");
  await page.goto(`${BASE}/dashboard`, { waitUntil: "load" });
  await page.waitForTimeout(2000);
  await shot(page, "03_dashboard");
  console.log(`URL: ${page.url().replace(BASE, "")}`);

  // ══════════════════════════════════════════════════════
  // 4. FINDINGS — check list loads
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 4. FINDINGS — initial state ═══");
  await page.goto(`${BASE}/findings`, { waitUntil: "load" });
  await waitForListLoad(page, "/vulnerabilities");
  await shot(page, "04_findings_initial");
  const findingsBefore = await page.locator("tbody tr").count();
  const findingsError = await page.locator("text=Failed, text=Not Found, text=Error").count();
  console.log(`Rows: ${findingsBefore}, Errors: ${findingsError}`);
  const pageText = await page.locator("body").textContent().catch(() => "");
  if (pageText?.includes("Failed") || pageText?.includes("Not Found")) {
    console.log("⚠ Page shows error — capturing full page text snippet:");
    console.log(pageText?.slice(0, 300));
  }

  // ══════════════════════════════════════════════════════
  // 5. FINDINGS — add manually
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 5. FINDINGS — add manually ═══");
  await page.getByRole("button", { name: /add manually/i }).click();
  await page.waitForTimeout(800);
  await shot(page, "05_add_dialog");

  // Fill fields using actual placeholder text from the UI
  await page.locator("input[placeholder*='CVE-2024']").fill("CVE-2021-44228");
  await page.locator("input[placeholder*='Short description']").fill("Log4Shell Remote Code Execution");
  await page.locator("dialog textarea, [role=dialog] textarea").first()
    .fill("Critical RCE via JNDI injection in Log4j. Actively exploited.");
  await page.locator("dialog select, [role=dialog] select").first().selectOption("critical");
  await page.locator("input[placeholder*='9.8']").fill("10.0");
  await shot(page, "05_add_filled");

  const [addResp] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/vulnerabilities"), { timeout: 20000 }),
    page.getByRole("button", { name: /add finding/i }).click(),
  ]);
  const addBody = await addResp.text().catch(() => "");
  console.log(`Add finding: ${addResp.status()} — ${addBody.slice(0, 200)}`);
  await page.waitForTimeout(3000);
  await shot(page, "05_after_add");

  // Reload findings page to see updated list
  await page.goto(`${BASE}/findings`, { waitUntil: "load" });
  await waitForListLoad(page, "/vulnerabilities");
  await shot(page, "05_findings_after_add");
  const afterAddRows = await page.locator("tbody tr").count();
  console.log(`Rows after manual add: ${afterAddRows}`);

  // ══════════════════════════════════════════════════════
  // 6. FINDINGS — CSV import
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 6. FINDINGS — CSV import ═══");
  await page.getByRole("button", { name: /upload csv/i }).click();
  await page.waitForTimeout(800);
  await shot(page, "06_import_dialog");

  const csvPath = path.join(DIR, "vulns.csv");
  fs.writeFileSync(csvPath, VULN_CSV);
  // The file input may have id="upload-file" based on the dialog label
  const fileInput = page.locator("#upload-file, input[type=file]").first();
  await fileInput.setInputFiles(csvPath);
  await page.waitForTimeout(1000);
  await shot(page, "06_file_selected");

  const [csvResp] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes("/vulnerabilities/ingest") || r.url().includes("/upload"),
      { timeout: 30000 }
    ),
    page.getByRole("button", { name: /import csv/i }).click(),
  ]);
  const csvBody = await csvResp.text().catch(() => "");
  console.log(`CSV import: ${csvResp.status()} — ${csvBody.slice(0, 250)}`);
  await page.waitForTimeout(3000);
  await shot(page, "06_import_done");

  // Reload to see list
  await page.goto(`${BASE}/findings`, { waitUntil: "load" });
  await waitForListLoad(page, "/vulnerabilities");
  await shot(page, "06_findings_after_import");
  const afterImportRows = await page.locator("tbody tr").count();
  console.log(`Rows after CSV import: ${afterImportRows}`);
  const totalLabel = await page.locator("text=/\\d+ total findings/").textContent().catch(() => "");
  console.log(`Total label: ${totalLabel}`);

  // ══════════════════════════════════════════════════════
  // 7. FINDINGS — expand row, enrich
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 7. FINDINGS — expand & enrich ═══");
  const firstRow = page.locator("tbody tr").first();
  if (await firstRow.count() > 0) {
    await firstRow.click();
    await page.waitForTimeout(1000);
    await shot(page, "07_row_expanded");

    const enrichBtn = page.getByRole("button", { name: /^enrich$/i }).first();
    if (await enrichBtn.count() > 0) {
      const [enrichResp] = await Promise.all([
        page.waitForResponse((r) => r.url().includes("/enrich"), { timeout: 30000 }),
        enrichBtn.click(),
      ]);
      console.log(`Enrich: ${enrichResp.status()}`);
      await page.waitForTimeout(3000);
      await shot(page, "07_after_enrich");
    } else {
      console.log("⚠ Enrich button not visible");
      await shot(page, "07_no_enrich_btn");
    }
  }

  // ══════════════════════════════════════════════════════
  // 8. ASSETS — initial state
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 8. ASSETS — initial state ═══");
  await page.goto(`${BASE}/assets`, { waitUntil: "load" });
  await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
  await waitForListLoad(page, "/assets");
  await shot(page, "08_assets_initial");
  const assetsText = await page.locator("body").textContent().catch(() => "");
  if (assetsText?.includes("Failed") || assetsText?.includes("Error")) {
    console.log("⚠ Assets page error:", assetsText?.match(/Failed.*|Error.*/)?.[0]);
  }

  // ══════════════════════════════════════════════════════
  // 9. ASSETS — add manually
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 9. ASSETS — add manually ═══");
  const addAssetBtn = page.getByRole("button", { name: /add asset/i });
  if (await addAssetBtn.count() > 0) {
    await addAssetBtn.click();
    await page.waitForTimeout(800);
    await shot(page, "09_add_asset_dialog");

    await page.locator("#a-name").fill("web-prod-01");
    await page.locator("#a-ip").fill("10.0.1.10");
    await page.locator("#a-host").fill("web-prod-01.corp");
    await page.locator("#a-crit").selectOption("critical");
    await shot(page, "09_asset_filled");

    const [assetAddResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/assets"), { timeout: 20000 }),
      // Click the submit button inside the dialog (not the trigger in the header)
      page.locator('[role="dialog"] button:has-text("Add asset")').click(),
    ]);
    const assetAddBody = await assetAddResp.text().catch(() => "");
    console.log(`Add asset: ${assetAddResp.status()} — ${assetAddBody.slice(0, 200)}`);
    await page.waitForTimeout(3000);
    await shot(page, "09_after_add_asset");

    await page.goto(`${BASE}/assets`, { waitUntil: "load" });
    await waitForListLoad(page, "/assets");
    await shot(page, "09_assets_after_add");
    const assetRows = await page.locator("tbody tr").count();
    console.log(`Asset rows after add: ${assetRows}`);
  }

  // ══════════════════════════════════════════════════════
  // 10. ASSETS — CSV import
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 10. ASSETS — CSV import ═══");
  const importAssetBtn = page.getByRole("button", { name: /import csv|import/i }).first();
  if (await importAssetBtn.count() > 0) {
    await importAssetBtn.click();
    await page.waitForTimeout(800);
    await shot(page, "10_asset_import_dialog");

    const assetCsvPath = path.join(DIR, "assets.csv");
    fs.writeFileSync(assetCsvPath, ASSET_CSV);
    await page.locator("#import-file, input[type=file]").first().setInputFiles(assetCsvPath);
    await page.waitForTimeout(800);
    await shot(page, "10_asset_csv_selected");

    const [assetImportResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/assets"), { timeout: 30000 }),
      page.getByRole("button", { name: /import/i }).last().click(),
    ]);
    const assetImportBody = await assetImportResp.text().catch(() => "");
    console.log(`Asset import: ${assetImportResp.status()} — ${assetImportBody.slice(0, 200)}`);
    await page.waitForTimeout(3000);
    await shot(page, "10_asset_import_done");

    await page.goto(`${BASE}/assets`, { waitUntil: "load" });
    await waitForListLoad(page, "/assets");
    await shot(page, "10_assets_after_import");
    const assetRowsAfter = await page.locator("tbody tr").count();
    console.log(`Asset rows after import: ${assetRowsAfter}`);
  }

  // ══════════════════════════════════════════════════════
  // 11. ASSETS — match vulnerabilities
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 11. ASSETS — match vulns ═══");
  const matchBtn = page.getByRole("button", { name: /match vulnerabilities/i });
  if (await matchBtn.count() > 0 && !(await matchBtn.isDisabled())) {
    const [matchResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("match"), { timeout: 15000 }),
      matchBtn.click(),
    ]);
    console.log(`Match vulns: ${matchResp.status()} — ${(await matchResp.text().catch(() => "")).slice(0, 100)}`);
    await page.waitForTimeout(2000);
    await shot(page, "11_after_match");
  } else {
    console.log("⚠ Match button disabled or not found");
    await shot(page, "11_match_state");
  }

  // ══════════════════════════════════════════════════════
  // 12. REPORTS
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 12. REPORTS ═══");
  await page.goto(`${BASE}/reports`, { waitUntil: "load" });
  await waitForListLoad(page, "/reports/dashboard");
  await shot(page, "12_reports");
  const reportsText = await page.locator("body").textContent().catch(() => "");
  if (reportsText?.includes("Failed") || reportsText?.includes("Error")) {
    console.log("⚠ Reports error");
  } else {
    console.log("✓ Reports loaded");
  }

  // PDF download
  const pdfBtn = page.getByRole("button", { name: /pdf|download/i }).first();
  if (await pdfBtn.count() > 0) {
    const [dl] = await Promise.all([
      page.waitForEvent("download", { timeout: 30000 }).catch(() => null),
      pdfBtn.click(),
    ]);
    await page.waitForTimeout(4000);
    if (dl) {
      const savePath = path.join(DIR, "report.pdf");
      await dl.saveAs(savePath);
      console.log(`✓ PDF downloaded: ${fs.statSync(savePath).size} bytes`);
    } else {
      console.log("⚠ PDF download not triggered");
    }
    await shot(page, "12_reports_after_pdf");
  }

  // ══════════════════════════════════════════════════════
  // 13. REMEDIATION
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 13. REMEDIATION ═══");
  await page.goto(`${BASE}/remediation`, { waitUntil: "load" });
  await waitForListLoad(page, "/vulnerabilities");
  await page.waitForSelector("text=Loading findings...", { state: "hidden", timeout: 10000 }).catch(() => null);
  await page.waitForTimeout(1500);
  await shot(page, "13_remediation");

  // Try Generate triage plan
  const triageBtn = page.getByRole("button", { name: /generate triage plan/i });
  if (await triageBtn.count() > 0) {
    const [triageResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/remediation") || r.url().includes("triage"), { timeout: 60000 }),
      triageBtn.click(),
    ]);
    console.log(`Triage plan: ${triageResp.status()}`);
    await page.waitForTimeout(5000);
    await shot(page, "13_triage_result");
  }

  // Try Draft ticket (needs a vuln selected)
  const findingSelect = page.locator("select").first();
  if (await findingSelect.count() > 0) {
    const opts = await findingSelect.locator("option").allTextContents();
    console.log(`Finding options: ${opts.length} — ${opts.slice(0, 4).join(" | ")}`);
    if (opts.length > 1) {
      await findingSelect.selectOption({ index: 1 });
      await page.waitForTimeout(500);
      const draftBtn = page.getByRole("button", { name: /draft ticket/i });
      const isDraftDisabled = await draftBtn.isDisabled().catch(() => true);
      console.log(`Draft ticket button disabled: ${isDraftDisabled}`);
      if (!isDraftDisabled) {
        const [draftResp] = await Promise.all([
          page.waitForResponse((r) => r.url().includes("/remediation/"), { timeout: 60000 }),
          draftBtn.click(),
        ]);
        console.log(`Draft ticket: ${draftResp.status()}`);
        await page.waitForTimeout(8000);
      }
      await shot(page, "13_draft_state");
    }
  }

  // ══════════════════════════════════════════════════════
  // 14. SETTINGS
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 14. SETTINGS ═══");
  await page.goto(`${BASE}/settings`, { waitUntil: "load" });
  await page.waitForTimeout(2000);
  await shot(page, "14_settings");
  const settingsText = await page.locator("body").textContent().catch(() => "");
  if (settingsText?.includes("Failed") || settingsText?.includes("Error")) {
    console.log("⚠ Settings error");
  } else {
    console.log("✓ Settings loaded");
  }

  // ══════════════════════════════════════════════════════
  // 15. FINAL STATE — all pages
  // ══════════════════════════════════════════════════════
  console.log("\n═══ 15. FINAL SCREENSHOTS ═══");
  const finalPages = ["/dashboard", "/findings", "/assets", "/reports", "/settings"];
  for (const p of finalPages) {
    await page.goto(`${BASE}${p}`, { waitUntil: "load" });
    await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 10000 }).catch(() => null);
    await page.waitForTimeout(3000);
    await shot(page, `15_final${p.replace("/", "_")}`);
    console.log(`✓ ${p}`);
  }

  console.log(`\n✓ All screenshots saved to: ${DIR}`);
});
