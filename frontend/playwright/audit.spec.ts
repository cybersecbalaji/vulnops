import { test, expect, Page } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const BASE = "https://grand-youthfulness-production-3b33.up.railway.app";
const SHOTS_DIR = path.join(__dirname, "screenshots");
const TIMESTAMP = Date.now();
const TEST_EMAIL = `audit+${TIMESTAMP}@example.com`;
const TEST_PASSWORD = "AuditPass123!@#";
const TEST_ORG = `AuditOrg${TIMESTAMP}`;

fs.mkdirSync(SHOTS_DIR, { recursive: true });

async function shot(page: Page, name: string) {
  await page.screenshot({ path: path.join(SHOTS_DIR, `${name}.png`), fullPage: true });
  console.log(`📸 ${name}.png`);
}

test.describe.serial("Full App Audit", () => {

  test("1. Homepage — hero, CTAs, mobile", async ({ page }) => {
    await page.goto(BASE, { waitUntil: "load" });
    await page.waitForTimeout(1500);
    await shot(page, "01_homepage_desktop");

    const h1 = await page.locator("h1").first().textContent();
    console.log("H1:", h1?.replace(/\s+/g, " ").trim());

    await expect(page.getByRole("link", { name: /sign in/i }).first()).toBeVisible();
    await expect(page.getByRole("link", { name: /get started/i }).first()).toBeVisible();
    console.log("✓ Homepage CTAs visible");

    // Mobile
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto(BASE, { waitUntil: "load" });
    await page.waitForTimeout(1000);
    await shot(page, "02_homepage_mobile");
    console.log("✓ Mobile homepage captured");

    await page.setViewportSize({ width: 1280, height: 900 });
  });

  test("2. Register — form fills, API call, result", async ({ page }) => {
    const apiCalls: { url: string; status: number; body: string }[] = [];
    page.on("response", async (res) => {
      if (res.url().includes("/api/")) {
        const body = await res.text().catch(() => "");
        apiCalls.push({ url: res.url(), status: res.status(), body: body.slice(0, 500) });
      }
    });

    await page.goto(`${BASE}/register`, { waitUntil: "load" });
    await shot(page, "03_register_empty");

    // Check for HaveIBeenPwned notice (should be removed)
    const hibpText = await page.getByText(/HaveIBeenPwned|k-anonymity/i).count();
    if (hibpText > 0) console.log("⚠ HaveIBeenPwned notice still visible (not yet deployed)");
    else console.log("✓ HaveIBeenPwned notice removed");

    await page.locator("#org_name").fill(TEST_ORG);
    await page.locator("#email").fill(TEST_EMAIL);
    await page.locator("#password").fill(TEST_PASSWORD);
    await shot(page, "04_register_filled");

    // Strength indicators
    const strengthOk = await page.locator(".text-green-700").count();
    console.log(`Password strength checks visible: ${strengthOk}`);

    await Promise.all([
      page.waitForResponse((r) => r.url().includes("/api/"), { timeout: 20000 }).catch(() => null),
      page.getByRole("button", { name: /create account/i }).click(),
    ]);
    await page.waitForTimeout(4000);
    await shot(page, "05_register_submitted");

    console.log("\n--- Register API calls ---");
    apiCalls.forEach((a) => console.log(`  ${a.status} ${a.url}\n  ${a.body.slice(0, 200)}`));

    const alert = page.locator("[role=alert]");
    if (await alert.count() > 0) console.log("Alert shown:", await alert.first().textContent());
    console.log("URL after register:", page.url());

    const regCall = apiCalls.find((a) => a.url.includes("/auth/register"));
    if (!regCall) {
      console.log("❌ CRITICAL: No /auth/register call — NEXT_PUBLIC_API_URL not set in Railway frontend Variables");
    } else if (regCall.status === 201) {
      console.log("✓ Register succeeded (201)");
    } else {
      console.log(`⚠ Register status: ${regCall.status} — ${regCall.body.slice(0, 150)}`);
    }
  });

  test("3. Login — fills, submits, checks redirect", async ({ page }) => {
    const apiCalls: { url: string; status: number; body: string }[] = [];
    page.on("response", async (res) => {
      if (res.url().includes("/api/")) {
        const body = await res.text().catch(() => "");
        apiCalls.push({ url: res.url(), status: res.status(), body: body.slice(0, 500) });
      }
    });

    await page.goto(`${BASE}/login`, { waitUntil: "load" });
    await shot(page, "06_login_empty");

    await page.locator("#email").fill(TEST_EMAIL);
    await page.locator("#password").fill(TEST_PASSWORD);
    await shot(page, "07_login_filled");

    await Promise.all([
      page.waitForResponse((r) => r.url().includes("/api/"), { timeout: 20000 }).catch(() => null),
      page.getByRole("button", { name: /sign in/i }).click(),
    ]);
    await page.waitForTimeout(4000);
    await shot(page, "08_login_submitted");

    console.log("\n--- Login API calls ---");
    apiCalls.forEach((a) => console.log(`  ${a.status} ${a.url}\n  ${a.body.slice(0, 200)}`));

    const alert = page.locator("[role=alert]");
    if (await alert.count() > 0) console.log("Alert:", await alert.first().textContent());
    console.log("URL after login:", page.url());

    const loginCall = apiCalls.find((a) => a.url.includes("/auth/login"));
    if (!loginCall) {
      console.log("❌ CRITICAL: No /auth/login call — NEXT_PUBLIC_API_URL not set");
    } else if (loginCall.status === 200) {
      console.log("✓ Login succeeded (200)");
    } else {
      console.log(`⚠ Login status: ${loginCall.status}`);
    }
  });

  test("4. Dashboard — unauthed redirect", async ({ page }) => {
    await page.goto(`${BASE}/dashboard`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    await shot(page, "09_dashboard_unauthed");
    const url = page.url();
    console.log("Dashboard URL when not logged in:", url);
    if (url.includes("login")) console.log("✓ Correctly redirected to login");
    else console.log("⚠ Did not redirect to login — auth guard may not be working");
  });

  test("5. Full signup + login + dashboard", async ({ page }) => {
    // Step 1: Register fresh account
    const regApiCalls: { url: string; status: number }[] = [];
    page.on("response", async (res) => {
      if (res.url().includes("/api/")) regApiCalls.push({ url: res.url(), status: res.status() });
    });

    const freshEmail = `e2e+${Date.now()}@example.com`;
    await page.goto(`${BASE}/register`, { waitUntil: "load" });
    await page.locator("#org_name").fill(`E2EOr${Date.now()}`);
    await page.locator("#email").fill(freshEmail);
    await page.locator("#password").fill(TEST_PASSWORD);

    await Promise.all([
      page.waitForResponse((r) => r.url().includes("/auth/register"), { timeout: 20000 }).catch(() => null),
      page.getByRole("button", { name: /create account/i }).click(),
    ]);
    await page.waitForTimeout(4000);

    const regCall = regApiCalls.find((a) => a.url.includes("/auth/register"));
    if (!regCall || regCall.status !== 201) {
      console.log("⚠ Register did not return 201 — skipping login step");
      console.log("API calls so far:", regApiCalls);
      await shot(page, "10_e2e_register_failed");
      return;
    }
    console.log("✓ Registered:", freshEmail);

    // Step 2: Login
    await page.goto(`${BASE}/login`, { waitUntil: "load" });
    await page.locator("#email").fill(freshEmail);
    await page.locator("#password").fill(TEST_PASSWORD);

    await Promise.all([
      page.waitForURL(/\/(dashboard|login)/, { timeout: 20000 }).catch(() => null),
      page.getByRole("button", { name: /sign in/i }).click(),
    ]);
    await page.waitForTimeout(3000);
    await shot(page, "10_e2e_after_login");

    const afterLoginUrl = page.url();
    console.log("After login URL:", afterLoginUrl);

    if (!afterLoginUrl.includes("dashboard")) {
      console.log("❌ Did not reach dashboard after login");
      return;
    }

    // Step 3: Dashboard loaded
    await shot(page, "11_dashboard");
    console.log("✓ Dashboard loaded");

    const welcomeText = await page.locator("h1").first().textContent();
    console.log("Dashboard H1:", welcomeText);

    // Check stat cards
    const cards = await page.locator(".border-l-4").count();
    console.log(`Stat cards visible: ${cards}`);

    // Check quick links
    const links = await page.getByRole("link", { name: /findings|assets|reports|remediation/i }).count();
    console.log(`Quick action links: ${links}`);

    // Mobile dashboard
    await page.setViewportSize({ width: 375, height: 812 });
    await page.waitForTimeout(500);
    await shot(page, "12_dashboard_mobile");

    await page.setViewportSize({ width: 1280, height: 900 });

    // Step 4: Navigate to findings
    await page.goto(`${BASE}/findings`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    await shot(page, "13_findings_page");
    console.log("Findings URL:", page.url());

    // Step 5: Navigate to assets
    await page.goto(`${BASE}/assets`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    await shot(page, "14_assets_page");
    console.log("Assets URL:", page.url());
  });

});
