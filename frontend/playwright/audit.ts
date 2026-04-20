import { chromium } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const BASE = "https://grand-youthfulness-production-3b33.up.railway.app";
const SHOTS_DIR = path.join(__dirname, "screenshots");
const TIMESTAMP = Date.now();
const TEST_EMAIL = `audit+${TIMESTAMP}@example.com`;
const TEST_PASSWORD = "AuditPass123!@#";
const TEST_ORG = `AuditOrg${TIMESTAMP}`;

const issues: string[] = [];
const fixes: string[] = [];

fs.mkdirSync(SHOTS_DIR, { recursive: true });

async function shot(page: import("@playwright/test").Page, name: string) {
  const file = path.join(SHOTS_DIR, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  console.log(`📸 ${name}.png`);
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();

  // Capture all API calls
  const apiLog: { method: string; url: string; status: number; body: string }[] = [];
  page.on("response", async (res) => {
    const url = res.url();
    if (url.includes("/api/")) {
      const body = await res.text().catch(() => "");
      apiLog.push({ method: res.request().method(), url, status: res.status(), body: body.slice(0, 400) });
    }
  });

  // ── 1. Homepage ──────────────────────────────────────────────────────────────
  console.log("\n═══ 1. Homepage ═══");
  await page.goto(BASE, { waitUntil: "networkidle" });
  await shot(page, "01_homepage");
  const heroText = await page.locator("h1").first().textContent().catch(() => "");
  console.log("H1:", heroText);
  const signInBtn = await page.getByRole("link", { name: /sign in/i }).count();
  const getStartedBtn = await page.getByRole("link", { name: /get started/i }).count();
  console.log(`Sign in links: ${signInBtn}, Get started links: ${getStartedBtn}`);
  if (signInBtn === 0) issues.push("Homepage: no 'Sign in' button visible");
  if (getStartedBtn === 0) issues.push("Homepage: no 'Get started' button visible");

  // ── 2. Register page ─────────────────────────────────────────────────────────
  console.log("\n═══ 2. Register Page ═══");
  await page.goto(`${BASE}/register`, { waitUntil: "networkidle" });
  await shot(page, "02_register_empty");

  // Check fields exist
  const orgField = await page.locator("#org_name").count();
  const emailField = await page.locator("#email").count();
  const pwField = await page.locator("#password").count();
  console.log(`Fields — org:${orgField} email:${emailField} pw:${pwField}`);
  if (!orgField || !emailField || !pwField) issues.push("Register: missing form fields");

  // Fill and submit
  await page.locator("#org_name").fill(TEST_ORG);
  await page.locator("#email").fill(TEST_EMAIL);
  await page.locator("#password").fill(TEST_PASSWORD);
  await shot(page, "03_register_filled");

  const [registerRes] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/auth/register"), { timeout: 15000 }).catch(() => null),
    page.getByRole("button", { name: /create account/i }).click(),
  ]);

  await page.waitForTimeout(3000);
  await shot(page, "04_register_submitted");

  if (registerRes) {
    const status = registerRes.status();
    const body = await registerRes.text().catch(() => "");
    console.log(`Register API: ${status}`);
    console.log(`Response: ${body.slice(0, 300)}`);
    if (status === 404) {
      issues.push("CRITICAL: /api/v1/auth/register returns 404 — NEXT_PUBLIC_API_URL not set or wrong");
      fixes.push("Set NEXT_PUBLIC_API_URL=https://<backend>.up.railway.app in Railway frontend service Variables");
    } else if (status >= 400) {
      issues.push(`Register API returned ${status}: ${body.slice(0, 200)}`);
    }
  } else {
    issues.push("CRITICAL: No API call to /auth/register was made — NEXT_PUBLIC_API_URL not configured");
    fixes.push("Set NEXT_PUBLIC_API_URL=https://<backend>.up.railway.app in Railway frontend service Variables");
  }

  const errorMsg = await page.locator("[role=alert]").textContent().catch(() => "");
  if (errorMsg) {
    console.log("Error on page:", errorMsg);
    issues.push(`Register error shown: "${errorMsg.trim()}"`);
  }

  const currentUrl = page.url();
  console.log("URL after register:", currentUrl);

  // ── 3. Login page ────────────────────────────────────────────────────────────
  console.log("\n═══ 3. Login Page ═══");
  await page.goto(`${BASE}/login`, { waitUntil: "networkidle" });
  await shot(page, "05_login_empty");

  const loginEmailField = await page.locator("#email").count();
  const loginPwField = await page.locator("#password").count();
  console.log(`Login fields — email:${loginEmailField} pw:${loginPwField}`);

  await page.locator("#email").fill(TEST_EMAIL);
  await page.locator("#password").fill(TEST_PASSWORD);
  await shot(page, "06_login_filled");

  const [loginRes] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/auth/login"), { timeout: 15000 }).catch(() => null),
    page.getByRole("button", { name: /sign in/i }).click(),
  ]);

  await page.waitForTimeout(3000);
  await shot(page, "07_login_submitted");

  if (loginRes) {
    const status = loginRes.status();
    const body = await loginRes.text().catch(() => "");
    console.log(`Login API: ${status} — ${body.slice(0, 200)}`);
    if (status === 401) issues.push("Login 401: user may not have been registered (register step failed first)");
    if (status === 404) issues.push("CRITICAL: /api/v1/auth/login returns 404 — backend URL not configured");
  }

  const loginError = await page.locator("[role=alert]").textContent().catch(() => "");
  if (loginError) {
    console.log("Login error:", loginError);
    issues.push(`Login error shown: "${loginError.trim()}"`);
  }
  console.log("URL after login:", page.url());

  // ── 4. Check mobile viewport ─────────────────────────────────────────────────
  console.log("\n═══ 4. Mobile Viewport ═══");
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(BASE, { waitUntil: "networkidle" });
  await shot(page, "08_homepage_mobile");
  await page.goto(`${BASE}/register`, { waitUntil: "networkidle" });
  await shot(page, "09_register_mobile");

  // ── 5. Summary ───────────────────────────────────────────────────────────────
  console.log("\n═══════════════════════════════════════");
  console.log("ISSUES FOUND:");
  if (issues.length === 0) {
    console.log("  ✓ No issues found");
  } else {
    issues.forEach((i, n) => console.log(`  ${n + 1}. ❌ ${i}`));
  }
  console.log("\nFIXES NEEDED:");
  if (fixes.length === 0) {
    console.log("  ✓ No fixes needed");
  } else {
    fixes.forEach((f, n) => console.log(`  ${n + 1}. 🔧 ${f}`));
  }
  console.log("\nAPI CALLS LOG:");
  apiLog.forEach((a) => console.log(`  ${a.method} ${a.status} ${a.url}`));
  console.log(`\nScreenshots saved to: ${SHOTS_DIR}`);

  await browser.close();
})();
