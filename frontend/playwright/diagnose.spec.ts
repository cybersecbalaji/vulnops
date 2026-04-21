import { test } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const BASE = "https://grand-youthfulness-production-3b33.up.railway.app";
const SHOTS = path.join(__dirname, "screenshots");
fs.mkdirSync(SHOTS, { recursive: true });

const TS = Date.now();
const EMAIL = `diag+${TS}@example.com`;
const PASS = "DiagPass123!@#";
const ORG = `DiagOrg${TS}`;

test("register — full request+response+console capture", async ({ page }) => {
  const outgoingRequests: string[] = [];
  const responses: { method: string; url: string; status: number; body: string }[] = [];

  // Capture OUTGOING requests (before response)
  page.on("request", (req) => {
    const url = req.url();
    if (!url.includes("_next/static") && !url.includes(".woff") && !url.includes(".css")) {
      outgoingRequests.push(`→ ${req.method()} ${url}`);
      if (req.method() !== "GET") {
        console.log(`OUTGOING: ${req.method()} ${url}`);
        try { console.log(`  body: ${req.postData()?.slice(0, 200)}`); } catch {}
      }
    }
  });

  // Capture failed requests
  page.on("requestfailed", (req) => {
    console.log(`FAILED REQUEST: ${req.method()} ${req.url()} — ${req.failure()?.errorText}`);
  });

  // Capture all console messages
  page.on("console", (msg) => {
    if (msg.type() === "error" || msg.text().includes("Error") || msg.text().includes("CORS")) {
      console.log(`CONSOLE [${msg.type()}]: ${msg.text()}`);
    }
  });

  // Capture responses
  page.on("response", async (res) => {
    const url = res.url();
    if (!url.includes("_next/static") && !url.includes(".woff") && !url.includes(".css")) {
      const body = await res.text().catch(() => "(unreadable)");
      responses.push({ method: res.request().method(), url, status: res.status(), body: body.slice(0, 400) });
      console.log(`RESPONSE: ${res.status()} ${res.request().method()} ${url}`);
      if (res.status() >= 400 || url.includes("/api/")) {
        console.log(`  body: ${body.slice(0, 300)}`);
      }
    }
  });

  await page.goto(`${BASE}/register`, { waitUntil: "load" });
  await page.waitForTimeout(2000);

  console.log("\n--- Filling form ---");
  await page.locator("#org_name").fill(ORG);
  await page.locator("#email").fill(EMAIL);
  await page.locator("#password").fill(PASS);

  // Check button state before clicking
  const btnDisabled = await page.locator("button[type=submit]").getAttribute("disabled");
  console.log("Button disabled?", btnDisabled);

  console.log("--- Clicking submit ---");
  await page.locator("button[type=submit]").click();
  await page.waitForTimeout(8000);

  await page.screenshot({ path: path.join(SHOTS, "diag_after_submit.png"), fullPage: true });

  console.log("\n═══ ALL OUTGOING REQUESTS ═══");
  outgoingRequests.forEach(r => console.log(" ", r));

  console.log("\n═══ ALL RESPONSES ═══");
  responses.forEach(r => console.log(` ${r.method} ${r.status} ${r.url}`));

  const errorText = await page.locator("[role=alert]").textContent().catch(() => "none");
  console.log("\nError on page:", errorText);
  console.log("Final URL:", page.url());

  // Check if BACKEND_URL rewrite is active by hitting the proxy
  const proxyCheck = await page.evaluate(async () => {
    try {
      const r = await fetch("/api/v1/auth/me", { method: "GET" });
      const body = await r.text().catch(() => "");
      return { status: r.status, url: r.url, bodyPreview: body.slice(0, 100) };
    } catch (e) {
      return { error: String(e) };
    }
  });
  console.log("\nProxy check /api/v1/auth/me:", proxyCheck);
  if (proxyCheck.status === 404 && proxyCheck.bodyPreview?.includes("<!DOCTYPE")) {
    console.log("❌ Rewrite NOT active — BACKEND_URL not set in Railway frontend Variables");
    console.log("   Fix: Railway → frontend service → Variables → add BACKEND_URL=https://<backend>.up.railway.app");
  } else if (proxyCheck.status === 401 || proxyCheck.status === 422) {
    console.log("✓ Rewrite IS active — backend is responding");
  } else {
    console.log(`⚠ Unexpected status: ${proxyCheck.status}`);
  }
});
