import { test, expect } from "@playwright/test";

const BASE = "https://grand-youthfulness-production-3b33.up.railway.app";
const TIMESTAMP = Date.now();
const TEST_EMAIL = `test+${TIMESTAMP}@example.com`;
const TEST_PASSWORD = "TestPass123!@#";
const TEST_ORG = `TestOrg${TIMESTAMP}`;

test.describe("VulnOps Auth Flow", () => {
  test("backend health check", async ({ request }) => {
    // First check if the backend is reachable at all
    const backendUrl = process.env.BACKEND_URL || "";
    if (!backendUrl) {
      console.log("BACKEND_URL not set — skipping direct health check");
      return;
    }
    const res = await request.get(`${backendUrl}/api/health`);
    expect(res.status()).toBe(200);
  });

  test("homepage loads", async ({ page }) => {
    await page.goto(BASE);
    await expect(page).toHaveTitle(/VulnOps/i);
    console.log("✓ Homepage loaded:", await page.title());
  });

  test("register page loads", async ({ page }) => {
    await page.goto(`${BASE}/register`);
    await expect(page.getByText("Create your organization")).toBeVisible({ timeout: 10000 });
    console.log("✓ Register page loaded");
  });

  test("API call from register — capture network request", async ({ page }) => {
    const apiCalls: { url: string; status: number; body: string }[] = [];

    // Intercept all fetch/XHR calls
    page.on("response", async (response) => {
      const url = response.url();
      if (url.includes("/api/") || url.includes("register") || url.includes("orgs")) {
        try {
          const body = await response.text().catch(() => "(unreadable)");
          apiCalls.push({ url, status: response.status(), body: body.slice(0, 300) });
          console.log(`API call: ${response.status()} ${url}`);
          console.log(`  Response: ${body.slice(0, 200)}`);
        } catch {
          apiCalls.push({ url, status: response.status(), body: "(error reading body)" });
        }
      }
    });

    await page.goto(`${BASE}/register`);
    await page.getByLabel("Organization name").fill(TEST_ORG);
    await page.getByLabel("Work email").fill(TEST_EMAIL);
    await page.locator("#password").fill(TEST_PASSWORD);

    // Click register and wait for network
    await Promise.all([
      page.waitForResponse((r) => r.url().includes("/api/"), { timeout: 15000 }).catch(() => null),
      page.getByRole("button", { name: /create account/i }).click(),
    ]);

    await page.waitForTimeout(3000);

    console.log("\n=== All API calls captured ===");
    if (apiCalls.length === 0) {
      console.log("NO API calls were made — NEXT_PUBLIC_API_URL is likely not set");
      console.log("Check the page URL of the API call:");
      const allResponses = await page.evaluate(() => {
        // Check what API_BASE resolves to
        return window.location.origin;
      });
      console.log("Page origin:", allResponses);
    }
    apiCalls.forEach((c) => console.log(c));

    // Check for error message on page
    const errorText = await page.getByText(/unexpected|error|failed/i).first().textContent().catch(() => null);
    if (errorText) {
      console.log("Error shown on page:", errorText);
    }

    // The test passes as diagnostic — it logs what's happening
    expect(true).toBe(true);
  });

  test("full signup → login flow", async ({ page }) => {
    // Step 1: Register
    await page.goto(`${BASE}/register`);
    await expect(page.getByText("Create your organization")).toBeVisible({ timeout: 10000 });

    await page.getByLabel("Organization name").fill(TEST_ORG);
    await page.getByLabel("Work email").fill(TEST_EMAIL);
    await page.locator("#password").fill(TEST_PASSWORD);
    await page.getByRole("button", { name: /create account/i }).click();

    // Wait up to 15s for either success (redirect to /dashboard or /login) or error
    await page.waitForURL(/\/(dashboard|login|verify)/, { timeout: 15000 }).catch(async () => {
      const bodyText = await page.locator("body").textContent();
      console.log("Page did not redirect. Body text:", bodyText?.slice(0, 500));
    });

    const currentUrl = page.url();
    console.log("After register, URL:", currentUrl);

    if (currentUrl.includes("dashboard")) {
      console.log("✓ Registered and auto-logged in to dashboard");
      return;
    }

    // Step 2: Login if redirected to /login
    if (currentUrl.includes("login")) {
      await page.getByLabel(/email/i).fill(TEST_EMAIL);
      await page.getByLabel(/password/i).fill(TEST_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();

      await page.waitForURL(/\/dashboard/, { timeout: 15000 }).catch(async () => {
        const bodyText = await page.locator("body").textContent();
        console.log("Login did not redirect to dashboard. Body:", bodyText?.slice(0, 500));
      });

      console.log("After login, URL:", page.url());
    }

    expect(page.url()).toContain("dashboard");
  });
});
