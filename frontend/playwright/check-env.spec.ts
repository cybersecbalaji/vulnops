import { test } from "@playwright/test";

const BASE = "https://grand-youthfulness-production-3b33.up.railway.app";

test("check NEXT_PUBLIC_API_URL baked into bundle", async ({ page }) => {
  await page.goto(`${BASE}/register`, { waitUntil: "load" });
  await page.waitForTimeout(2000);

  // Evaluate what API_BASE the bundle resolved to
  const apiBase = await page.evaluate(() => {
    // Try to find it in the webpack chunks
    const scripts = Array.from(document.querySelectorAll("script[src]")).map(s => (s as HTMLScriptElement).src);
    return scripts;
  });
  console.log("Script chunks:", apiBase.slice(0, 5));

  // Check the actual API URL by making a test fetch
  const apiUrl = await page.evaluate(async () => {
    // Make a dummy request and capture the URL it goes to
    try {
      const resp = await fetch("/api/v1/auth/me", { method: "GET" });
      return { url: resp.url, status: resp.status, type: "relative" };
    } catch (e) {
      return { error: String(e) };
    }
  });
  console.log("Relative /api/v1 fetch result:", apiUrl);

  // Check what NEXT_PUBLIC_API_URL resolved to in the bundle
  const envCheck = await page.evaluate(() => {
    // Search all loaded chunks for the API URL string
    const allText = Array.from(document.querySelectorAll("script:not([src])"))
      .map(s => s.textContent || "")
      .join(" ");

    // Look for railway.app URL pattern in inline scripts
    const railwayMatch = allText.match(/https:\/\/[a-z0-9-]+\.up\.railway\.app/g);
    return { railwayUrls: [...new Set(railwayMatch || [])] };
  });
  console.log("Railway URLs found in bundle:", envCheck);

  // Try fetching the main JS chunk to find API_BASE
  const chunkUrls = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("script[src]"))
      .map(s => (s as HTMLScriptElement).src)
      .filter(s => s.includes("main-app") || s.includes("layout"));
  });

  console.log("Main chunk URLs:", chunkUrls);

  // Fetch first main chunk and grep for API URL
  if (chunkUrls.length > 0) {
    const chunkText = await page.evaluate(async (url: string) => {
      const r = await fetch(url);
      const text = await r.text();
      // Find anything that looks like an API base URL
      const match = text.match(/railway\.app[^"']*/g);
      const apiMatch = text.match(/NEXT_PUBLIC_API_URL[^,;]*/g);
      const apiV1Match = text.match(/\/api\/v1/g);
      return { railwayRefs: match?.slice(0, 5), apiUrlRefs: apiMatch?.slice(0, 3), hasApiV1: !!apiV1Match };
    }, chunkUrls[0]);
    console.log("In chunk:", chunkText);
  }
});
