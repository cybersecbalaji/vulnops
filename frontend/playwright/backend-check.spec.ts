import { test } from "@playwright/test";

const FRONTEND = "https://grand-youthfulness-production-3b33.up.railway.app";

test("check backend reachability and BACKEND_URL", async ({ page, request }) => {
  // Check what BACKEND_URL the Next.js server is using by hitting the proxy
  const proxyResult = await request.get(`${FRONTEND}/api/v1/health`);
  console.log(`\nProxy /api/v1/health: ${proxyResult.status()}`);
  console.log(`Body: ${await proxyResult.text()}`);

  // Check if the proxy returns 404 (no rewrite) vs 502 (rewrite exists but backend down)
  const registerCheck = await request.post(`${FRONTEND}/api/v1/auth/register`, {
    data: { email: "test@test.com", password: "Test123!@#$", org_name: "Test" },
    headers: { "Content-Type": "application/json" },
  });
  console.log(`\nProxy /api/v1/auth/register: ${registerCheck.status()}`);
  const body = await registerCheck.text();
  console.log(`Body: ${body.slice(0, 300)}`);

  if (registerCheck.status() === 404 && body.includes("<!DOCTYPE")) {
    console.log("\n❌ BACKEND_URL not set — Next.js has no rewrite, returning its own 404 HTML");
  } else if (registerCheck.status() === 502) {
    console.log("\n⚠ Rewrite exists but backend unreachable (502) — check:");
    console.log("  1. BACKEND_URL value in frontend service Variables");
    console.log("  2. Backend service public domain port matches $PORT (check deploy logs)");
  } else if (registerCheck.status() === 201) {
    console.log("\n✓ Backend working!");
  } else if (registerCheck.status() === 422 || registerCheck.status() === 400) {
    console.log("\n✓ Backend reachable (validation error expected for test data)");
  }
});
