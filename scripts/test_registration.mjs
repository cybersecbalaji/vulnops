/**
 * Playwright smoke test — validates the registration page end-to-end.
 * Run: node scripts/test_registration.mjs
 */
import { chromium } from 'playwright';

const BASE_URL = 'http://localhost:3000';
const EMAIL = `e2e_${Date.now()}@gmail.com`;
const PASSWORD = `VulnOps!E2e#${Date.now()}`;
const ORG_NAME = 'E2E Test Organization';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Collect all network responses
  const apiCalls = [];
  page.on('response', async res => {
    const url = res.url();
    if (url.includes('/api/')) {
      try {
        const body = await res.text();
        apiCalls.push({ url, status: res.status(), body });
      } catch {
        apiCalls.push({ url, status: res.status(), body: '<unreadable>' });
      }
    }
  });

  const consoleErrors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  try {
    console.log(`\n=== VulnOps Registration E2E Test ===`);
    console.log(`URL:   ${BASE_URL}/register`);
    console.log(`Email: ${EMAIL}`);
    console.log(`Pass:  ${PASSWORD.slice(0, 10)}...`);

    // 1. Navigate to register page
    console.log('\n[1] Navigating to /register...');
    await page.goto(`${BASE_URL}/register`, { waitUntil: 'networkidle' });
    console.log(`    Title: "${await page.title()}"`);

    // 2. Fill form
    console.log('[2] Filling form...');
    await page.fill('#org_name', ORG_NAME);
    await page.fill('#email', EMAIL);
    await page.fill('#password', PASSWORD);

    // Verify fields are filled
    const orgVal = await page.inputValue('#org_name');
    const emailVal = await page.inputValue('#email');
    const passVal = await page.inputValue('#password');
    console.log(`    org_name filled: ${orgVal === ORG_NAME ? '✓' : '✗ "' + orgVal + '"'}`);
    console.log(`    email filled:    ${emailVal === EMAIL ? '✓' : '✗ "' + emailVal + '"'}`);
    console.log(`    password filled: ${passVal.length > 0 ? `✓ (${passVal.length} chars)` : '✗ empty'}`);

    // 3. Submit
    console.log('[3] Clicking submit...');
    await page.click('button[type="submit"]');

    // 4. Wait for button to show loading state, then wait for it to stop
    console.log('[4] Waiting for API response (HIBP check may take a few seconds)...');

    // Wait up to 20s for either: navigation to /dashboard or an error alert appearing
    // or the loading button to become un-disabled
    const outcome = await Promise.race([
      page.waitForURL(`${BASE_URL}/dashboard`, { timeout: 20000 })
        .then(() => 'navigated'),
      page.waitForFunction(
        () => {
          // Look for a destructive error alert (not the HIBP info note)
          const alerts = document.querySelectorAll('[role="alert"]');
          for (const alert of alerts) {
            if (!alert.textContent?.includes('HaveIBeenPwned')) return true;
          }
          return false;
        },
        { timeout: 20000 }
      ).then(() => 'error_shown'),
    ]).catch(e => `timeout: ${e.message}`);

    console.log(`    Outcome: ${outcome}`);

    // 5. Report
    const currentUrl = page.url();
    console.log(`\n[5] Final URL: ${currentUrl}`);

    // Show API calls made
    const registerCalls = apiCalls.filter(c => c.url.includes('/auth/register'));
    if (registerCalls.length > 0) {
      for (const call of registerCalls) {
        console.log(`    POST /auth/register → HTTP ${call.status}`);
        try {
          const json = JSON.parse(call.body);
          if (json.user) {
            console.log(`    User: ${json.user.email} (${json.user.role})`);
            console.log(`    Token: ${json.access_token ? 'present ✓' : 'MISSING ✗'}`);
          } else if (json.detail) {
            console.log(`    Backend error: ${JSON.stringify(json.detail)}`);
          }
        } catch {
          console.log(`    Body: ${call.body.slice(0, 200)}`);
        }
      }
    } else {
      console.log('    No POST /auth/register call captured');
      // Show all API calls for debugging
      if (apiCalls.length > 0) {
        console.log('    All API calls:');
        apiCalls.forEach(c => console.log(`      ${c.status} ${c.url}`));
      }
    }

    if (outcome === 'navigated' || currentUrl.includes('/dashboard')) {
      console.log('\n✅ PASS — Registration successful! Redirected to /dashboard.');
    } else if (outcome === 'error_shown') {
      const alerts = await page.$$('[role="alert"]');
      for (const alert of alerts) {
        const text = (await alert.textContent())?.trim();
        if (text && !text.includes('HaveIBeenPwned')) {
          console.log(`\n❌ FAIL — Error on page: "${text}"`);
        }
      }
    } else {
      console.log(`\n❌ FAIL — ${outcome}`);
      const body = await page.textContent('body');
      console.log(`    Page: ${body?.slice(0, 400)}`);
    }

    if (consoleErrors.length > 0) {
      console.log('\n--- Console errors ---');
      consoleErrors.slice(0, 10).forEach(e => console.log(`  ${e}`));
    }

  } finally {
    await browser.close();
    process.exit(0);
  }
})();
