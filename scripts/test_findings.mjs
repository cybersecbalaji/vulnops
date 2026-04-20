/**
 * Playwright smoke test — validates /findings page loads after login.
 * Run: node scripts/test_findings.mjs
 */
import { chromium } from 'playwright';

const BASE_URL = 'http://localhost:3000';
// Use a fresh email each run so registration always works
const EMAIL = `findings_test_${Date.now()}@gmail.com`;
const PASSWORD = `VulnOps!E2e#${Date.now()}`;
const ORG = 'Findings Test Org';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  try {
    // 1. Register
    console.log('Registering...');
    await page.goto(`${BASE_URL}/register`, { waitUntil: 'networkidle' });
    await page.fill('#org_name', ORG);
    await page.fill('#email', EMAIL);
    await page.fill('#password', PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL(`${BASE_URL}/dashboard`, { timeout: 20000 });
    console.log('Logged in via registration ✓');

    // 2. Navigate to /findings
    console.log('Navigating to /findings...');
    await page.goto(`${BASE_URL}/findings`, { waitUntil: 'networkidle' });
    console.log(`URL: ${page.url()}`);

    const heading = await page.textContent('header').catch(() => '');
    const hasTable = await page.$('table') !== null;
    const hasUploadBtn = await page.getByText('Upload CSV / JSON').isVisible().catch(() => false);
    const hasAddBtn = await page.getByText('Add manually').isVisible().catch(() => false);
    const hasEnrichBtn = await page.getByText('Enrich all').isVisible().catch(() => false);
    const hasScoreBtn = await page.getByText('Score all (AI)').isVisible().catch(() => false);
    const emptyState = await page.getByText('No findings yet').isVisible().catch(() => false);

    console.log(`\nResults:`);
    console.log(`  URL:          ${page.url().includes('/findings') ? '✓ /findings' : '✗ ' + page.url()}`);
    console.log(`  Upload btn:   ${hasUploadBtn ? '✓' : '✗'}`);
    console.log(`  Add btn:      ${hasAddBtn ? '✓' : '✗'}`);
    console.log(`  Enrich btn:   ${hasEnrichBtn ? '✓' : '✗'}`);
    console.log(`  Score btn:    ${hasScoreBtn ? '✓' : '✗'}`);
    console.log(`  Empty state:  ${emptyState ? '✓ (no findings yet, as expected)' : '✗'}`);

    const pass = page.url().includes('/findings') && hasUploadBtn && hasAddBtn;
    console.log(`\n${pass ? '✅ PASS' : '❌ FAIL'} — /findings page`);

    if (errors.length) {
      console.log('\nJS errors:', errors);
    }
  } finally {
    await browser.close();
    process.exit(0);
  }
})();
