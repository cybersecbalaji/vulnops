import { chromium } from 'playwright';
const BASE_URL = 'http://localhost:3000';
const EMAIL = `f2_${Date.now()}@gmail.com`;
const PASSWORD = `VulnOps!E2e#${Date.now()}`;

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', e => console.log('JS ERROR:', e.message));
  page.on('console', m => { if (m.type() === 'error') console.log('CONSOLE ERR:', m.text()); });

  await page.goto(`${BASE_URL}/register`, { waitUntil: 'networkidle' });
  await page.fill('#org_name', 'Debug Org');
  await page.fill('#email', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${BASE_URL}/dashboard`, { timeout: 20000 });

  await page.goto(`${BASE_URL}/findings`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  const body = await page.textContent('body');
  console.log('\n--- Page body (first 800 chars) ---');
  console.log(body?.slice(0, 800));

  await browser.close();
  process.exit(0);
})();
