import { chromium } from 'playwright';
const BASE = 'http://localhost:3000';
const TS = Date.now();
const EMAIL = `signout_${TS}@gmail.com`;
const PASSWORD = `VulnOut!${TS}`;

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  page.on('response', async (res) => {
    if (res.url().includes('/auth/')) {
      const sc = res.headers()['set-cookie'] || '';
      console.log(`[${res.status()}] ${res.request().method()} ${res.url().split('/api/v1')[1] || res.url()}`);
      if (sc) console.log(`  Set-Cookie: ${sc.substring(0, 120)}`);
    }
  });

  // Register
  await page.goto(`${BASE}/register`, { waitUntil: 'networkidle' });
  await page.fill('#org_name', 'SO Org');
  await page.fill('#email', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${BASE}/dashboard`, { timeout: 20000 });
  console.log('\n--- Registered, URL:', page.url());

  // Navigate to dashboard (full reload)
  await page.goto(`${BASE}/dashboard`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  console.log('\n--- After reload, cookies:');
  (await ctx.cookies()).forEach(c => console.log(`  ${c.name}=${c.value.substring(0,20)}... domain=${c.domain} path=${c.path}`));

  console.log('\n--- Clicking Sign out...');
  await page.getByText('Sign out').click();
  await page.waitForTimeout(4000);
  
  console.log('URL after 4s wait:', page.url());
  console.log('Cookies after sign out:');
  (await ctx.cookies()).forEach(c => console.log(`  ${c.name}=${c.value.substring(0,20)}... domain=${c.domain}`));

  // Now navigate to /login
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  console.log('\nURL after goto /login:', page.url());

  await browser.close();
})();
