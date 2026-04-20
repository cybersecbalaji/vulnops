import { chromium } from 'playwright';
const BASE = 'http://localhost:3000';
const TS = Date.now();
const EMAIL = `lc_${TS}@gmail.com`;
const PASSWORD = `Vuln!${TS}`;

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  // Capture ALL Set-Cookie headers from logout
  page.on('response', async (res) => {
    if (res.url().includes('/auth/logout')) {
      console.log(`Logout response: ${res.status()}`);
      const allHeaders = res.headers();
      Object.entries(allHeaders).forEach(([k, v]) => {
        if (k.toLowerCase().includes('cookie') || k.toLowerCase().includes('access')) {
          console.log(`  ${k}: ${v}`);
        }
      });
    }
  });

  // Register + login
  await page.goto(`${BASE}/register`, { waitUntil: 'networkidle' });
  await page.fill('#org_name', 'LC Org');
  await page.fill('#email', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${BASE}/dashboard`, { timeout: 20000 });
  await page.goto(`${BASE}/dashboard`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  console.log('\nBefore logout:');
  (await ctx.cookies()).forEach(c => {
    console.log(`  ${c.name}=${c.value.slice(0,20)}... domain=${c.domain} path=${c.path} httpOnly=${c.httpOnly} sameSite=${c.sameSite}`);
  });

  await page.getByText('Sign out').click();
  await page.waitForTimeout(3000);

  console.log('\nAfter logout:');
  const cookies = await ctx.cookies();
  if (cookies.length === 0) {
    console.log('  (no cookies)');
  } else {
    cookies.forEach(c => console.log(`  ${c.name}=${c.value.slice(0,20)}... domain=${c.domain}`));
  }

  await browser.close();
})();
