import { chromium } from 'playwright';
const BASE = 'http://localhost:3000';
const TS = Date.now();
const EMAIL = `debug_${TS}@gmail.com`;
const PASSWORD = `VulnDebug!${TS}`;

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  
  // Intercept all requests to see what's happening
  page.on('response', async (res) => {
    if (res.url().includes('/auth/')) {
      console.log(`[${res.status()}] ${res.request().method()} ${res.url()}`);
      const setCookie = res.headers()['set-cookie'];
      if (setCookie) console.log(`  Set-Cookie: ${setCookie.substring(0, 80)}...`);
    }
  });

  console.log('\n--- Step 1: Register ---');
  await page.goto(`${BASE}/register`, { waitUntil: 'networkidle' });
  await page.fill('#org_name', 'Debug Org');
  await page.fill('#email', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${BASE}/dashboard`, { timeout: 20000 });
  console.log('Registered, at dashboard:', page.url());

  // Check cookies
  const cookies1 = await ctx.cookies();
  const refreshCookie = cookies1.find(c => c.name === 'refresh_token');
  console.log('Refresh cookie present:', !!refreshCookie);
  if (refreshCookie) console.log('  domain:', refreshCookie.domain, 'path:', refreshCookie.path, 'httpOnly:', refreshCookie.httpOnly);

  // Check page content
  const bodyText = await page.textContent('body');
  console.log('Has email in page:', bodyText.includes(EMAIL.split('@')[0]));

  console.log('\n--- Step 2: Hard navigate to dashboard ---');
  await page.goto(`${BASE}/dashboard`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(3000);
  const bodyText2 = await page.textContent('body');
  console.log('Has email in page:', bodyText2.includes(EMAIL.split('@')[0]));
  console.log('Has Loading:', bodyText2.includes('Loading'));
  console.log('Page snippet:', bodyText2.substring(0, 200));

  // Check cookies after reload
  const cookies2 = await ctx.cookies();
  const refreshCookie2 = cookies2.find(c => c.name === 'refresh_token');
  console.log('Refresh cookie after reload:', !!refreshCookie2);

  await browser.close();
})();
