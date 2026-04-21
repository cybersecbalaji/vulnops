# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: full-e2e.spec.ts >> VulnOps Full E2E >> 05 · Findings — CSV import
- Location: playwright\full-e2e.spec.ts:194:7

# Error details

```
Error: expect(received).toBeGreaterThan(expected)

Expected: > 0
Received:   0
```

# Page snapshot

```yaml
- generic [ref=e1]:
  - generic [ref=e2]:
    - banner [ref=e3]:
      - generic [ref=e4]:
        - generic [ref=e5]:
          - link "Dashboard" [ref=e6] [cursor=pointer]:
            - /url: /dashboard
            - img [ref=e7]
            - text: Dashboard
          - generic [ref=e9]: /
          - generic [ref=e10]:
            - img [ref=e11]
            - text: Vulnerability Queue
        - generic [ref=e13]:
          - generic [ref=e14]: 0 total findings
          - button "Switch to light mode" [ref=e15] [cursor=pointer]:
            - img [ref=e16]
    - main [ref=e18]:
      - generic [ref=e19]:
        - button "Upload CSV / JSON" [active] [ref=e20] [cursor=pointer]:
          - img [ref=e21]
          - text: Upload CSV / JSON
        - button "Add manually" [ref=e24] [cursor=pointer]:
          - img [ref=e25]
          - text: Add manually
        - button "Enrich all" [disabled]:
          - img
          - text: Enrich all
        - button "Score all (AI)" [disabled]:
          - img
          - text: Score all (AI)
      - generic [ref=e26]:
        - generic [ref=e27]: "Filter:"
        - combobox [ref=e28]:
          - option "All severities" [selected]
          - option "Critical"
          - option "High"
          - option "Medium"
          - option "Low"
          - option "Informational"
        - combobox [ref=e29]:
          - option "All statuses" [selected]
          - option "Open"
          - option "Triaged"
          - option "Remediated"
          - option "Accepted risk"
          - option "False positive"
      - generic [ref=e31]:
        - img [ref=e32]
        - text: Not Found
  - alert [ref=e34]
```

# Test source

```ts
  133 |     await page.waitForTimeout(2000);
  134 |     await shot(page, "03_dashboard");
  135 | 
  136 |     const h1 = await page.locator("h1").first().textContent();
  137 |     console.log(`  H1: ${h1}`);
  138 |     await expect(page.locator("h1").first()).toBeVisible();
  139 | 
  140 |     // Nav links
  141 |     const navLinks = await page.getByRole("link", { name: /findings|assets|reports|remediation/i }).count();
  142 |     console.log(`  Nav links: ${navLinks}`);
  143 |     expect(navLinks).toBeGreaterThan(0);
  144 | 
  145 |     // Stat cards
  146 |     const cards = page.locator(".border-l-4, [class*='stat'], [class*='card']");
  147 |     console.log(`  Stat containers: ${await cards.count()}`);
  148 |   });
  149 | 
  150 |   // ── 4. Findings — add manually ────────────────────────────────────────────
  151 | 
  152 |   test("04 · Findings — add manually", async ({ page }) => {
  153 |     await loginAs(page, EMAIL, PASS);
  154 | 
  155 |     await page.goto(`${BASE}/findings`, { waitUntil: "load" });
  156 |     await page.waitForTimeout(2000);
  157 |     await shot(page, "04_findings_empty");
  158 | 
  159 |     // Click "+ Add manually" button
  160 |     await page.getByRole("button", { name: /add manually/i }).click();
  161 |     await page.waitForTimeout(500);
  162 |     await shot(page, "04_add_dialog");
  163 | 
  164 |     // Fill form — using exact placeholders from the UI
  165 |     await page.locator("input[placeholder*='CVE-2024']").fill("CVE-2021-44228");
  166 |     await page.locator("input[placeholder*='Short description']").fill("Log4Shell Remote Code Execution");
  167 |     await page.locator("dialog textarea, [role=dialog] textarea").first().fill(
  168 |       "JNDI injection vulnerability in Apache Log4j allows unauthenticated remote code execution."
  169 |     );
  170 |     // Severity is already set to Medium — upgrade to critical
  171 |     await page.locator("dialog select, [role=dialog] select").first().selectOption("critical");
  172 |     await page.locator("input[placeholder*='9.8']").fill("10.0");
  173 |     await page.locator("input[placeholder*='OpenSSL']").fill("log4j-core:2.14.1");
  174 | 
  175 |     await shot(page, "04_add_filled");
  176 | 
  177 |     // Submit — "Add finding" button
  178 |     const [addResp] = await Promise.all([
  179 |       page.waitForResponse((r) => r.url().includes("/vulnerabilities"), { timeout: 15000 }),
  180 |       page.getByRole("button", { name: /add finding/i }).click(),
  181 |     ]);
  182 |     const addBody = await addResp.text().catch(() => "");
  183 |     console.log(`  Add finding: ${addResp.status()} — ${addBody.slice(0, 150)}`);
  184 |     await page.waitForTimeout(2000);
  185 |     await shot(page, "04_after_add");
  186 | 
  187 |     const rows = await page.locator("tbody tr").count();
  188 |     console.log(`  Rows after add: ${rows}`);
  189 |     expect(addResp.status()).toBeLessThan(400);
  190 |   });
  191 | 
  192 |   // ── 5. Findings — CSV import ──────────────────────────────────────────────
  193 | 
  194 |   test("05 · Findings — CSV import", async ({ page }) => {
  195 |     await loginAs(page, EMAIL, PASS);
  196 | 
  197 |     await page.goto(`${BASE}/findings`, { waitUntil: "load" });
  198 |     await page.waitForTimeout(2000);
  199 | 
  200 |     await page.getByRole("button", { name: /upload csv/i }).click();
  201 |     await page.waitForTimeout(500);
  202 |     await shot(page, "05_import_dialog");
  203 | 
  204 |     // Write CSV to temp file and upload (CSV tab is selected by default)
  205 |     const csvPath = path.join(SHOTS, "test-vulns.csv");
  206 |     fs.writeFileSync(csvPath, VULN_CSV);
  207 |     await page.locator("input[type=file]").first().setInputFiles(csvPath);
  208 |     await page.waitForTimeout(1000);
  209 |     await shot(page, "05_import_file_selected");
  210 | 
  211 |     // Click "Import Csv" button — wait for response
  212 |     const [importResp] = await Promise.all([
  213 |       page.waitForResponse((r) => r.url().includes("/ingest/csv") || r.url().includes("/upload"), { timeout: 30000 }),
  214 |       page.getByRole("button", { name: /import csv|import/i }).last().click(),
  215 |     ]);
  216 |     const importBody = await importResp.text().catch(() => "");
  217 |     console.log(`  Import: ${importResp.status()} — ${importBody.slice(0, 200)}`);
  218 |     await page.waitForTimeout(2000);
  219 |     await shot(page, "05_import_result");
  220 | 
  221 |     expect(importResp.status()).toBeLessThan(400);
  222 |     const result = JSON.parse(importBody);
  223 |     console.log(`  ✓ Ingested: ${result.ingested}, Duplicates: ${result.duplicates}`);
  224 | 
  225 |     // Close dialog (click X)
  226 |     const xBtn = page.locator("button").filter({ has: page.locator("svg") }).last();
  227 |     await page.keyboard.press("Escape");
  228 |     await page.waitForTimeout(2000);
  229 |     await shot(page, "05_findings_list");
  230 | 
  231 |     const rows = await page.locator("tbody tr").count();
  232 |     console.log(`  Rows visible: ${rows}`);
> 233 |     expect(rows).toBeGreaterThan(0);
      |                  ^ Error: expect(received).toBeGreaterThan(expected)
  234 |   });
  235 | 
  236 |   // ── 6. Findings — enrich first vuln ──────────────────────────────────────
  237 | 
  238 |   test("06 · Findings — enrich first vuln", async ({ page }) => {
  239 |     await loginAs(page, EMAIL, PASS);
  240 | 
  241 |     await page.goto(`${BASE}/findings`, { waitUntil: "load" });
  242 |     await page.waitForTimeout(3000);
  243 | 
  244 |     const firstRow = page.locator("tbody tr").first();
  245 |     if (await firstRow.count() === 0) {
  246 |       console.log("  ⚠ No rows — skipping");
  247 |       return;
  248 |     }
  249 | 
  250 |     // Expand first row
  251 |     await firstRow.click();
  252 |     await page.waitForTimeout(1000);
  253 |     await shot(page, "06_row_expanded");
  254 | 
  255 |     // Enrich button
  256 |     const enrichBtn = page.getByRole("button", { name: /^enrich$/i }).first();
  257 |     if (await enrichBtn.count() > 0 && !(await enrichBtn.isDisabled())) {
  258 |       const [enrichResp] = await Promise.all([
  259 |         page.waitForResponse((r) => r.url().includes("/enrich"), { timeout: 30000 }),
  260 |         enrichBtn.click(),
  261 |       ]);
  262 |       console.log(`  Enrich: ${enrichResp.status()}`);
  263 |       await page.waitForTimeout(3000);
  264 |       await shot(page, "06_after_enrich");
  265 |     } else {
  266 |       console.log("  ⚠ Enrich button not available");
  267 |     }
  268 |   });
  269 | 
  270 |   // ── 7. Assets — add manually ──────────────────────────────────────────────
  271 | 
  272 |   test("07 · Assets — add manually", async ({ page }) => {
  273 |     await loginAs(page, EMAIL, PASS);
  274 | 
  275 |     await page.goto(`${BASE}/assets`, { waitUntil: "load" });
  276 |     // Wait for loading spinner to disappear
  277 |     await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
  278 |     await page.waitForTimeout(1500);
  279 |     await shot(page, "07_assets_page");
  280 | 
  281 |     // Open add dialog
  282 |     const addBtn = page.getByRole("button", { name: /add asset/i });
  283 |     await expect(addBtn).toBeVisible({ timeout: 10000 });
  284 |     await addBtn.click();
  285 |     await page.waitForTimeout(500);
  286 |     await shot(page, "07_add_dialog");
  287 | 
  288 |     // Fill using exact IDs from the source
  289 |     await page.locator("#a-name").fill("web-prod-01");
  290 |     await page.locator("#a-ip").fill("10.0.1.10");
  291 |     await page.locator("#a-host").fill("web-prod-01.corp");
  292 |     await page.locator("#a-crit").selectOption("critical");
  293 |     await page.locator("#a-env").selectOption("production");
  294 | 
  295 |     await shot(page, "07_add_filled");
  296 | 
  297 |     const [addResp] = await Promise.all([
  298 |       page.waitForResponse((r) => r.url().includes("/assets"), { timeout: 15000 }),
  299 |       page.getByRole("button", { name: /add asset/i }).last().click(),
  300 |     ]);
  301 |     const body = await addResp.text().catch(() => "");
  302 |     console.log(`  Add asset: ${addResp.status()} — ${body.slice(0, 150)}`);
  303 |     await page.waitForTimeout(2000);
  304 |     await shot(page, "07_after_add");
  305 | 
  306 |     expect(addResp.status()).toBeLessThan(400);
  307 |   });
  308 | 
  309 |   // ── 8. Assets — CSV import ────────────────────────────────────────────────
  310 | 
  311 |   test("08 · Assets — CSV import", async ({ page }) => {
  312 |     await loginAs(page, EMAIL, PASS);
  313 | 
  314 |     await page.goto(`${BASE}/assets`, { waitUntil: "load" });
  315 |     await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 15000 }).catch(() => null);
  316 |     await page.waitForTimeout(1500);
  317 | 
  318 |     // Open import dialog
  319 |     await page.getByRole("button", { name: /import csv|import/i }).click();
  320 |     await page.waitForTimeout(500);
  321 |     await shot(page, "08_import_dialog");
  322 | 
  323 |     const csvPath = path.join(SHOTS, "test-assets.csv");
  324 |     fs.writeFileSync(csvPath, ASSET_CSV);
  325 | 
  326 |     await page.locator("#import-file").setInputFiles(csvPath);
  327 |     await page.waitForTimeout(500);
  328 | 
  329 |     // Select format: "vulnops" is the default for generic CSV; check options
  330 |     const formatSelect = page.locator("dialog select, [role=dialog] select").first();
  331 |     if (await formatSelect.count() > 0) {
  332 |       const opts = await formatSelect.locator("option").allTextContents();
  333 |       console.log("  Format options:", opts);
```