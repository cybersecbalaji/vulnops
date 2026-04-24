# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: live-check.spec.ts >> Live app workflow check
- Location: playwright\live-check.spec.ts:46:5

# Error details

```
Test timeout of 300000ms exceeded.
```

```
Error: locator.click: Test timeout of 300000ms exceeded.
Call log:
  - waiting for getByRole('button', { name: /pdf|download/i }).first()
    - locator resolved to <button disabled class="inline-flex items-center justify-center whitespace-nowrap text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3">…</button>
  - attempting click action
    2 × waiting for element to be visible, enabled and stable
      - element is not enabled
    - retrying click action
    - waiting 20ms
    2 × waiting for element to be visible, enabled and stable
      - element is not enabled
    - retrying click action
      - waiting 100ms
    345 × waiting for element to be visible, enabled and stable
        - element is not enabled
      - retrying click action
        - waiting 500ms

```

# Page snapshot

```yaml
- generic [active] [ref=e1]:
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
            - text: Reports
        - generic [ref=e13]:
          - button "Switch to light mode" [ref=e14] [cursor=pointer]:
            - img [ref=e15]
          - button "Refresh" [ref=e17] [cursor=pointer]:
            - img [ref=e18]
            - text: Refresh
          - button "Download PDF" [disabled]:
            - img
            - text: Download PDF
    - main [ref=e23]:
      - generic [ref=e24]:
        - heading "Vulnerability Report" [level=1] [ref=e25]
        - paragraph [ref=e26]: Board-ready summary of your org's current vulnerability posture. Data refreshes in real time.
      - alert [ref=e27]:
        - generic [ref=e28]: Not authenticated
  - alert [ref=e29]
```

# Test source

```ts
  219 |   // ══════════════════════════════════════════════════════
  220 |   console.log("\n═══ 9. ASSETS — add manually ═══");
  221 |   const addAssetBtn = page.getByRole("button", { name: /add asset/i });
  222 |   if (await addAssetBtn.count() > 0) {
  223 |     await addAssetBtn.click();
  224 |     await page.waitForTimeout(800);
  225 |     await shot(page, "09_add_asset_dialog");
  226 | 
  227 |     await page.locator("#a-name").fill("web-prod-01");
  228 |     await page.locator("#a-ip").fill("10.0.1.10");
  229 |     await page.locator("#a-host").fill("web-prod-01.corp");
  230 |     await page.locator("#a-crit").selectOption("critical");
  231 |     await shot(page, "09_asset_filled");
  232 | 
  233 |     const [assetAddResp] = await Promise.all([
  234 |       page.waitForResponse((r) => r.url().includes("/assets"), { timeout: 20000 }),
  235 |       // Click the submit button inside the dialog (not the trigger in the header)
  236 |       page.locator('[role="dialog"] button:has-text("Add asset")').click(),
  237 |     ]);
  238 |     const assetAddBody = await assetAddResp.text().catch(() => "");
  239 |     console.log(`Add asset: ${assetAddResp.status()} — ${assetAddBody.slice(0, 200)}`);
  240 |     await page.waitForTimeout(3000);
  241 |     await shot(page, "09_after_add_asset");
  242 | 
  243 |     await page.goto(`${BASE}/assets`, { waitUntil: "load" });
  244 |     await waitForListLoad(page, "/assets");
  245 |     await shot(page, "09_assets_after_add");
  246 |     const assetRows = await page.locator("tbody tr").count();
  247 |     console.log(`Asset rows after add: ${assetRows}`);
  248 |   }
  249 | 
  250 |   // ══════════════════════════════════════════════════════
  251 |   // 10. ASSETS — CSV import
  252 |   // ══════════════════════════════════════════════════════
  253 |   console.log("\n═══ 10. ASSETS — CSV import ═══");
  254 |   const importAssetBtn = page.getByRole("button", { name: /import csv|import/i }).first();
  255 |   if (await importAssetBtn.count() > 0) {
  256 |     await importAssetBtn.click();
  257 |     await page.waitForTimeout(800);
  258 |     await shot(page, "10_asset_import_dialog");
  259 | 
  260 |     const assetCsvPath = path.join(DIR, "assets.csv");
  261 |     fs.writeFileSync(assetCsvPath, ASSET_CSV);
  262 |     await page.locator("#import-file, input[type=file]").first().setInputFiles(assetCsvPath);
  263 |     await page.waitForTimeout(800);
  264 |     await shot(page, "10_asset_csv_selected");
  265 | 
  266 |     const [assetImportResp] = await Promise.all([
  267 |       page.waitForResponse((r) => r.url().includes("/assets"), { timeout: 30000 }),
  268 |       page.getByRole("button", { name: /import/i }).last().click(),
  269 |     ]);
  270 |     const assetImportBody = await assetImportResp.text().catch(() => "");
  271 |     console.log(`Asset import: ${assetImportResp.status()} — ${assetImportBody.slice(0, 200)}`);
  272 |     await page.waitForTimeout(3000);
  273 |     await shot(page, "10_asset_import_done");
  274 | 
  275 |     await page.goto(`${BASE}/assets`, { waitUntil: "load" });
  276 |     await waitForListLoad(page, "/assets");
  277 |     await shot(page, "10_assets_after_import");
  278 |     const assetRowsAfter = await page.locator("tbody tr").count();
  279 |     console.log(`Asset rows after import: ${assetRowsAfter}`);
  280 |   }
  281 | 
  282 |   // ══════════════════════════════════════════════════════
  283 |   // 11. ASSETS — match vulnerabilities
  284 |   // ══════════════════════════════════════════════════════
  285 |   console.log("\n═══ 11. ASSETS — match vulns ═══");
  286 |   const matchBtn = page.getByRole("button", { name: /match vulnerabilities/i });
  287 |   if (await matchBtn.count() > 0 && !(await matchBtn.isDisabled())) {
  288 |     const [matchResp] = await Promise.all([
  289 |       page.waitForResponse((r) => r.url().includes("match"), { timeout: 15000 }),
  290 |       matchBtn.click(),
  291 |     ]);
  292 |     console.log(`Match vulns: ${matchResp.status()} — ${(await matchResp.text().catch(() => "")).slice(0, 100)}`);
  293 |     await page.waitForTimeout(2000);
  294 |     await shot(page, "11_after_match");
  295 |   } else {
  296 |     console.log("⚠ Match button disabled or not found");
  297 |     await shot(page, "11_match_state");
  298 |   }
  299 | 
  300 |   // ══════════════════════════════════════════════════════
  301 |   // 12. REPORTS
  302 |   // ══════════════════════════════════════════════════════
  303 |   console.log("\n═══ 12. REPORTS ═══");
  304 |   await page.goto(`${BASE}/reports`, { waitUntil: "load" });
  305 |   await waitForListLoad(page, "/reports/dashboard");
  306 |   await shot(page, "12_reports");
  307 |   const reportsText = await page.locator("body").textContent().catch(() => "");
  308 |   if (reportsText?.includes("Failed") || reportsText?.includes("Error")) {
  309 |     console.log("⚠ Reports error");
  310 |   } else {
  311 |     console.log("✓ Reports loaded");
  312 |   }
  313 | 
  314 |   // PDF download
  315 |   const pdfBtn = page.getByRole("button", { name: /pdf|download/i }).first();
  316 |   if (await pdfBtn.count() > 0) {
  317 |     const [dl] = await Promise.all([
  318 |       page.waitForEvent("download", { timeout: 30000 }).catch(() => null),
> 319 |       pdfBtn.click(),
      |              ^ Error: locator.click: Test timeout of 300000ms exceeded.
  320 |     ]);
  321 |     await page.waitForTimeout(4000);
  322 |     if (dl) {
  323 |       const savePath = path.join(DIR, "report.pdf");
  324 |       await dl.saveAs(savePath);
  325 |       console.log(`✓ PDF downloaded: ${fs.statSync(savePath).size} bytes`);
  326 |     } else {
  327 |       console.log("⚠ PDF download not triggered");
  328 |     }
  329 |     await shot(page, "12_reports_after_pdf");
  330 |   }
  331 | 
  332 |   // ══════════════════════════════════════════════════════
  333 |   // 13. REMEDIATION
  334 |   // ══════════════════════════════════════════════════════
  335 |   console.log("\n═══ 13. REMEDIATION ═══");
  336 |   await page.goto(`${BASE}/remediation`, { waitUntil: "load" });
  337 |   await waitForListLoad(page, "/vulnerabilities");
  338 |   await page.waitForSelector("text=Loading findings...", { state: "hidden", timeout: 10000 }).catch(() => null);
  339 |   await page.waitForTimeout(1500);
  340 |   await shot(page, "13_remediation");
  341 | 
  342 |   // Try Generate triage plan
  343 |   const triageBtn = page.getByRole("button", { name: /generate triage plan/i });
  344 |   if (await triageBtn.count() > 0) {
  345 |     const [triageResp] = await Promise.all([
  346 |       page.waitForResponse((r) => r.url().includes("/remediation") || r.url().includes("triage"), { timeout: 60000 }),
  347 |       triageBtn.click(),
  348 |     ]);
  349 |     console.log(`Triage plan: ${triageResp.status()}`);
  350 |     await page.waitForTimeout(5000);
  351 |     await shot(page, "13_triage_result");
  352 |   }
  353 | 
  354 |   // Try Draft ticket (needs a vuln selected)
  355 |   const findingSelect = page.locator("select").first();
  356 |   if (await findingSelect.count() > 0) {
  357 |     const opts = await findingSelect.locator("option").allTextContents();
  358 |     console.log(`Finding options: ${opts.length} — ${opts.slice(0, 4).join(" | ")}`);
  359 |     if (opts.length > 1) {
  360 |       await findingSelect.selectOption({ index: 1 });
  361 |       await page.waitForTimeout(500);
  362 |       const draftBtn = page.getByRole("button", { name: /draft ticket/i });
  363 |       const isDraftDisabled = await draftBtn.isDisabled().catch(() => true);
  364 |       console.log(`Draft ticket button disabled: ${isDraftDisabled}`);
  365 |       if (!isDraftDisabled) {
  366 |         const [draftResp] = await Promise.all([
  367 |           page.waitForResponse((r) => r.url().includes("/remediation/"), { timeout: 60000 }),
  368 |           draftBtn.click(),
  369 |         ]);
  370 |         console.log(`Draft ticket: ${draftResp.status()}`);
  371 |         await page.waitForTimeout(8000);
  372 |       }
  373 |       await shot(page, "13_draft_state");
  374 |     }
  375 |   }
  376 | 
  377 |   // ══════════════════════════════════════════════════════
  378 |   // 14. SETTINGS
  379 |   // ══════════════════════════════════════════════════════
  380 |   console.log("\n═══ 14. SETTINGS ═══");
  381 |   await page.goto(`${BASE}/settings`, { waitUntil: "load" });
  382 |   await page.waitForTimeout(2000);
  383 |   await shot(page, "14_settings");
  384 |   const settingsText = await page.locator("body").textContent().catch(() => "");
  385 |   if (settingsText?.includes("Failed") || settingsText?.includes("Error")) {
  386 |     console.log("⚠ Settings error");
  387 |   } else {
  388 |     console.log("✓ Settings loaded");
  389 |   }
  390 | 
  391 |   // ══════════════════════════════════════════════════════
  392 |   // 15. FINAL STATE — all pages
  393 |   // ══════════════════════════════════════════════════════
  394 |   console.log("\n═══ 15. FINAL SCREENSHOTS ═══");
  395 |   const finalPages = ["/dashboard", "/findings", "/assets", "/reports", "/settings"];
  396 |   for (const p of finalPages) {
  397 |     await page.goto(`${BASE}${p}`, { waitUntil: "load" });
  398 |     await page.waitForSelector("text=Loading...", { state: "hidden", timeout: 10000 }).catch(() => null);
  399 |     await page.waitForTimeout(3000);
  400 |     await shot(page, `15_final${p.replace("/", "_")}`);
  401 |     console.log(`✓ ${p}`);
  402 |   }
  403 | 
  404 |   console.log(`\n✓ All screenshots saved to: ${DIR}`);
  405 | });
  406 | 
```