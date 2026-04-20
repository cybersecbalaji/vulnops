# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: auth.test.ts >> VulnOps Auth Flow >> full signup → login flow
- Location: playwright\auth.test.ts:86:7

# Error details

```
Error: expect(received).toContain(expected) // indexOf

Expected substring: "dashboard"
Received string:    "https://grand-youthfulness-production-3b33.up.railway.app/register"
```

# Page snapshot

```yaml
- generic [active] [ref=e1]:
  - generic [ref=e2]:
    - button "Switch to light mode" [ref=e4] [cursor=pointer]:
      - img [ref=e5]
    - generic [ref=e7]:
      - generic [ref=e8]:
        - img [ref=e9]
        - generic [ref=e11]: VulnOps
      - generic [ref=e12]:
        - generic [ref=e13]:
          - heading "Create your organization" [level=3] [ref=e14]
          - paragraph [ref=e15]: Set up VulnOps for your security team. You'll be the admin.
        - generic [ref=e17]:
          - alert [ref=e18]:
            - generic [ref=e19]: Unexpected response from server.
          - generic [ref=e20]:
            - text: Organization name
            - textbox "Organization name" [ref=e21]:
              - /placeholder: Acme Security
              - text: TestOrg1776686193165
          - generic [ref=e22]:
            - text: Work email
            - textbox "Work email" [ref=e23]:
              - /placeholder: you@acme.com
              - text: test+1776686193165@example.com
          - generic [ref=e24]:
            - text: Password
            - generic [ref=e25]:
              - textbox "Password" [ref=e26]:
                - /placeholder: Minimum 12 characters
                - text: TestPass123!@#
              - button "Show password" [ref=e27] [cursor=pointer]:
                - img [ref=e28]
            - list [ref=e31]:
              - listitem [ref=e32]:
                - img [ref=e33]
                - generic [ref=e36]: At least 12 characters
              - listitem [ref=e37]:
                - img [ref=e38]
                - generic [ref=e41]: Contains a number
              - listitem [ref=e42]:
                - img [ref=e43]
                - generic [ref=e46]: Contains a special character
              - listitem [ref=e47]:
                - img [ref=e48]
                - generic [ref=e51]: Contains uppercase letter
          - alert [ref=e52]:
            - generic [ref=e53]: Your password is checked against the HaveIBeenPwned database using k-anonymity (only the first 5 characters of your password hash are sent — your password never leaves your device).
          - button "Create account" [ref=e54] [cursor=pointer]
        - paragraph [ref=e56]:
          - text: Already have an account?
          - link "Sign in" [ref=e57] [cursor=pointer]:
            - /url: /login
  - alert [ref=e58]
```

# Test source

```ts
  24  |     console.log("✓ Homepage loaded:", await page.title());
  25  |   });
  26  | 
  27  |   test("register page loads", async ({ page }) => {
  28  |     await page.goto(`${BASE}/register`);
  29  |     await expect(page.getByText("Create your organization")).toBeVisible({ timeout: 10000 });
  30  |     console.log("✓ Register page loaded");
  31  |   });
  32  | 
  33  |   test("API call from register — capture network request", async ({ page }) => {
  34  |     const apiCalls: { url: string; status: number; body: string }[] = [];
  35  | 
  36  |     // Intercept all fetch/XHR calls
  37  |     page.on("response", async (response) => {
  38  |       const url = response.url();
  39  |       if (url.includes("/api/") || url.includes("register") || url.includes("orgs")) {
  40  |         try {
  41  |           const body = await response.text().catch(() => "(unreadable)");
  42  |           apiCalls.push({ url, status: response.status(), body: body.slice(0, 300) });
  43  |           console.log(`API call: ${response.status()} ${url}`);
  44  |           console.log(`  Response: ${body.slice(0, 200)}`);
  45  |         } catch {
  46  |           apiCalls.push({ url, status: response.status(), body: "(error reading body)" });
  47  |         }
  48  |       }
  49  |     });
  50  | 
  51  |     await page.goto(`${BASE}/register`);
  52  |     await page.getByLabel("Organization name").fill(TEST_ORG);
  53  |     await page.getByLabel("Work email").fill(TEST_EMAIL);
  54  |     await page.locator("#password").fill(TEST_PASSWORD);
  55  | 
  56  |     // Click register and wait for network
  57  |     await Promise.all([
  58  |       page.waitForResponse((r) => r.url().includes("/api/"), { timeout: 15000 }).catch(() => null),
  59  |       page.getByRole("button", { name: /create account/i }).click(),
  60  |     ]);
  61  | 
  62  |     await page.waitForTimeout(3000);
  63  | 
  64  |     console.log("\n=== All API calls captured ===");
  65  |     if (apiCalls.length === 0) {
  66  |       console.log("NO API calls were made — NEXT_PUBLIC_API_URL is likely not set");
  67  |       console.log("Check the page URL of the API call:");
  68  |       const allResponses = await page.evaluate(() => {
  69  |         // Check what API_BASE resolves to
  70  |         return window.location.origin;
  71  |       });
  72  |       console.log("Page origin:", allResponses);
  73  |     }
  74  |     apiCalls.forEach((c) => console.log(c));
  75  | 
  76  |     // Check for error message on page
  77  |     const errorText = await page.getByText(/unexpected|error|failed/i).first().textContent().catch(() => null);
  78  |     if (errorText) {
  79  |       console.log("Error shown on page:", errorText);
  80  |     }
  81  | 
  82  |     // The test passes as diagnostic — it logs what's happening
  83  |     expect(true).toBe(true);
  84  |   });
  85  | 
  86  |   test("full signup → login flow", async ({ page }) => {
  87  |     // Step 1: Register
  88  |     await page.goto(`${BASE}/register`);
  89  |     await expect(page.getByText("Create your organization")).toBeVisible({ timeout: 10000 });
  90  | 
  91  |     await page.getByLabel("Organization name").fill(TEST_ORG);
  92  |     await page.getByLabel("Work email").fill(TEST_EMAIL);
  93  |     await page.locator("#password").fill(TEST_PASSWORD);
  94  |     await page.getByRole("button", { name: /create account/i }).click();
  95  | 
  96  |     // Wait up to 15s for either success (redirect to /dashboard or /login) or error
  97  |     await page.waitForURL(/\/(dashboard|login|verify)/, { timeout: 15000 }).catch(async () => {
  98  |       const bodyText = await page.locator("body").textContent();
  99  |       console.log("Page did not redirect. Body text:", bodyText?.slice(0, 500));
  100 |     });
  101 | 
  102 |     const currentUrl = page.url();
  103 |     console.log("After register, URL:", currentUrl);
  104 | 
  105 |     if (currentUrl.includes("dashboard")) {
  106 |       console.log("✓ Registered and auto-logged in to dashboard");
  107 |       return;
  108 |     }
  109 | 
  110 |     // Step 2: Login if redirected to /login
  111 |     if (currentUrl.includes("login")) {
  112 |       await page.getByLabel(/email/i).fill(TEST_EMAIL);
  113 |       await page.getByLabel(/password/i).fill(TEST_PASSWORD);
  114 |       await page.getByRole("button", { name: /sign in/i }).click();
  115 | 
  116 |       await page.waitForURL(/\/dashboard/, { timeout: 15000 }).catch(async () => {
  117 |         const bodyText = await page.locator("body").textContent();
  118 |         console.log("Login did not redirect to dashboard. Body:", bodyText?.slice(0, 500));
  119 |       });
  120 | 
  121 |       console.log("After login, URL:", page.url());
  122 |     }
  123 | 
> 124 |     expect(page.url()).toContain("dashboard");
      |                        ^ Error: expect(received).toContain(expected) // indexOf
  125 |   });
  126 | });
  127 | 
```