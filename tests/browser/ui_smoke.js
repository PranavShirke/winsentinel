// Real-browser smoke test: drives the dashboard in Edge/Chrome and fails on any console or CSP error.
// Run via tests/test_browser.py (starts the fixture server) or manually:
//   set BASE_URL=http://127.0.0.1:5057 && npm test
const { chromium } = require("playwright-core");

const BASE = process.env.BASE_URL || "http://127.0.0.1:5057";
const SHOTS = process.env.SHOT_DIR || "";

async function launch() {
  const exe = process.env.BROWSER_EXE;
  if (exe) return chromium.launch({ executablePath: exe, headless: true });
  try { return await chromium.launch({ channel: "msedge", headless: true }); }
  catch (e) { return await chromium.launch({ channel: "chrome", headless: true }); }
}

(async () => {
  const browser = await launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const problems = [];
  page.on("console", (m) => { if (["error", "warning"].includes(m.type())) problems.push(m.type() + ": " + m.text()); });
  page.on("pageerror", (e) => problems.push("pageerror: " + e.message));

  const results = [];
  const check = (name, ok, extra) => results.push({ ok, line: (ok ? "PASS " : "FAIL ") + name + (extra ? "  [" + extra + "]" : "") });
  const shot = async (name) => { if (SHOTS) await page.screenshot({ path: SHOTS + "/" + name + ".png" }); };

  try {
  // ---- Findings: filters, search, sort, expand, fix command, risk decision
  await page.goto(BASE + "/findings");
  await page.waitForSelector("tbody.finding");
  const total = await page.locator("tbody.finding").count();
  check("findings rendered", total >= 8, "rows=" + total);

  await page.locator(".chip", { hasText: "High" }).first().click();
  await page.waitForTimeout(150);
  const high = await page.locator("tbody.finding:visible").count();
  check("severity chip filters rows", high > 0 && high < total, "visible=" + high);
  await page.locator(".chip", { hasText: "All" }).first().click();

  await page.fill("#finding-search", "password");
  await page.waitForTimeout(150);
  check("live search filters rows", (await page.locator("tbody.finding:visible").count()) === 1);
  await page.fill("#finding-search", "");

  await page.selectOption("#finding-sort", "title");
  const titles = await page.locator("tbody.finding .finding-title").allInnerTexts();
  check("sort A-Z reorders", JSON.stringify(titles) === JSON.stringify([...titles].sort((a, b) => a.localeCompare(b))));
  await page.selectOption("#finding-sort", "risk");

  const target = page.locator("tbody.finding", { hasText: "Minimum Password Length" }).first();
  await target.locator(".finding-main").click();
  check("row expands", await target.locator(".detail-row").isVisible());
  check("framework tag shown", (await target.locator(".tag-attack").count()) > 0);
  check("fix command shown", (await target.locator(".fixbox .code").innerText()).includes("net accounts /minpwlen:12"));
  check("copy button present", (await target.locator("[data-copy-target]").count()) === 1);

  await target.locator("button", { hasText: "Risk decision" }).click();
  await page.waitForSelector(".overlay.center .dialog", { state: "visible" });
  await page.check('input[value="accepted"]', { force: true });
  await page.fill("#reg-note", "");
  await page.locator(".dialog-foot button[type=submit]").click();
  check("justification required", (await page.locator(".dialog-error").innerText()).toLowerCase().includes("justification"));
  await page.fill("#reg-note", "Accepted by lab owner for the demo environment");
  await page.locator(".dialog-foot button[type=submit]").click();
  await page.waitForSelector(".toast", { timeout: 5000 });
  check("decision saved and toast shown", (await page.locator(".toast").first().innerText()).includes("Adjusted score"));
  check("row shows decision badge", (await target.locator(".reg").first().innerText()).toLowerCase().includes("accepted"));
  await shot("findings");

  // ---- Command palette
  await page.keyboard.press("Control+k");
  await page.waitForSelector(".palette", { state: "visible" });
  await page.keyboard.type("alerts");
  await page.waitForTimeout(250);
  await Promise.all([page.waitForURL("**/alerts"), page.keyboard.press("Enter")]);
  check("palette navigates", page.url().endsWith("/alerts"));

  // ---- Alerts: live monitor panel and analytics charts
  await page.waitForSelector("#analytics");
  await page.waitForTimeout(800);
  check("live alerts listed", (await page.locator("#live-panel").innerText()).includes("Brute Force Attack"));
  check("analytics charts drawn", (await page.locator("#analytics canvas").count()) === 4);
  const chipState = await page.locator("#live-chip").getAttribute("data-state");
  check("live chip updates from API", ["on", "off", "error"].includes(chipState), "state=" + chipState);
  await shot("alerts");

  // ---- Dashboard / frameworks / verify / theme / downloads
  await page.goto(BASE + "/dashboard");
  await page.waitForTimeout(1500);
  check("adjusted score after accepting risk", (await page.locator(".adjusted-line").count()) === 1);
  await shot("dashboard");

  await page.goto(BASE + "/frameworks");
  check("frameworks page has rows", (await page.locator(".cov-row").count()) > 3);

  await page.goto(BASE + "/report/verify");
  check("verify page renders", (await page.locator("#report-file").count()) === 1);

  await page.goto(BASE + "/findings");
  await page.click(".icon-btn");
  await page.waitForTimeout(300);
  check("theme switches to light", (await page.evaluate(() => document.documentElement.getAttribute("data-theme"))) === "light");

  const pdf = await page.request.get(BASE + "/report/download.pdf");
  const body = await pdf.body();
  check("pdf download with integrity header", pdf.status() === 200 && body.slice(0, 4).toString() === "%PDF" && /^[0-9a-f]{64}$/.test(pdf.headers()["x-report-sha256"] || ""));

  check("no console or CSP errors", problems.length === 0, problems.join(" | ").slice(0, 400));
  } catch (e) {
    // Report how far we got and what the browser logged, then fail
    check("test aborted: " + String(e.message).split("\n")[0], false, "url=" + page.url() + " console=" + problems.join(" | ").slice(0, 400));
  }

  console.log(results.map((r) => r.line).join("\n"));
  await browser.close();
  process.exit(results.every((r) => r.ok) ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });
