// A seller's own web page inside the app (docs/SELLER-APPS.md), in a real headless Chrome over the
// DevTools protocol: set the password, keep a stand-in approval key in the wallet's storage, then
// open three sellers' pages: a model's chat page (compressed page, streamed answer), a media
// server's web client (a login with a cookie, a token in its storage, a request with its login
// header) and a hostile page. Screenshots (wide and phone width) go to OUT.
//   node seller_app_test.mjs BASE SETUP_CODE OUT OPENS_JSON
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [BASE, CODE, OUT, OPENS] = process.argv.slice(2);
const opens = JSON.parse(OPENS);
mkdirSync(OUT, { recursive: true });
const CHROME = process.env.CHROME || "google-chrome";
const profile = mkdtempSync(join(tmpdir(), "xbtui-app-chrome-"));
const chrome = spawn(CHROME, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--no-sandbox",
  "--disable-dev-shm-usage", "--disable-popup-blocking", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
let chromeErr = ""; let chromeExit = null; let finishing = false;
chrome.stderr.on("data", (d) => { chromeErr = (chromeErr + d).slice(-4000); });
chrome.on("error", (e) => { chromeExit = `could not run ${CHROME}: ${e.message}`; });
const CALL_MS = 30000;
const LIMIT_S = Number(process.env.XBT_UI_JS_LIMIT_S || 300);
function fail(why) { console.log(`FAIL ${why}`); try { chrome.kill("SIGKILL"); } catch (e) { /* gone */ } process.exit(1); }
setTimeout(() => fail(`the run took over ${LIMIT_S} s: Chrome stopped answering`), LIMIT_S * 1000);
chrome.on("exit", (code, sig) => { chromeExit = `exit ${code ?? "none"} signal ${sig ?? "none"}`; if (!finishing) fail(`Chrome exited (${code ?? sig}) during the run: ${chromeErr}`); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail }); console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : " " + (detail || "")}`); }

let port;
for (let i = 0; i < 1200 && !port && chromeExit === null; i++) {
  await sleep(100);
  const f = join(profile, "DevToolsActivePort");
  if (existsSync(f)) port = readFileSync(f, "utf8").split("\n")[0];
}
if (!port) { console.log(`FAIL chrome did not start (${chromeExit ?? "no DevTools port after 120 s"}): ${chromeErr}`); process.exit(1); }
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r, j) => { ws.addEventListener("open", r); ws.addEventListener("error", () => j(new Error("the DevTools connection failed")));
  setTimeout(() => j(new Error("the DevTools connection did not open")), CALL_MS); }).catch((e) => fail(e.message));
ws.addEventListener("close", () => { if (!finishing) fail("Chrome closed the DevTools connection"); });
let seq = 0; const pending = new Map();
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
});
function cdp(method, params = {}) {
  const id = ++seq;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((r, j) => {
    const t = setTimeout(() => { pending.delete(id); j(new Error(`${method}: no answer from Chrome in ${CALL_MS / 1000} s`)); }, CALL_MS);
    pending.set(id, (d) => { clearTimeout(t); r(d.result || { error: d.error }); });
  });
}
async function ev(expr, contextId) {
  const r = await cdp("Runtime.evaluate", Object.assign({ expression: expr, awaitPromise: true, returnByValue: true }, contextId ? { contextId } : {}));
  if (r.exceptionDetails) throw new Error(`${expr}: ${JSON.stringify(r.exceptionDetails)}`);
  return r.result && r.result.value;
}
async function loaded() {
  for (let i = 0; i < 200; i++) {
    await sleep(50);
    try { if ((await ev("document.readyState")) === "complete" && (await ev("!!document.body"))) return; } catch (e) { /* navigating */ }
  }
}
async function go(path) { await cdp("Page.navigate", { url: BASE + path }); await sleep(100); await loaded(); }
async function submitAndWait(expr) {
  const before = await ev("performance.timeOrigin");
  await ev(expr);
  for (let i = 0; i < 400; i++) {
    await sleep(50);
    try { if ((await ev("performance.timeOrigin")) !== before && (await ev("document.readyState")) === "complete") return; } catch (e) { /* navigating */ }
  }
}
async function shot(name, width) {
  await cdp("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
  await sleep(250);
  const png = await cdp("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(OUT, `${name}.png`), Buffer.from(png.data, "base64"));
  const wide = await ev("document.documentElement.scrollWidth <= window.innerWidth + 1");
  await cdp("Emulation.setDeviceMetricsOverride", { width: 1100, height: 900, deviceScaleFactor: 1, mobile: false });
  return wide;
}
const set = (sel, v) => ev(`(function(){var e=document.querySelector(${JSON.stringify(sel)});e.value=${JSON.stringify(v)};return true})()`);
// the frame's own world: its DOM and storage, as its page sees them
async function frameWorld() {
  const tree = await cdp("Page.getFrameTree");
  const child = (tree.frameTree.childFrames || [])[0];
  if (!child) return null;
  const w = await cdp("Page.createIsolatedWorld", { frameId: child.frame.id, worldName: "check" });
  return { id: w.executionContextId, url: child.frame.url };
}
async function frameTitle(want, ms) {
  for (let i = 0; i < ms / 100; i++) {
    await sleep(100);
    const f = await frameWorld();
    if (!f) continue;
    try { const t = await ev("document.title", f.id); if (t.startsWith(want)) return { t, f }; } catch (e) { /* loading */ }
  }
  const f = await frameWorld();
  return { t: f ? await ev("document.title", f.id).catch(() => "none") : "no frame", f };
}
async function openApp(path) {
  await go(path);
  check(`${path.slice(0, 12)}: the limit is asked first`, (await ev("document.body.innerText")).includes("Spend at most"));
  await set("[name=limit]", "800");
  await submitAndWait("document.querySelector('form[action=\"./app\"]').submit()");
}

await cdp("Page.enable"); await cdp("Runtime.enable");
try {
  await go("/");
  await set("[name=code]", CODE); await set("[name=password]", "seller app box password"); await set("[name=password2]", "seller app box password");
  await submitAndWait("document.querySelector('form').submit()");
  // a stand-in approval key in the wallet's storage: no seller's page may read it
  await ev("localStorage.setItem('xbt-wallet-human-key-v1', JSON.stringify({pub: 'not a real key'}))");

  // 1. a model's chat page: served only compressed, its answer streamed
  await openApp(opens.chat);
  check("chat: the visit bar says what is spent and has Stop", (await ev("document.body.innerText")).includes("spent on this visit") && await ev("!!document.querySelector('.app-visit button.danger')"));
  const chat = await frameTitle("chat-", 20000);
  check("chat: the page loaded and the streamed answer arrived", chat.t === "chat-done", chat.t);
  check("chat: the answer reads whole", chat.f && (await ev("document.getElementById('out').textContent", chat.f.id)) === "Hello from the model");
  check("chat: the frame is another origin than the wallet", chat.f && !chat.f.url.startsWith(BASE), chat.f && chat.f.url);
  check("chat: the one-time code is gone from the frame's address", chat.f && !chat.f.url.includes("/__ls/enter"), chat.f && chat.f.url);
  check("chat: no sideways scroll on the wide page", await shot("01-chat-wide", 1100));
  check("chat: no sideways scroll at phone width", await shot("02-chat-phone", 390));
  await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
  check("chat: dark, wide", await shot("01b-chat-dark", 1100));
  check("chat: dark, phone width", await shot("02b-chat-phone-dark", 390));
  await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });

  // 2. a media server's web client: login, cookie, token in its own storage, a request with its login header
  await openApp(opens.jf);
  const jf = await frameTitle("jf-", 20000);
  check("media: the web client logged in and listed the films", jf.t === "jf-done", jf.t);
  check("media: its items show", jf.f && (await ev("document.getElementById('items').innerText", jf.f.id)).includes("Big Buck Bunny"));
  check("media: its token is in its own storage", jf.f && (await ev("localStorage.getItem('jf_token')", jf.f.id)) === "tok-123");
  check("media: the wallet's storage is not the page's", jf.f && (await ev("localStorage.getItem('xbt-wallet-human-key-v1')", jf.f.id)) === null);
  check("media: the seller's cookie is not readable by the page (HttpOnly) and the wallet's are not either",
        jf.f && !(await ev("document.cookie", jf.f.id)).includes("xbt_ui"), jf.f && await ev("document.cookie", jf.f.id));
  await shot("03-media-wide", 1100);
  await shot("04-media-phone", 390);

  // 3. a hostile page: it tries the wallet, then reports
  await openApp(opens.evil);
  const evil = await frameTitle("evil-", 20000);
  check("hostile: the page ran and reported", evil.t === "evil-done", evil.t);
  check("hostile: the wallet's storage is still there", (await ev("localStorage.getItem('xbt-wallet-human-key-v1')")) !== null);
  await shot("05-hostile-wide", 1100);

  // 4. Stop: the visit ends and the frame closes
  await submitAndWait("document.querySelector('.app-visit form[action=\"./app-stop\"]').submit()");
  check("stop: back on Browse, saying it stopped", (await ev("document.body.innerText")).includes("Stopped"), await ev("location.href"));
} catch (e) {
  check("no error", false, e.stack || String(e));
}
finishing = true;
try { chrome.kill("SIGKILL"); } catch (e) { /* gone */ }
try { rmSync(profile, { recursive: true, force: true }); } catch (e) { /* busy */ }
const failed = results.filter((r) => !r.ok);
console.log(`${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
