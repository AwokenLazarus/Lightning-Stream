// The look of the app in a real headless Chrome: screenshots of the main pages in light, dark and
// at phone width, the cost of the river background (CPU and frame time, with and without it), and
// the contrast of text over the brightest point the river reaches.
//   node look_test.mjs WALLET_BASE SETUP_CODE GATEWAY_BASE GATEWAY_SETUP_CODE OUT PLAY_PATH SECONDS PAGES
// PAGES: a JSON list of [name, path] for the wallet's pages to shoot.
// Prints one JSON line starting "LOOK " with the measurements.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [BASE, CODE, GW, GWCODE, OUT, PLAY, SECS, PAGES] = process.argv.slice(2);
const SECONDS = Number(SECS || 30);
mkdirSync(OUT, { recursive: true });
const CHROME = process.env.CHROME || "google-chrome";
const profile = mkdtempSync(join(tmpdir(), "ls-look-"));
const chrome = spawn(CHROME, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--no-sandbox", "--hide-scrollbars",
  "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let port;
for (let i = 0; i < 100 && !port; i++) {
  await sleep(100);
  const f = join(profile, "DevToolsActivePort");
  if (existsSync(f)) port = readFileSync(f, "utf8").split("\n")[0];
}
if (!port) { console.log("FAIL chrome did not start"); process.exit(1); }
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let seq = 0; const pending = new Map();
ws.addEventListener("message", (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } });
function cdp(method, params = {}) { const id = ++seq; ws.send(JSON.stringify({ id, method, params })); return new Promise((r) => pending.set(id, (d) => r(d.result || { error: d.error }))); }
async function ev(expr) {
  const r = await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`${expr}: ${JSON.stringify(r.exceptionDetails)}`);
  return r.result && r.result.value;
}
async function loaded() {
  for (let i = 0; i < 200; i++) { await sleep(50); try { if ((await ev("document.readyState")) === "complete") return; } catch (e) { /* navigating */ } }
}
async function go(url) { await cdp("Page.navigate", { url }); await sleep(150); await loaded(); await sleep(300); }
async function submitAndWait(expr) {
  const before = await ev("performance.timeOrigin"); await ev(expr);
  for (let i = 0; i < 400; i++) { await sleep(50); try { if ((await ev("performance.timeOrigin")) !== before && (await ev("document.readyState")) === "complete") return; } catch (e) { /* navigating */ } }
}
const set = (sel, v) => ev(`(function(){var e=document.querySelector(${JSON.stringify(sel)});e.value=${JSON.stringify(v)};return true})()`);
async function scheme(s) { await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: s }] }); }
async function size(width, height) { await cdp("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 600 }); }
async function sweep(x0, y0) {
  // the pointer drifts across the middle of the screen, so a shot shows the bend and an arc
  for (let i = 0; i < 14; i++) { await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x: x0 + i * 9, y: y0 + Math.sin(i / 2) * 20 }); await sleep(35); }
}
const shots = [];
async function shot(name, width) {
  await size(width, width < 600 ? 844 : 900); await sleep(200);
  await sweep(width * 0.55, width < 600 ? 520 : 380);
  const png = await cdp("Page.captureScreenshot", { format: "png" });
  const f = join(OUT, `${name}.png`); writeFileSync(f, Buffer.from(png.data, "base64")); shots.push(f);
}

// CPU of the whole browser (all its processes) over a window, as % of one core
function tree(root) {
  const kids = {}; for (const p of readdirSync("/proc").filter((d) => /^\d+$/.test(d))) {
    try { const st = readFileSync(`/proc/${p}/stat`, "utf8"); const f = st.slice(st.lastIndexOf(")") + 2).split(" "); (kids[f[1]] ||= []).push(p); } catch (e) { /* gone */ }
  }
  const out = []; const q = [String(root)]; while (q.length) { const p = q.pop(); out.push(p); q.push(...(kids[p] || [])); } return out;
}
function ticks(pids) {
  let t = 0; for (const p of pids) { try { const st = readFileSync(`/proc/${p}/stat`, "utf8"); const f = st.slice(st.lastIndexOf(")") + 2).split(" "); t += Number(f[11]) + Number(f[12]); } catch (e) { /* gone */ } } return t;
}
async function cpu(seconds, moving) {
  const pids = tree(chrome.pid); const a = ticks(pids); const m0 = await cdp("Performance.getMetrics");
  const start = Date.now(); let i = 0;
  while (Date.now() - start < seconds * 1000) {
    if (moving) await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x: 600 + (i % 80) * 9, y: 400 + Math.sin(i / 6) * 120 });
    i++; await sleep(moving ? 50 : 500);
  }
  const b = ticks(pids); const m1 = await cdp("Performance.getMetrics");
  const task = (m) => (m.metrics || []).find((x) => x.name === "TaskDuration")?.value || 0;
  return { cpu_pct_one_core: +(((b - a) / 100) / seconds * 100).toFixed(2), main_thread_busy_pct: +(((task(m1) - task(m0)) / seconds) * 100).toFixed(2) };
}

const result = { shots, cost: {}, contrast: {} };
await cdp("Page.enable"); await cdp("Runtime.enable"); await cdp("Network.enable"); await cdp("Performance.enable");
try {
  // the wallet: first run, set the password
  await scheme("dark"); await size(1280, 900);
  await go(BASE + "/");
  await shot("setup-first-run-dark", 1280);
  await scheme("light"); await go(BASE + "/"); await shot("setup-first-run-light", 1280); await shot("setup-first-run-phone-light", 390);
  await set("[name=code]", CODE); await set("[name=password]", "look box password"); await set("[name=password2]", "look box password");
  await submitAndWait("document.querySelector('form').submit()");
  const pages = PAGES ? JSON.parse(PAGES) : [["setup", "/setup"], ["browse", "/browse"], ["player", PLAY], ["connections", "/connections"]];
  for (const [page, path] of pages) {
    for (const s of ["dark", "light"]) { await scheme(s); await go(BASE + path); await shot(`${page}-${s}`, 1280); await shot(`${page}-phone-${s}`, 390); }
  }
  // the phone's menu, opened
  await scheme("light"); await size(390, 844); await go(BASE + "/browse"); await ev("document.querySelector('.menu-toggle').click()"); await sleep(200);
  { const png = await cdp("Page.captureScreenshot", { format: "png" }); const f = join(OUT, "menu-phone-light.png"); writeFileSync(f, Buffer.from(png.data, "base64")); shots.push(f); }
  // the seller's side
  await scheme("dark"); await go(GW + "/");
  await set("[name=code]", GWCODE); await set("[name=password]", "look box password"); await set("[name=password2]", "look box password");
  await submitAndWait("document.querySelector('form').submit()");
  for (const s of ["dark", "light"]) { await scheme(s); await go(GW + "/"); await shot(`seller-app-${s}`, 1280); await shot(`seller-app-phone-${s}`, 390); }

  // contrast: text colours against the brightest point the river and the glow reach, anywhere.
  // The page's own canvas is read, so the river draws in the page here (its fallback when a
  // browser has no OffscreenCanvas): the same drawing code as in the worker.
  const inPage = await cdp("Page.addScriptToEvaluateOnNewDocument", { source: "HTMLCanvasElement.prototype.transferControlToOffscreen = undefined;" });
  for (const s of ["dark", "light"]) {
    await scheme(s); await size(1920, 1080); await go(BASE + "/browse"); await sweep(900, 500);
    result.contrast[s] = await ev(`(function(){
      function rgb(c){var d=document.createElement('div');d.style.color=c;document.body.appendChild(d);var m=getComputedStyle(d).color.match(/[\\d.]+/g).map(Number);d.remove();return m}
      function lum(c){var a=c.slice(0,3).map(function(v){v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4)});return 0.2126*a[0]+0.7152*a[1]+0.0722*a[2]}
      function ratio(a,b){var x=lum(a),y=lum(b);return (Math.max(x,y)+0.05)/(Math.min(x,y)+0.05)}
      var st=getComputedStyle(document.documentElement),v=function(k){return st.getPropertyValue(k).trim()};
      var cv=document.getElementById('river'),d=cv.getContext('2d').getImageData(0,0,cv.width,cv.height).data;
      // the ground under a glyph: the river over the page colour, averaged over 8x8 px blocks (a
      // letter's size), so a hairline spark doesn't count as the ground the text sits on
      var grounds=[rgb(v('--bg')),rgb(v('--bg-2'))],dark=lum(rgb(v('--fg')))>0.5,worst=null,wl=dark?-1:2,W=cv.width,B=8;
      for(var g=0;g<grounds.length;g++){var bg=grounds[g];
        for(var by=0;by+B<=cv.height;by+=B)for(var bx=0;bx+B<=W;bx+=B){var c=[0,0,0];
          for(var y=by;y<by+B;y++)for(var x=bx;x<bx+B;x++){var i=(y*W+x)*4,a=d[i+3]/255;c[0]+=d[i]*a+bg[0]*(1-a);c[1]+=d[i+1]*a+bg[1]*(1-a);c[2]+=d[i+2]*a+bg[2]*(1-a)}
          c=c.map(function(t){return t/(B*B)});var l=lum(c);if(dark?l>wl:l<wl){wl=l;worst=c}}}
      worst=worst||grounds[1];
      return {worst_ground:worst.map(Math.round),text:+ratio(rgb(v('--fg')),worst).toFixed(2),muted:+ratio(rgb(v('--muted')),worst).toFixed(2),
              text_on_card:+ratio(rgb(v('--fg')),grounds[1]).toFixed(2)};
    })()`);
  }

  await scheme("dark"); await go(BASE + "/browse"); await sleep(1000);
  const fallback = { still: await cpu(SECONDS, false), moving: await cpu(SECONDS, true) };
  await cdp("Page.removeScriptToEvaluateOnNewDocument", { identifier: inPage.identifier });

  // cost at 1080p, dark, on Browse: still pointer, then a moving pointer; with the river, then without
  await scheme("dark"); await size(1920, 1080);
  // two rounds, alternating, averaged: the machine's other load moves a single window by a few %
  const runs = { with_river: [], without_river: [] };
  for (const river of [false, true, false, true]) {
    await cdp("Network.setBlockedURLs", { urls: river ? [] : ["*river.js*"] });
    await cdp("Network.setCacheDisabled", { cacheDisabled: true });
    await go(BASE + "/browse"); await sleep(1000);
    const still = await cpu(SECONDS, false);
    const moving = await cpu(SECONDS, true);
    const frames = await ev("window.lsRiver ? {frames: lsRiver.stats.frames, avg_ms: +(lsRiver.stats.ms / Math.max(1, lsRiver.stats.frames)).toFixed(3), max_ms: +lsRiver.stats.max.toFixed(3)} : null");
    runs[river ? "with_river" : "without_river"].push({ still, moving, frames });
  }
  const mean = (xs, f) => +(xs.reduce((a, x) => a + f(x), 0) / xs.length).toFixed(2);
  for (const [k, xs] of Object.entries(runs)) {
    result.cost[k] = { still: { cpu_pct_one_core: mean(xs, (x) => x.still.cpu_pct_one_core), main_thread_busy_pct: mean(xs, (x) => x.still.main_thread_busy_pct) },
                       moving: { cpu_pct_one_core: mean(xs, (x) => x.moving.cpu_pct_one_core), main_thread_busy_pct: mean(xs, (x) => x.moving.main_thread_busy_pct) },
                       frames: xs[1].frames && { frames: xs[0].frames.frames + xs[1].frames.frames, avg_ms: mean(xs, (x) => x.frames.avg_ms),
                                                 max_ms: Math.max(xs[0].frames.max_ms, xs[1].frames.max_ms) }, runs: xs };
  }
  result.cost.with_river_in_page = fallback;
} finally {
  writeFileSync(join(OUT, "look.json"), JSON.stringify(result, null, 1));
  console.log("LOOK " + JSON.stringify(result));
  chrome.kill();
}
process.exit(0);
