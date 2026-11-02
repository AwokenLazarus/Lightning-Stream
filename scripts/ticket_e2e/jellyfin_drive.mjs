// Drive the real Jellyfin web client through a Lightning Stream visit in headless Chrome: log in, open
// the home page, play ITEM_ID for a minute, seek to 300 s. Screenshots and log.json go to OUT_DIR.
//   node jellyfin_drive.mjs ENTER_URL ITEM_ID OUT_DIR
// JF_TAP_USER: the user to tap on the login page, a regular expression (a shop with buyers' own
// accounts shows one, `buyer-…`); else the guest is typed in with JF_GUEST_USER and JF_GUEST_PW.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path";
const [ENTER, ITEM, OUT] = process.argv.slice(2); mkdirSync(OUT, { recursive: true });
const PW = process.env.JF_GUEST_PW || ""; const GUEST = process.env.JF_GUEST_USER || "stream-guest";
const TAP = process.env.JF_TAP_USER ? new RegExp(process.env.JF_TAP_USER) : null; const res = {};
const profile = mkdtempSync(join(tmpdir(), "jfdrive-"));
const chrome = spawn("google-chrome", ["--headless=new", "--no-first-run", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
  "--autoplay-policy=no-user-gesture-required", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--window-size=1280,800", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let port; for (let i = 0; i < 300 && !port; i++) { await sleep(100); const f = join(profile, "DevToolsActivePort"); if (existsSync(f)) port = readFileSync(f, "utf8").split("\n")[0]; }
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl); await new Promise((r) => ws.addEventListener("open", r));
let seq = 0; const pend = new Map(); const log = { failed: [], http_errors: [], console: [], ws: [], requests: 0, bytes: 0 };
const t0 = Date.now(); const ts = () => ((Date.now() - t0) / 1000).toFixed(1);
ws.addEventListener("message", (m) => { const d = JSON.parse(m.data);
  if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); return; }
  const p = d.params || {};
  if (d.method === "Network.requestWillBeSent") log.requests++;
  if (d.method === "Network.loadingFailed" && !p.canceled) log.failed.push(`${ts()} ${p.errorText} ${p.type} ${(reqs.get(p.requestId) || "").slice(0, 160)}`);
  if (d.method === "Network.requestWillBeSent") reqs.set(p.requestId, `${p.request.method} ${p.request.url}`);
  if (d.method === "Network.responseReceived" && p.response.status >= 400) log.http_errors.push(`${ts()} ${p.response.status} ${(reqs.get(p.requestId) || p.response.url).slice(0, 160)}`);
  if (d.method === "Network.dataReceived") log.bytes += p.dataLength;
  if (d.method === "Network.webSocketCreated") log.ws.push(`${ts()} created ${p.url.slice(0, 120)}`);
  if (d.method === "Network.webSocketHandshakeResponseReceived") log.ws.push(`${ts()} handshake ${p.response.status}`);
  if (d.method === "Network.webSocketClosed") log.ws.push(`${ts()} closed`);
  if (d.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(p.type)) log.console.push(`${ts()} ${p.type} ${p.args.map((a) => a.value ?? a.description ?? "").join(" ").slice(0, 200)}`);
  if (d.method === "Runtime.exceptionThrown") log.console.push(`${ts()} exception ${(p.exceptionDetails.exception?.description || p.exceptionDetails.text || "").slice(0, 200)}`);
});
const reqs = new Map();
const cdp = (method, params = {}) => new Promise((r) => { const id = ++seq; pend.set(id, (d) => r(d.result || { error: d.error })); ws.send(JSON.stringify({ id, method, params })); });
const ev = async (expr) => { const r = await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }); return r.result?.value ?? (r.exceptionDetails ? "EXC " + JSON.stringify(r.exceptionDetails).slice(0, 200) : undefined); };
const shot = async (name) => { const r = await cdp("Page.captureScreenshot", { format: "png" }); if (r.data) writeFileSync(join(OUT, name + ".png"), Buffer.from(r.data, "base64")); };
const waitFor = async (expr, ms) => { for (let t = 0; t < ms; t += 500) { if (await ev(expr)) return true; await sleep(500); } return false; };
await cdp("Network.enable"); await cdp("Page.enable"); await cdp("Runtime.enable");
const step = (s) => console.log(`${ts()}s ${s}`);
step("open the visit"); await cdp("Page.navigate", { url: ENTER });
await waitFor("document.readyState==='complete' && location.pathname.startsWith('/web')", 30000);
await sleep(6000); await shot("01-first-page");
step(`page: ${await ev("location.href")} title=${await ev("document.title")}`);
// over a slow link the web client takes a while to load all its parts: a viewer waits for the login page
const loginForm = await waitFor("!!document.querySelector('#txtManualName, .manualLoginForm, input[type=password]')", Number(process.env.JF_LOGIN_WAIT_MS || 90000));
step(`login form shown: ${loginForm}`);
if (loginForm && TAP) {
  // the login page lists the users once it has asked the server for them: on a slow link, seconds after the form
  const listed = await waitFor(`[...document.querySelectorAll('[data-username], .cardBox, button')].some(x=>new RegExp(${JSON.stringify(TAP.source)}).test(x.textContent)||new RegExp(${JSON.stringify(TAP.source)}).test(x.getAttribute('data-username')||''))`, 20000);
  step(`buyer listed: ${listed}`);
  const tapped = await ev(`(()=>{const c=[...document.querySelectorAll('[data-username], .cardBox, button')].find(x=>new RegExp(${JSON.stringify(TAP.source)}).test(x.textContent)||new RegExp(${JSON.stringify(TAP.source)}).test(x.getAttribute('data-username')||'')); if(c){c.click(); return c.tagName+' '+(c.className||'')} return false})()`);
  step(`tapped guest: ${tapped}`); await sleep(4000);
  const pwShown = await ev("!!document.querySelector('#txtManualPassword') && document.querySelector('.manualLoginForm:not(.hide)')!==null");
  step(`password form after tap: ${pwShown}`);
  if (pwShown) { await ev(`(()=>{const f=document.querySelector('form.manualLoginForm'); const b=f&&f.querySelector('button[type=submit]'); if(b){b.click(); return true} return false})()`); await sleep(5000); }
} else if (loginForm) {
  await ev(`(()=>{const b=[...document.querySelectorAll('button')].find(x=>/manual/i.test(x.textContent)); if(b) b.click(); return !!b})()`);
  await sleep(1000);
  const set = (sel, v) => `(()=>{const e=document.querySelector('${sel}'); if(!e) return false; e.value=${JSON.stringify(v)}; e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true})); return true})()`;
  step(`name field: ${await ev(set('#txtManualName', GUEST))}`);
  await ev(set('#txtManualPassword', PW));
  await ev(`(()=>{const f=document.querySelector('form.manualLoginForm'); const b=f&&f.querySelector('button[type=submit]'); if(b){b.click(); return true} return false})()`);
  await sleep(6000);
}
// signed in once the web client has a user: over a slow link, seconds after the tap or the submit
const signedIn = await waitFor("(()=>{try{return !!(window.ApiClient && window.ApiClient.getCurrentUserId())}catch(e){return false}})()", Number(process.env.JF_LOGIN_WAIT_MS || 90000));
step(`signed in: ${signedIn}`);
await shot("02-after-login");
res.after_login = await ev("location.href"); step(`after login: ${res.after_login}`);
const home = await waitFor("!!document.querySelector('.card, .itemsContainer .card')", 20000);
res.home = home; step(`home shows cards: ${home}`); await shot("03-home");
// Each run starts the film from the beginning: an earlier run with the same buyer's account left a
// resume point (or a "watched" mark), and Play would resume there, near the end of a short clip.
res.reset_progress = await ev(`(async()=>{try{const a=window.ApiClient; await a.markUnplayed(a.getCurrentUserId(), '${ITEM}'); return true}catch(e){return String(e)}})()`);
step(`progress reset: ${res.reset_progress}`);
step("open the 4K film"); await ev(`location.hash = '#/details?id=${ITEM}'`);
// the details page fills in once its item has arrived: over a slow link, seconds after it opens. A viewer waits for its
// title and play button, not a fixed time
const shown = await waitFor(`(()=>{const pg=[...document.querySelectorAll('.itemDetailPage')].find(p=>!p.classList.contains('hide')&&p.offsetParent!==null); return !!(pg && pg.querySelector('.mainDetailButtons .btnPlay:not(.hide), .mainDetailButtons button[data-action=resume]:not(.hide)') && pg.querySelector('.itemName, h1, h3.itemName'))})()`, Number(process.env.JF_PAGE_WAIT_MS || 60000));
step(`details shown: ${shown}`); await sleep(1000); await shot("04-details");
// The play button of the details page on show: Jellyfin keeps earlier pages (home, with its
// "Continue watching" cards) in the document, hidden, so the first .btnPlay may be another film's.
const play = await ev(`(()=>{const pg=[...document.querySelectorAll('.itemDetailPage')].find(p=>!p.classList.contains('hide')&&p.offsetParent!==null); const b=pg&&pg.querySelector('.mainDetailButtons .btnPlay, .mainDetailButtons button[data-action=resume], .mainDetailButtons button[data-action=play]'); if(b){b.click(); return true} return false})()`);
step(`play pressed: ${play}`);
const t1 = Date.now();
const started = await waitFor("(()=>{const v=document.querySelector('video'); return !!(v && v.currentTime>0.5)})()", 60000);
const startup = ((Date.now() - t1) / 1000).toFixed(1); res.started = started;
res.playing_item = await ev(`(()=>{const v=document.querySelector('video'); const m=v&&/[/]videos[/]([0-9a-f-]+)[/]/i.exec(v.currentSrc||v.src||''); return m?m[1].replace(/-/g,''):null})()`);
res.played_requested = res.playing_item === ITEM.replace(/-/g, ""); step(`playing ${res.playing_item}, the requested film: ${res.played_requested}`); step(`playback started: ${started} after ${startup}s`);
await ev(`(()=>{const v=document.querySelector('video'); if(!v) return; window.__stalls=0; window.__waitT=0; let w=0; v.addEventListener('waiting',()=>{window.__stalls++; w=performance.now()}); v.addEventListener('playing',()=>{ if(w){window.__waitT+=performance.now()-w; w=0} });})()`);
const samples = []; for (let i = 0; i < 12; i++) { await sleep(5000);
  samples.push(await ev(`(()=>{const v=document.querySelector('video'); if(!v) return null; const q=v.getVideoPlaybackQuality? v.getVideoPlaybackQuality():{}; return {t:+v.currentTime.toFixed(1), w:v.videoWidth, h:v.videoHeight, rs:v.readyState, dropped:q.droppedVideoFrames, total:q.totalVideoFrames, stalls:window.__stalls, waitMs:Math.round(window.__waitT), src:(v.currentSrc||'').slice(0,140)}})()`)); }
await shot("05-playing");
step(`samples: ${JSON.stringify(samples)}`);
step("seek to 300 s"); const t2 = Date.now();
await ev(`(()=>{const v=document.querySelector('video'); if(v) v.currentTime=300})()`);
const resumed = await waitFor("(()=>{const v=document.querySelector('video'); return !!(v && v.currentTime>300.5 && !v.paused)})()", 60000);
res.seek_resumed = resumed; res.seek_s = +((Date.now() - t2) / 1000).toFixed(1); step(`seek resumed: ${resumed} after ${((Date.now() - t2) / 1000).toFixed(1)}s`);
await sleep(10000); await shot("06-after-seek");
res.after_seek = await ev(`(()=>{const v=document.querySelector('video'); return v?{t:+v.currentTime.toFixed(1), stalls:window.__stalls, waitMs:Math.round(window.__waitT)}:null})()`);
step(`after seek: ${JSON.stringify(await ev(`(()=>{const v=document.querySelector('video'); return v?{t:+v.currentTime.toFixed(1), stalls:window.__stalls, waitMs:Math.round(window.__waitT)}:null})()`))}`);
// the film left as a viewer leaves it: the player reports where it stopped, and Jellyfin keeps that position now,
// not when it gives up on a browser that went away (by then the next run may have started)
await ev("(()=>{const v=document.querySelector('video'); if(v) v.pause(); history.back(); return true})()"); await sleep(4000);
step("left the player");
writeFileSync(join(OUT, "log.json"), JSON.stringify({ startup_s: startup, samples, ...res, ...log }, null, 1));
console.log(`requests=${log.requests} bytes=${log.bytes} failed=${log.failed.length} http_errors=${log.http_errors.length} console=${log.console.length} ws=${log.ws.length}`);
chrome.kill("SIGKILL"); process.exit(0);
