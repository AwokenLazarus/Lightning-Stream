// The river's pointer effects sit on the streams: the brightening near the pointer is drawn along
// points of the streams' own curves, never as a shape of their own between them; a click's discharge
// (an arc, a jittered current and a few forks) stays close to them, and is gone within a second. river.js runs here as it does in its worker, drawing on a context that records each path.
//   node river_test.mjs RIVER_JS
// Prints "RIVER ok ..." or exits non-zero.
import { readFileSync } from "node:fs";
import vm from "node:vm";

const src = readFileSync(process.argv[2], "utf8");
const frames = [];
let cur = null, path = [];
const grad = (kind) => ({ kind, addColorStop() {} });
const ctx = {
  canvas: { width: 0, height: 0 },
  setTransform() {}, clearRect() { cur = { strokes: [], fills: 0 }; frames.push(cur); },
  beginPath() { path = []; }, moveTo(x, y) { path.push([x, y]); }, lineTo(x, y) { path.push([x, y]); },
  quadraticCurveTo(a, b, x, y) { path.push([a, b], [x, y]); },
  arc() {}, fill() { cur.fills++; }, fillRect() { cur.fills++; },
  stroke() { cur.strokes.push({ style: this.strokeStyle, pts: path.slice() }); },
  createLinearGradient: () => grad("linear"), createRadialGradient: () => grad("radial"),
};
const sandbox = { performance, setTimeout, clearTimeout, Math, Float32Array, postMessage() {}, onmessage: null, console };
sandbox.self = sandbox;
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const send = (m) => sandbox.onmessage({ data: m });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

send({ canvas: { getContext: () => ctx }, size: [1200, 800, 0.5], col: { a: "#38bdf8", b: "#a78bfa", spark: "#e0f2fe", glow: 0.05, core: 0.27, add: true },
       still: false, paused: false });
const fail = (why) => { console.log("RIVER FAIL " + why); process.exit(1); };
if (!frames.length) fail("no first frame before any timer ran");
// the pointer rests in the middle; streams near it brighten
for (let i = 0; i < 12; i++) { send({ p: [600 + i, 400] }); await sleep(40); }
// a click on the stream nearest the pointer sends a pulse along it
const last = frames[frames.length - 1];
const mains = last.strokes.filter((s) => typeof s.style === "string" && s.pts.length > 40);
const ys = mains.map((s) => s.pts);
let near = null, nd = 1e9;
for (const pts of ys) for (const [x, y] of pts) if (Math.abs(x - 600) < 13 && Math.abs(y - 400) < nd) { nd = Math.abs(y - 400); near = y; }
if (near === null) fail("no stream crosses the middle");
send({ p: [600, near + 3], tap: [600, near + 3] });
await sleep(300);

let bright = 0, pulse = 0;
// how far a point is from the nearest stream at its x
const off = (f, x, y) => {
  let d = 1e9;
  for (const s of f.strokes) if (typeof s.style === "string" && s.pts.length > 40)
    for (let i = 1; i < s.pts.length; i++) {
      const [x0, y0] = s.pts[i - 1], [x1, y1] = s.pts[i];
      if ((x0 - x) * (x1 - x) <= 0 && x0 !== x1) d = Math.min(d, Math.abs(y0 + (y1 - y0) * (x - x0) / (x1 - x0) - y));
    }
  return d;
};
for (const f of frames.slice(-4)) {
  const onStreams = new Set();
  for (const s of f.strokes) if (typeof s.style === "string" && s.pts.length > 40) for (const [x, y] of s.pts) onStreams.add(`${x},${y}`);
  for (const s of f.strokes) {
    const extra = (typeof s.style === "object" && s.style.kind === "linear") ? "bright" : (s.style === "#e0f2fe" ? "pulse" : null);
    if (!extra) continue;
    if (extra === "bright") {
      bright++;
      for (const [x, y] of s.pts) if (!onStreams.has(`${x},${y}`)) fail(`a bright point (${x}, ${y}) is off every stream`);
    } else {
      pulse++;
      for (const [x, y] of s.pts) if (x < -50 || x > 1250 || off(f, x, y) > 60) fail(`a discharge point (${x}, ${y}) strays from the streams`);
    }
  }
  if (f.strokes.some((s) => typeof s.style === "object" && s.style.kind === "radial")) fail("a radial gradient was stroked");
}
// and a second later it has faded out
await sleep(1100);
send({ p: [600, near + 3] }); await sleep(80);
if (frames[frames.length - 1].strokes.some((s) => s.style === "#e0f2fe")) fail("the discharge was still drawn a second later");
if (!bright) fail("nothing brightened near the pointer");
if (!pulse) fail("a click sent no pulse");
console.log(`RIVER ok: ${frames.length} frames, ${bright} brightened and ${pulse} discharge strokes, all near the streams`);
process.exit(0);
