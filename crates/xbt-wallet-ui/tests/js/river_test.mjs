// The river's pointer effects sit on the streams: the brightening near the pointer and a click's
// pulse are drawn along points of the streams' own curves, never as a shape of their own between
// them. river.js runs here as it does in its worker, drawing on a context that records each path.
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
for (const f of frames.slice(-4)) {
  const onStreams = new Set();
  for (const s of f.strokes) if (typeof s.style === "string" && s.pts.length > 40) for (const [x, y] of s.pts) onStreams.add(`${x},${y}`);
  for (const s of f.strokes) {
    const extra = (typeof s.style === "object" && s.style.kind === "linear") ? "bright" : (s.style === "#e0f2fe" ? "pulse" : null);
    if (!extra) continue;
    if (extra === "bright") bright++; else pulse++;
    for (const [x, y] of s.pts) if (!onStreams.has(`${x},${y}`)) fail(`a ${extra} point (${x}, ${y}) is off every stream`);
  }
  if (f.strokes.some((s) => typeof s.style === "object" && s.style.kind === "radial")) fail("a radial gradient was stroked");
}
if (!bright) fail("nothing brightened near the pointer");
if (!pulse) fail("a click sent no pulse");
console.log(`RIVER ok: ${frames.length} frames, ${bright} brightened and ${pulse} pulse strokes, every point on a stream`);
process.exit(0);
