// Lightning Stream: the river behind every page. Near the pointer the streams brighten a little and
// ease away from it, and a soft glow follows it; a click sends one pulse along the nearest stream;
// lsRiver.pulse() runs one down a whole stream. Everything is drawn on the streams' own curve, so
// it always sits on them. Drawn in a worker on an OffscreenCanvas where the browser has one (the
// page's thread only forwards the pointer), else in the page. 30 fps while something moves, 6 at
// rest, none while hidden or a video plays; half resolution; one still frame for reduced motion.
// The streams' shape is a function of the clock, so every page shows the same frame at the same
// moment: a new page starts where the last one left off, with a first frame drawn before it shows.
// Colours: --river-* in ui.css.
(function () {
  "use strict";
  var STEP = 24, REACH = 140, FAST = 1000 / 30, SLOW = 1000 / 6, IDLE = 8000, SPEED = 0.035;

  // the drawing, the same in a worker and in the page; told everything by messages
  function engine(cx, report) {
    var W = 0, H = 0, streams = [], pulses = [], col = {}, still = false, paused = false, first = true;
    var px = -1e4, py = -1e4, gx = -1e4, gy = -1e4, pull = 0, moved = -1e9, last = 0, raf = 0, nap = 0;
    var stats = { frames: 0, ms: 0, max: 0 }, seed = 0;
    var tick = self.requestAnimationFrame ? requestAnimationFrame.bind(self) : function (f) { return setTimeout(function () { f(performance.now()); }, 16); };
    function rnd() {
      seed = (seed + 0x6d2b79f5) | 0;
      var t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
    }
    function rgba(hex, a) {
      var n = parseInt(hex.slice(1), 16); // #rrggbb, as the stylesheet gives them
      return "rgba(" + (n >> 16 & 255) + "," + (n >> 8 & 255) + "," + (n & 255) + "," + a + ")";
    }
    function build() {
      seed = 0x5eed1e55; // the same streams on every page
      var n = Math.max(3, Math.min(7, Math.round(W * H / 280000) + 2)), k2 = Math.PI * 2 / 900;
      streams = [];
      for (var i = 0; i < n; i++) {
        streams.push({ base: (i + 0.5 + (rnd() - 0.5) * 0.6) / n, tilt: (rnd() - 0.5) * 0.35,
          a1: 18 + rnd() * 34, k1: (0.6 + rnd() * 1.2) * k2, w1: 0.05 + rnd() * 0.08, p1: rnd() * 6.28,
          a2: 6 + rnd() * 14, k2: (1.5 + rnd() * 2.5) * k2, w2: 0.08 + rnd() * 0.1, p2: rnd() * 6.28,
          hue: i % 2 ? "b" : "a", width: 0.8 + rnd() * 0.9, sparks: [rnd(), rnd(), rnd()], speed: 0.004 + rnd() * 0.006, ys: null, near: 0 });
      }
    }
    function at(s, x, t) {
      return (s.base + s.tilt * (x / W - 0.5)) * H + s.a1 * Math.sin(s.k1 * x + s.w1 * t + s.p1) + s.a2 * Math.sin(s.k2 * x - s.w2 * t + s.p2);
    }
    // each stream as a row of points; near the pointer it eases away from it in one smooth bump, as
    // a whole, so it never tears, and the nearer it passes the more it brightens (s.near)
    function shape(t) {
      var cols = Math.ceil(W / STEP) + 1, r2 = REACH * REACH;
      streams.forEach(function (s) {
        if (!s.ys || s.ys.length !== cols) s.ys = new Float32Array(cols);
        var off = at(s, px, t) - py, amp = 0;
        s.near = pull > 0.01 ? pull * Math.exp(-off * off / r2) : 0;
        if (s.near > 0.01) amp = 30 * pull * Math.tanh(off / 28) * Math.exp(-off * off / (r2 * 1.6));
        for (var c = 0; c < cols; c++) {
          var x = c * STEP, dx = x - px;
          s.ys[c] = at(s, x, t) + (amp ? amp * Math.exp(-dx * dx / (r2 * 1.4)) : 0);
        }
      });
    }
    function line(s, from, to) {
      cx.beginPath();
      cx.moveTo(from * STEP, s.ys[from]);
      for (var c = from + 1; c <= to; c++) cx.quadraticCurveTo((c - 1) * STEP, s.ys[c - 1], (c - 0.5) * STEP, (s.ys[c - 1] + s.ys[c]) / 2);
      cx.lineTo(to * STEP, s.ys[to]);
    }
    function stroke(a, w) { cx.globalAlpha = a; cx.lineWidth = w; cx.stroke(); }
    function draw(t, now) {
      cx.clearRect(0, 0, W, H);
      cx.lineCap = cx.lineJoin = "round";
      shape(t);
      var end = streams.length && streams[0].ys.length - 1, R = REACH * 1.3;
      // the glow that follows the pointer, a little behind it
      if (pull > 0.01 && gx > -1e3) {
        var g = cx.createRadialGradient(gx, gy, 0, gx, gy, R * 1.2);
        g.addColorStop(0, rgba(col.a, col.glow * 2.4 * pull)); g.addColorStop(1, rgba(col.a, 0));
        cx.globalCompositeOperation = "source-over"; cx.globalAlpha = 1; cx.fillStyle = g;
        cx.fillRect(gx - R * 1.2, gy - R * 1.2, R * 2.4, R * 2.4);
      }
      cx.globalCompositeOperation = col.add ? "lighter" : "source-over";
      var c0 = Math.max(0, Math.floor((px - R) / STEP)), c1 = Math.min(end, Math.ceil((px + R) / STEP));
      streams.forEach(function (s) {
        cx.strokeStyle = col[s.hue];
        line(s, 0, end);
        stroke(col.glow, 9 * s.width);
        stroke(col.core, 2 * s.width);
        // brighter where it passes the pointer, fading out either side, on its own curve
        if (s.near > 0.02 && c1 > c0) {
          var b = cx.createLinearGradient(px - R, 0, px + R, 0);
          [0, 1, 0].forEach(function (a, i) { b.addColorStop(i / 2, rgba(col[s.hue], a)); });
          cx.strokeStyle = b;
          line(s, c0, c1);
          stroke(col.glow * 1.6 * s.near, 10 * s.width);
          stroke(col.core * 1.3 * s.near, 2.2 * s.width);
        }
        cx.fillStyle = col.spark; cx.globalAlpha = col.core * 1.6;
        s.sparks.forEach(function (u) {
          var f = ((u + t * s.speed) % 1) * end, c = Math.floor(f), n = s.ys[Math.min(c + 1, end)];
          cx.beginPath(); cx.arc(f * STEP, s.ys[c] + (n - s.ys[c]) * (f - c), 1.6, 0, 7); cx.fill();
        });
      });
      if (now === undefined) return;
      // pulses: a short bright stretch travelling along a stream from where it started
      cx.strokeStyle = col.spark;
      pulses = pulses.filter(function (p) { return p.c0 + (now - p.born) * SPEED < end + 4; });
      pulses.forEach(function (p) {
        var s = streams[p.s % streams.length], mid = Math.round(p.c0 + (now - p.born) * SPEED), u = (mid - p.c0) / Math.max(1, end - p.c0);
        var from = Math.max(0, mid - 4), to = Math.min(end, mid + 4);
        if (to <= from) return;
        line(s, from, to);
        stroke(0.18 * (1 - u * 0.6), 9); stroke(0.85 * (1 - u * 0.6), 1.8);
      });
    }
    function frame(now) {
      raf = 0;
      if (still || paused) return;
      var busy = now - moved < IDLE || pulses.length || pull > 0.01, t0 = performance.now(), ms;
      if (now - last >= FAST - 1) {
        last = now;
        // ease in while the pointer moves, out when it rests; the glow trails the pointer
        pull += ((now - moved < 1500 ? 1 : 0) - pull) * 0.08;
        if (pull < 0.005) pull = 0;
        if (gx < -1e3) { gx = px; gy = py; }
        gx += (px - gx) * 0.12; gy += (py - gy) * 0.12;
        draw(Date.now() / 1000, now);
        ms = performance.now() - t0;
        stats.frames++; stats.ms += ms; if (ms > stats.max) stats.max = ms;
        if (stats.frames % 30 === 0) report(stats);
      }
      // at rest, sleep between frames rather than wake every refresh
      if (busy) raf = tick(frame);
      else nap = setTimeout(function () { nap = 0; wake(); }, SLOW);
    }
    function wake() {
      if (nap) nap = clearTimeout(nap) || 0;
      if (!raf && !still && !paused) raf = tick(frame);
    }
    // the stream nearest a point, and the column there
    function tap(x, y) {
      var c = Math.max(0, Math.round(x / STEP)), best = -1, bd = REACH * 1.5;
      if (!streams.length || !streams[0].ys) return;
      c = Math.min(c, streams[0].ys.length - 1);
      streams.forEach(function (s, i) { var d = Math.abs(s.ys[c] - y); if (d < bd) { bd = d; best = i; } });
      if (best >= 0) pulses.push({ s: best, c0: c, born: performance.now() });
    }
    return function (m) {
      if (m.col) col = m.col;
      if ("still" in m) still = m.still;
      if ("paused" in m) paused = m.paused;
      if (m.size) {
        W = m.size[0]; H = m.size[1];
        cx.canvas.width = Math.round(W * m.size[2]); cx.canvas.height = Math.round(H * m.size[2]);
        cx.setTransform(m.size[2], 0, 0, m.size[2], 0, 0);
        build();
      }
      if (m.p) { px = m.p[0]; py = m.p[1]; moved = performance.now(); }
      if (m.gone) moved = -1e9;
      if (m.tap && !still) tap(m.tap[0], m.tap[1]);
      if (m.pulse !== undefined) pulses.push({ s: m.pulse, c0: 0, born: performance.now() });
      // a frame at once on a new size (the first one too): never a blank canvas while waiting
      if (W && (m.size || still)) draw(Date.now() / 1000);
      if (first && W) { first = false; report({ drawn: 1 }); }
      wake();
    };
  }

  if (typeof document === "undefined") { // in the worker
    var run;
    onmessage = function (e) {
      if (e.data.canvas) run = engine(e.data.canvas.getContext("2d"), function (s) { postMessage(s); });
      if (run) run(e.data);
    };
    return;
  }

  var cv = document.getElementById("river");
  if (!cv || !cv.getContext) return;
  var reduce = matchMedia("(prefers-reduced-motion: reduce)"), stats = {}, send;
  function colours() {
    var s = getComputedStyle(document.documentElement);
    function v(k) { return s.getPropertyValue("--river-" + k).trim(); }
    return { a: v("a"), b: v("b"), spark: v("spark"), glow: +v("glow") || 0.05, core: +v("core") || 0.3, add: v("blend") === "lighter" };
  }
  function playing() { var v = document.querySelector("video"); return !!v && !v.paused && !v.ended; }
  function state() { return { size: [innerWidth, innerHeight, Math.min(devicePixelRatio || 1, 1.5) / 2], col: colours(), still: reduce.matches, paused: document.hidden || playing() }; }
  try {
    var w = new Worker(document.currentScript.src), off = cv.transferControlToOffscreen();
    // the first frame, drawn here at once on a canvas of its own, so the page never shows without
    // the river while the worker starts; the worker's first frame replaces it
    var pre = document.createElement("canvas");
    pre.id = "river0"; pre.setAttribute("aria-hidden", "true");
    cv.parentNode.insertBefore(pre, cv);
    var s0 = state(); s0.still = true;
    engine(pre.getContext("2d"), function () {})(s0);
    w.onmessage = function (e) { if (e.data.drawn) { if (pre) { pre.remove(); pre = null; } } else Object.assign(stats, e.data); };
    var first = state(); first.canvas = off;
    w.postMessage(first, [off]);
    send = w.postMessage.bind(w);
  } catch (e) {
    send = engine(cv.getContext("2d"), function (s) { if (!s.drawn) Object.assign(stats, s); });
    send(state());
  }
  function point(e) { send({ p: [e.clientX, e.clientY] }); }
  function update() { send({ paused: document.hidden || playing() }); }
  addEventListener("pointermove", point, { passive: true });
  addEventListener("pointerdown", function (e) { send({ p: [e.clientX, e.clientY], tap: [e.clientX, e.clientY] }); }, { passive: true });
  document.addEventListener("pointerleave", function () { send({ gone: 1 }); });
  addEventListener("blur", function () { send({ gone: 1 }); });
  document.addEventListener("visibilitychange", update);
  ["play", "pause", "ended"].forEach(function (t) { document.addEventListener(t, update, true); });
  var later = 0;
  addEventListener("resize", function () { clearTimeout(later); later = setTimeout(function () { send(state()); }, 150); });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () { send({ col: colours() }); });
  reduce.addEventListener("change", function () { send({ still: reduce.matches }); });
  window.lsRiver = { pulse: function (s) { if (!reduce.matches) send({ pulse: s === undefined ? (Math.random() * 97) | 0 : s }); }, stats: stats };
})();
