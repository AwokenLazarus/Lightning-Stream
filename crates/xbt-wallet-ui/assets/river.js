// Lightning Stream: the river behind every page. The pointer bends nearby streams; near two, an
// arc joins them like a channel opening; lsRiver.pulse() runs a pulse down one. Drawn in a worker
// on an OffscreenCanvas where the browser has one (the page's thread only forwards the pointer),
// else in the page. 30 fps while the pointer moves, 6 at rest, none while hidden or a video
// plays; half resolution; one still frame for reduced motion. Colours: --river-* in ui.css.
(function () {
  "use strict";
  var STEP = 24, REACH = 150, FAST = 1000 / 30, SLOW = 1000 / 6, IDLE = 8000;

  // the drawing, the same in a worker and in the page; told everything by messages
  function engine(cx, report) {
    var W = 0, H = 0, streams = [], arcs = [], pulses = [], col = {}, still = false, paused = false;
    var px = -1e4, py = -1e4, pull = 0, moved = -1e9, last = 0, raf = 0, nap = 0, nextArc = 0;
    var stats = { frames: 0, ms: 0, max: 0 }, seed = 0;
    var tick = self.requestAnimationFrame ? requestAnimationFrame.bind(self) : function (f) { return setTimeout(function () { f(performance.now()); }, 16); };
    function rnd() {
      seed = (seed + 0x6d2b79f5) | 0;
      var t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
    }
    function build() {
      seed = 0x5eed1e55; // the same streams on every page
      var n = Math.max(3, Math.min(7, Math.round(W * H / 280000) + 2)), k2 = Math.PI * 2 / 900;
      streams = [];
      for (var i = 0; i < n; i++) {
        streams.push({ base: (i + 0.5 + (rnd() - 0.5) * 0.6) / n, tilt: (rnd() - 0.5) * 0.35,
          a1: 18 + rnd() * 34, k1: (0.6 + rnd() * 1.2) * k2, w1: 0.05 + rnd() * 0.08, p1: rnd() * 6.28,
          a2: 6 + rnd() * 14, k2: (1.5 + rnd() * 2.5) * k2, w2: 0.08 + rnd() * 0.1, p2: rnd() * 6.28,
          hue: i % 2 ? "b" : "a", width: 0.8 + rnd() * 0.9, sparks: [rnd(), rnd(), rnd()], speed: 0.004 + rnd() * 0.006, ys: null });
      }
    }
    function shape(t) {
      var cols = Math.ceil(W / STEP) + 1, r2 = REACH * REACH;
      streams.forEach(function (s) {
        if (!s.ys || s.ys.length !== cols) s.ys = new Float32Array(cols);
        for (var c = 0; c < cols; c++) {
          var x = c * STEP, y = (s.base + s.tilt * (x / W - 0.5)) * H + s.a1 * Math.sin(s.k1 * x + s.w1 * t + s.p1) + s.a2 * Math.sin(s.k2 * x - s.w2 * t + s.p2);
          var dx = x - px, dy = y - py, d2 = dx * dx + dy * dy;
          if (pull > 0.01 && d2 < r2 * 4) y -= dy * 0.45 * pull * Math.exp(-d2 / r2);
          s.ys[c] = y;
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
    // an arc across the streams either side of the pointer
    function link(now) {
      if (pull < 0.5 || now < nextArc || px < 0 || px > W || !streams.length || !streams[0].ys) return;
      var c = Math.round(px / STEP), up = null, down = null;
      streams.forEach(function (s) {
        var y = s.ys[Math.min(c, s.ys.length - 1)];
        if (y <= py && (up === null || y > up)) up = y;
        if (y > py && (down === null || y < down)) down = y;
      });
      if (up === null || down === null || down - up > REACH * 1.6) return;
      var pts = [], x2 = px + (rnd() - 0.5) * 40;
      for (var k = 0; k <= 7; k++) pts.push([px + (x2 - px) * k / 7 + (k % 7 ? (rnd() - 0.5) * 18 : 0), up + (down - up) * k / 7]);
      arcs.push({ pts: pts, born: now });
      nextArc = now + 160;
    }
    function draw(t, now) {
      cx.clearRect(0, 0, W, H);
      cx.globalCompositeOperation = col.add ? "lighter" : "source-over";
      cx.lineCap = cx.lineJoin = "round";
      shape(t);
      var end = streams.length && streams[0].ys.length - 1;
      streams.forEach(function (s) {
        cx.strokeStyle = col[s.hue];
        line(s, 0, end);
        stroke(col.glow, 9 * s.width);
        stroke(col.core, 2 * s.width);
        cx.fillStyle = col.spark; cx.globalAlpha = col.core * 1.6;
        s.sparks.forEach(function (u) {
          var f = ((u + t * s.speed) % 1) * end, c = Math.floor(f), n = s.ys[Math.min(c + 1, end)];
          cx.beginPath(); cx.arc(f * STEP, s.ys[c] + (n - s.ys[c]) * (f - c), 1.6, 0, 7); cx.fill();
        });
      });
      if (now === undefined) return;
      cx.strokeStyle = col.arc;
      arcs = arcs.filter(function (a) { return now - a.born < 420; });
      arcs.forEach(function (a) {
        var life = 1 - (now - a.born) / 420;
        cx.beginPath(); cx.moveTo(a.pts[0][0], a.pts[0][1]);
        for (var q = 1; q < a.pts.length; q++) cx.lineTo(a.pts[q][0], a.pts[q][1]);
        stroke(0.12 * life, 6); stroke(0.6 * life, 1.6);
      });
      cx.strokeStyle = col.spark;
      pulses = pulses.filter(function (p) { return now - p.born < 1400; });
      pulses.forEach(function (p) {
        var u = (now - p.born) / 1400, mid = Math.round(u * end), from = Math.max(0, mid - 4), to = Math.min(end, mid + 4);
        if (to <= from) return;
        line(streams[p.s % streams.length], from, to);
        stroke(0.2 - u * 0.1, 10); stroke(0.9 - u * 0.45, 2);
      });
    }
    function frame(now) {
      raf = 0;
      if (still || paused) return;
      var busy = now - moved < IDLE || pulses.length || arcs.length, t0 = performance.now(), ms;
      if (now - last >= FAST - 1) {
        last = now;
        pull += ((now - moved < 1500 ? 1 : 0) - pull) * 0.12;
        link(now);
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
      if (m.pulse !== undefined) pulses.push({ s: m.pulse, born: performance.now() });
      if (still && W) draw(Date.now() / 1000);
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
    return { a: v("a"), b: v("b"), spark: v("spark"), arc: v("arc"), glow: +v("glow") || 0.05, core: +v("core") || 0.3, add: v("blend") === "lighter" };
  }
  function playing() { var v = document.querySelector("video"); return !!v && !v.paused && !v.ended; }
  function state() { return { size: [innerWidth, innerHeight, Math.min(devicePixelRatio || 1, 1.5) / 2], col: colours(), still: reduce.matches, paused: document.hidden || playing() }; }
  try {
    var w = new Worker(document.currentScript.src), off = cv.transferControlToOffscreen();
    w.onmessage = function (e) { Object.assign(stats, e.data); };
    var first = state(); first.canvas = off;
    w.postMessage(first, [off]);
    send = w.postMessage.bind(w);
  } catch (e) {
    send = engine(cv.getContext("2d"), function (s) { Object.assign(stats, s); });
    send(state());
  }
  function point(e) { send({ p: [e.clientX, e.clientY] }); }
  function update() { send({ paused: document.hidden || playing() }); }
  addEventListener("pointermove", point, { passive: true });
  addEventListener("pointerdown", point, { passive: true });
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
