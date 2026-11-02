// The pages slide into each other with the browser's view transitions (ui.css). A transition the
// browser skips (the window was resized, or the next page was asked for, before it ended) rejects
// its promises; that is no fault of the page, so it is not reported as one. Loaded in the head:
// the new page's pagereveal comes before its first frame.
// It also sets the owner's theme before that first frame: dark unless this browser was told light
// (the bar's theme button, ui.js), so a light page never opens dark for a moment.
"use strict";
try { if (localStorage.getItem("ls-theme") === "light") document.documentElement.setAttribute("data-theme", "light"); } catch (e) { /* no storage: dark */ }
for (const name of ["pageswap", "pagereveal"]) {
  window.addEventListener(name, (e) => {
    const t = e.viewTransition;
    if (t) for (const p of [t.ready, t.finished, t.updateCallbackDone]) if (p) p.catch(() => {});
  });
}
