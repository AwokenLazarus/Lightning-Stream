// The pages slide into each other with the browser's view transitions (ui.css). A transition the
// browser skips (the window was resized, or the next page was asked for, before it ended) rejects
// its promises; that is no fault of the page, so it is not reported as one. Loaded in the head:
// the new page's pagereveal comes before its first frame.
"use strict";
for (const name of ["pageswap", "pagereveal"]) {
  window.addEventListener(name, (e) => {
    const t = e.viewTransition;
    if (t) for (const p of [t.ready, t.finished, t.updateCallbackDone]) if (p) p.catch(() => {});
  });
}
