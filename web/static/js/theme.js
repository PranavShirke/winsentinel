/**
 * WinSentinel - early theme loader.
 * Runs in <head> (before first paint) so the saved light/dark theme never flashes.
 */
(function () {
  try {
    var saved = localStorage.getItem("ws-theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  } catch (e) {
    /* storage blocked: stay on the default dark theme */
  }
})();
