/**
 * WinSentinel - Console client script.
 *
 * Strict-CSP friendly: no inline scripts or styles in templates. Chart data comes from
 * GET /api/summary, scan progress from GET /scan/status, and dynamic sizing is applied
 * through the CSSOM (element.style), which CSP allows.
 */

document.addEventListener("DOMContentLoaded", function () {
  initFindingsTable();
  initHeatBar();
  initPaletteButtons();
  initCopyButtons();
  initLiveMonitor();
  initLogAnalytics();
  initGaugeAndCounters();
  initRowFilters();
  showPostReloadToast();
  initScanControls();
  initDashboardCharts();
  initHistoryTrendChart();
});

/** Read a CSS custom property so charts share the stylesheet's palette. */
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}

/** 1. Expandable findings rows (mouse and keyboard). */
function initFindingsTable() {
  document.querySelectorAll(".table-row-clickable").forEach(function (row) {
    function toggle() {
      const detail = document.getElementById(row.getAttribute("data-target"));
      if (!detail) return;
      const open = detail.classList.toggle("expanded");
      row.classList.toggle("is-open", open);
      row.setAttribute("aria-expanded", open ? "true" : "false");
    }
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle();
      }
    });
  });
}

/** 2. Proportional widths for the severity heat strip and framework coverage bars. */
function initHeatBar() {
  document.querySelectorAll("[data-weight]").forEach(function (seg) {
    seg.style.flexGrow = seg.getAttribute("data-weight") || "1";
    seg.style.flexBasis = "0";
  });
}

/** Buttons that open the command palette (Alpine listens for this window event). */
function initPaletteButtons() {
  document.querySelectorAll("[data-open-palette]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      window.dispatchEvent(new CustomEvent("open-palette"));
    });
  });
}

/** Animate the posture gauge sweep and count-up numbers on the dashboard. */
function initGaugeAndCounters() {
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) return;

  var gauge = document.querySelector("[data-gauge]");
  if (gauge) {
    var target = gauge.getAttribute("data-gauge");
    gauge.style.strokeDasharray = "0 628.3";
    gauge.style.transition = "stroke-dasharray 1.1s cubic-bezier(0.2, 0.7, 0.2, 1)";
    requestAnimationFrame(function () {
      requestAnimationFrame(function () { gauge.style.strokeDasharray = target + " 628.3"; });
    });
  }

  document.querySelectorAll("[data-countup]").forEach(function (el) {
    var end = parseInt(el.getAttribute("data-countup"), 10);
    if (isNaN(end) || end === 0) return;
    var start = null;
    function step(ts) {
      if (start === null) start = ts;
      var p = Math.min(1, (ts - start) / 900);
      el.textContent = String(Math.round(end * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(step);
    }
    el.textContent = "0";
    requestAnimationFrame(step);
  });
}

/** Live text filter for plain tables: <input data-filter-rows="css selector of rows">. */
function initRowFilters() {
  document.querySelectorAll("[data-filter-rows]").forEach(function (input) {
    var rows = document.querySelectorAll(input.getAttribute("data-filter-rows"));
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      rows.forEach(function (row) {
        row.style.display = !q || row.textContent.toLowerCase().indexOf(q) !== -1 ? "" : "none";
      });
    });
  });
}

/** Show a toast queued before a page reload (for example after a scan completes). */
function showPostReloadToast() {
  var msg = null;
  try { msg = sessionStorage.getItem("ws-toast"); sessionStorage.removeItem("ws-toast"); } catch (e) { return; }
  if (msg && window.wsToast) setTimeout(function () { window.wsToast(msg, "success"); }, 600);
}

/** Poll the live Security-log monitor, update the top-bar chip and toast new alerts. */
function initLiveMonitor() {
  var chip = document.getElementById("live-chip");
  if (!chip) return;
  var text = document.getElementById("live-chip-text");
  var count = document.getElementById("live-chip-count");
  var sinceId = null;
  var unseen = 0;

  function poll() {
    fetch("/api/live/status?since_id=" + (sinceId || 0), { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var m = d.monitor || {};
        chip.setAttribute("data-state", m.enabled ? (m.last_error ? "error" : "on") : "off");
        if (text) text.textContent = m.enabled ? "Live" : "Live off";
        chip.title = m.enabled
          ? "Monitoring the Security log every " + m.interval_seconds + "s" + (m.last_error ? " (last error: " + m.last_error + ")" : "")
          : (m.reason || "Live monitor is off");

        if (sinceId === null) { sinceId = d.max_id; return; }  // first poll only sets the baseline
        if (d.alerts && d.alerts.length) {
          d.alerts.slice().reverse().forEach(function (a) {
            unseen += 1;
            if (window.wsToast) window.wsToast(a.severity + ": " + a.type + " (" + a.account + ")", a.severity === "Critical" ? "error" : "info");
          });
          sinceId = d.max_id;
          if (count) count.textContent = String(unseen);
          chip.classList.add("has-new");
          if (window.location.pathname === "/alerts") setTimeout(function () { window.location.reload(); }, 1500);
        }
      })
      .catch(function () { /* server restarting or logged out: try again next tick */ });
  }
  poll();
  setInterval(poll, 20000);
}

/** Security-log analytics charts on the Alerts page (top accounts / IPs, logon types, hourly timeline). */
function initLogAnalytics() {
  var root = document.getElementById("analytics");
  if (!root || typeof Chart === "undefined") return;
  var scanId = root.getAttribute("data-scan");

  fetch("/api/log-analytics?scan_id=" + encodeURIComponent(scanId), { credentials: "same-origin" })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (!d.available) {
        root.querySelectorAll(".chart-panel").forEach(function (p) { p.hidden = true; });
        var note = document.getElementById("analytics-note");
        if (note) note.hidden = false;
        return;
      }
      applyChartDefaults();
      var signal = cssVar("--signal"), red = cssVar("--sev-critical"), green = cssVar("--sev-low"), orange = cssVar("--sev-high");
      var names = function (arr) { return arr.map(function (x) { return x.name; }); };
      var counts = function (arr) { return arr.map(function (x) { return x.count; }); };
      var empty = function (arr) { return arr.length ? arr : [{ name: "none", count: 0 }]; };

      function bar(id, rows, color) {
        var el = document.getElementById(id);
        if (!el) return;
        rows = empty(rows);
        new Chart(el, {
          type: "bar",
          data: { labels: names(rows), datasets: [{ data: counts(rows), backgroundColor: color, borderRadius: 3, maxBarThickness: 22 }] },
          options: {
            indexAxis: "y", responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
          },
        });
      }
      bar("topAccountsChart", d.top_accounts, red);
      bar("topIpsChart", d.top_ips, orange);

      var types = d.logon_types.length ? d.logon_types : [{ name: "none", failed: 0, success: 0 }];
      new Chart(document.getElementById("logonTypeChart"), {
        type: "bar",
        data: {
          labels: types.map(function (t) { return t.name; }),
          datasets: [
            { label: "Failed", data: types.map(function (t) { return t.failed; }), backgroundColor: red, borderRadius: 3 },
            { label: "Successful", data: types.map(function (t) { return t.success; }), backgroundColor: green, borderRadius: 3 },
          ],
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { boxWidth: 9, boxHeight: 9 } } },
          scales: { x: { beginAtZero: true, stacked: true, ticks: { precision: 0 } }, y: { stacked: true, grid: { display: false } } },
        },
      });

      var hourly = empty(d.hourly);
      new Chart(document.getElementById("hourlyChart"), {
        type: "line",
        data: {
          labels: hourly.map(function (h) { return h.name.slice(5); }),
          datasets: [{ label: "Failed logons", data: counts(hourly), borderColor: signal, backgroundColor: "rgba(61, 219, 217, 0.12)", fill: true, tension: 0.25, pointRadius: 2 }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false }, ticks: { maxTicksLimit: 12 } } },
        },
      });
    })
    .catch(function (err) { console.error("Log analytics error:", err); });
}

/** Copy-to-clipboard for fix commands: <button data-copy-target="#id">. */
function initCopyButtons() {
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy-target]");
    if (!btn) return;
    var target = document.querySelector(btn.getAttribute("data-copy-target"));
    if (!target) return;
    var done = function () { if (window.wsToast) window.wsToast("Command copied. Paste it into an elevated PowerShell.", "success"); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(target.textContent).then(done, function () { window.wsToast("Could not copy. Select the text and press Ctrl+C.", "error"); });
    } else {
      var range = document.createRange();
      range.selectNodeContents(target);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      window.wsToast("Command selected. Press Ctrl+C to copy.", "info");
    }
  });
}

/** 3. Scan trigger, pipeline stepper and status polling. */
function initScanControls() {
  const scanBtn = document.getElementById("btn-start-scan");
  const emptyBtn = document.getElementById("btn-empty-scan");
  const banner = document.getElementById("progress-banner");
  const stepText = document.getElementById("progress-step");
  const barFill = document.getElementById("progress-bar-fill");
  const percent = document.getElementById("progress-percent");
  const steps = Array.prototype.slice.call(document.querySelectorAll("#scan-pipeline li"));
  let pollTimer = null;

  function setBusy(busy) {
    [scanBtn, emptyBtn].forEach(function (b) {
      if (!b) return;
      b.disabled = busy;
      b.classList.toggle("is-busy", busy);
    });
  }

  function renderProgress(data) {
    if (banner) banner.classList.add("active");
    if (stepText) stepText.textContent = "Current step: " + (data.step || "Auditing");
    if (barFill) barFill.style.width = (data.progress || 0) + "%";
    if (percent) percent.textContent = (data.progress || 0) + "%";
    let currentIdx = steps.findIndex(function (li) {
      return li.getAttribute("data-step") === data.step;
    });
    steps.forEach(function (li, i) {
      li.classList.toggle("done", currentIdx > -1 && i < currentIdx);
      li.classList.toggle("current", i === currentIdx);
    });
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function startPolling() {
    if (!pollTimer) pollTimer = setInterval(function () { checkStatus(true); }, 1000);
  }

  function checkStatus(reloadOnComplete) {
    fetch("/scan/status", { credentials: "same-origin" })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data.status === "running") {
          setBusy(true);
          renderProgress(data);
          startPolling();
        } else if (data.status === "completed") {
          stopPolling();
          if (reloadOnComplete) {
            steps.forEach(function (li) { li.classList.add("done"); li.classList.remove("current"); });
            if (barFill) barFill.style.width = "100%";
            if (percent) percent.textContent = "100%";
            if (stepText) stepText.textContent = "Audit complete. Loading results...";
            try { sessionStorage.setItem("ws-toast", "Scan complete. Results updated."); } catch (e) { /* ignore */ }
            setTimeout(function () { window.location.reload(); }, 600);
          }
        } else if (data.status === "failed") {
          stopPolling();
          setBusy(false);
          if (reloadOnComplete && banner) {
            banner.classList.add("active");
            if (stepText) stepText.textContent = "Scan failed: " + (data.error || "unknown error");
          }
        }
      })
      .catch(function (err) { console.error("Status poll error:", err); });
  }

  function startScan(e) {
    e.preventDefault();
    setBusy(true);
    fetch("/scan/start", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": getCsrfToken() },
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data.status === "started") {
          renderProgress({ step: "Initializing audit", progress: 5 });
          startPolling();
        } else {
          setBusy(false);
          if (banner) banner.classList.add("active");
          if (stepText) stepText.textContent = data.message || "Could not start the scan.";
        }
      })
      .catch(function (err) {
        console.error("Scan start error:", err);
        setBusy(false);
      });
  }

  if (scanBtn) scanBtn.addEventListener("click", startScan);
  if (emptyBtn) emptyBtn.addEventListener("click", startScan);

  // Resume the progress display if a scan is already running when the page loads.
  checkStatus(false);
}

/** Shared Chart.js defaults matching the console theme. */
function applyChartDefaults() {
  Chart.defaults.color = cssVar("--text-dim");
  Chart.defaults.borderColor = cssVar("--line");
  Chart.defaults.font.family = cssVar("--font-body");
  Chart.defaults.font.size = 11;
}

/** 4. Dashboard charts (severity doughnut, module bars, daily failed logons). */
function initDashboardCharts() {
  const sevCanvas = document.getElementById("severityChart");
  const modCanvas = document.getElementById("moduleChart");
  const logCanvas = document.getElementById("logonChart");
  if (!sevCanvas && !modCanvas && !logCanvas) return;

  const scanId = new URLSearchParams(window.location.search).get("scan_id");
  const url = "/api/summary" + (scanId ? "?scan_id=" + encodeURIComponent(scanId) : "");

  fetch(url, { credentials: "same-origin" })
    .then(function (res) {
      if (!res.ok) throw new Error("API returned " + res.status);
      return res.json();
    })
    .then(function (data) {
      if (typeof Chart === "undefined") return;
      applyChartDefaults();
      const signal = cssVar("--signal");

      if (sevCanvas) {
        const c = data.severity_counts || {};
        const labels = ["Critical", "High", "Medium", "Low", "Info"];
        new Chart(sevCanvas, {
          type: "doughnut",
          data: {
            labels: labels,
            datasets: [{
              data: labels.map(function (l) { return c[l] || 0; }),
              backgroundColor: [
                cssVar("--sev-critical"), cssVar("--sev-high"), cssVar("--sev-medium"),
                cssVar("--sev-low"), cssVar("--sev-info"),
              ],
              borderWidth: 3,
              borderColor: cssVar("--ink-850"),
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "66%",
            plugins: { legend: { position: "bottom", labels: { boxWidth: 9, boxHeight: 9, padding: 10 } } },
          },
        });
      }

      if (modCanvas) {
        const m = data.module_counts || {};
        new Chart(modCanvas, {
          type: "bar",
          data: {
            labels: ["Config", "Event logs", "Software"],
            datasets: [{
              label: "Failed checks",
              data: [m.config || 0, m.logs || 0, m.software || 0],
              backgroundColor: signal,
              borderRadius: 3,
              maxBarThickness: 46,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false } } },
          },
        });
      }

      if (logCanvas) {
        const days = Object.keys(data.daily_failures || {}).sort();
        new Chart(logCanvas, {
          type: "line",
          data: {
            labels: days.length ? days.map(function (d) { return d.slice(5); }) : ["No failed logons"],
            datasets: [{
              label: "Failed logons",
              data: days.length ? days.map(function (d) { return data.daily_failures[d]; }) : [0],
              borderColor: cssVar("--sev-critical"),
              backgroundColor: "rgba(255, 77, 94, 0.12)",
              fill: true,
              tension: 0.3,
              pointRadius: 3,
              pointBackgroundColor: cssVar("--sev-critical"),
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false } } },
          },
        });
      }
    })
    .catch(function (err) { console.error("Dashboard chart load error:", err); });
}

/** 5. Posture score trend on the history page (completed scans only). */
function initHistoryTrendChart() {
  const canvas = document.getElementById("historyTrendChart");
  if (!canvas) return;

  fetch("/api/summary", { credentials: "same-origin" })
    .then(function (res) { return res.json(); })
    .then(function (data) {
      if (typeof Chart === "undefined") return;
      const history = (data.scan_history || [])
        .filter(function (s) { return s.posture_score !== null && s.posture_score !== undefined; })
        .reverse();
      if (!history.length) return;
      applyChartDefaults();
      const signal = cssVar("--signal");

      new Chart(canvas, {
        type: "line",
        data: {
          labels: history.map(function (s) { return "#" + s.id + " " + s.started_at.substring(5, 10); }),
          datasets: [{
            label: "Posture score",
            data: history.map(function (s) { return s.posture_score; }),
            borderColor: signal,
            backgroundColor: "rgba(61, 219, 217, 0.12)",
            borderWidth: 2,
            fill: true,
            tension: 0.25,
            pointRadius: 4,
            pointBackgroundColor: signal,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { y: { min: 0, max: 100, ticks: { stepSize: 20 } }, x: { grid: { display: false } } },
        },
      });
    })
    .catch(function (err) { console.error("History chart error:", err); });
}
