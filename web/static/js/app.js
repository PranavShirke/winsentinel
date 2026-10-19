/**
 * WinSentinel - Dashboard Client JavaScript.
 *
 * Implements:
 *   1. Chart.js rendering via asynchronous GET /api/summary fetch (No inline scripts).
 *   2. Background scan execution and status polling (GET /scan/status).
 *   3. Interactive expandable findings rows for evidence and remediation details.
 *   4. Zero third-party network requests (Strict CSP compliance).
 */

document.addEventListener("DOMContentLoaded", function () {
  initFindingsTable();
  initScanControls();
  initDashboardCharts();
  initHistoryTrendChart();
});

/**
 * 1. Expandable Table Rows for Findings
 */
function initFindingsTable() {
  const clickableRows = document.querySelectorAll(".table-row-clickable");
  clickableRows.forEach(function (row) {
    row.addEventListener("click", function () {
      const targetId = row.getAttribute("data-target");
      if (!targetId) return;
      const detailRow = document.getElementById(targetId);
      if (detailRow) {
        detailRow.classList.toggle("expanded");
      }
    });

    // Keyboard accessibility: Enter or Space expands row
    row.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        row.click();
      }
    });
  });
}

/**
 * 2. Background Scan Trigger & Status Polling
 */
function initScanControls() {
  const scanBtn = document.getElementById("btn-start-scan");
  const emptyScanBtn = document.getElementById("btn-empty-scan");
  const progressBanner = document.getElementById("progress-banner");
  const progressStep = document.getElementById("progress-step");
  const progressBarFill = document.getElementById("progress-bar-fill");
  const progressPercent = document.getElementById("progress-percent");

  // Only resume polling when a scan is actually running. A completed status
  // belongs to the last scan and must not trigger a reload on every page load.
  checkScanStatus(false);

  if (scanBtn) {
    scanBtn.addEventListener("click", function (e) {
      e.preventDefault();
      startNewScan();
    });
  }

  if (emptyScanBtn) {
    emptyScanBtn.addEventListener("click", function (e) {
      e.preventDefault();
      startNewScan();
    });
  }

  function startNewScan() {
    const csrfToken = getCsrfToken();
    if (scanBtn) scanBtn.disabled = true;

    fetch("/scan/start", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken,
      },
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        if (data.status === "started" || data.status === "running") {
          if (progressBanner) progressBanner.classList.add("active");
          pollStatus();
        } else {
          alert(data.message || "Failed to start audit scan.");
          if (scanBtn) scanBtn.disabled = false;
        }
      })
      .catch(function (err) {
        console.error("Scan start error:", err);
        if (scanBtn) scanBtn.disabled = false;
      });
  }

  let pollInterval = null;

  function pollStatus() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(function () {
      checkScanStatus(true);
    }, 1000);
  }

  function checkScanStatus(allowCompletionReload) {
    fetch("/scan/status")
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        if (data.status === "running") {
          if (progressBanner) progressBanner.classList.add("active");
          if (scanBtn) scanBtn.disabled = true;
          if (progressStep) progressStep.textContent = "Step: " + (data.step || "Auditing...");
          if (progressBarFill) progressBarFill.style.width = data.progress + "%";
          if (progressPercent) progressPercent.textContent = data.progress + "%";
          if (!pollInterval) pollStatus();
        } else if (data.status === "completed") {
          if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
          }
          if (allowCompletionReload) {
            if (progressBarFill) progressBarFill.style.width = "100%";
            if (progressPercent) progressPercent.textContent = "100%";
            if (progressStep) progressStep.textContent = "Audit completed. Updating results...";
            setTimeout(function () {
              window.location.reload();
            }, 700);
          }
        } else if (data.status === "failed") {
          if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
          }
          if (progressStep) progressStep.textContent = "Scan Failed: " + (data.error || "Unknown error");
          if (scanBtn) scanBtn.disabled = false;
          if (!allowCompletionReload && progressBanner) {
            progressBanner.classList.remove("active");
          }
        }
      })
      .catch(function (err) {
        console.error("Status poll error:", err);
      });
  }
}

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}

/**
 * 3. Dashboard Chart.js Visualizations (Loaded via GET /api/summary)
 */
function initDashboardCharts() {
  const sevCanvas = document.getElementById("severityChart");
  const modCanvas = document.getElementById("moduleChart");
  const logCanvas = document.getElementById("logonChart");

  if (!sevCanvas && !modCanvas && !logCanvas) return;

  const urlParams = new URLSearchParams(window.location.search);
  const scanId = urlParams.get("scan_id");
  let apiUrl = "/api/summary";
  if (scanId) apiUrl += "?scan_id=" + encodeURIComponent(scanId);

  fetch(apiUrl)
    .then(function (res) {
      if (!res.ok) throw new Error("API returned " + res.status);
      return res.json();
    })
    .then(function (data) {
      if (typeof Chart === "undefined") {
        console.warn("Chart.js vendor library not loaded.");
        return;
      }

      // Configure Chart.js global dark theme defaults
      Chart.defaults.color = "#8b98a9";
      Chart.defaults.borderColor = "#263040";
      Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

      // Chart A: Severity Breakdown (Doughnut)
      if (sevCanvas && data.severity_counts) {
        const counts = data.severity_counts;
        new Chart(sevCanvas, {
          type: "doughnut",
          data: {
            labels: ["Critical", "High", "Medium", "Low", "Info"],
            datasets: [
              {
                data: [
                  counts["Critical"] || 0,
                  counts["High"] || 0,
                  counts["Medium"] || 0,
                  counts["Low"] || 0,
                  counts["Info"] || 0,
                ],
                backgroundColor: [
                  "#ef4444", // Critical
                  "#f97316", // High
                  "#eab308", // Medium
                  "#22c55e", // Low
                  "#64748b", // Info
                ],
                borderWidth: 2,
                borderColor: "#171d26",
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: "bottom",
                labels: { boxWidth: 10, padding: 8, font: { size: 11 } },
              },
            },
            cutout: "68%",
            layout: { padding: 4 },
          },
        });
      }

      // Chart B: Findings by Module (Bar)
      if (modCanvas && data.module_counts) {
        const mods = data.module_counts;
        new Chart(modCanvas, {
          type: "bar",
          data: {
            labels: ["Configuration", "Event Logs", "Software CVEs"],
            datasets: [
              {
                label: "Failed Findings",
                data: [mods["config"] || 0, mods["logs"] || 0, mods["software"] || 0],
                backgroundColor: "#3b82f6",
                borderRadius: 4,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              y: { beginAtZero: true, ticks: { precision: 0 } },
              x: { grid: { display: false } },
            },
          },
        });
      }

      // Chart C: Failed Logons per Day (Line/Bar)
      if (logCanvas && data.daily_failures) {
        const dates = Object.keys(data.daily_failures).sort();
        const counts = dates.map(function (d) {
          return data.daily_failures[d];
        });

        new Chart(logCanvas, {
          type: "line",
          data: {
            labels: dates.length ? dates : ["No Logons"],
            datasets: [
              {
                label: "Failed Logons (4625)",
                data: counts.length ? counts : [0],
                borderColor: "#ef4444",
                backgroundColor: "rgba(239, 68, 68, 0.1)",
                tension: 0.3,
                fill: true,
                pointRadius: 4,
                pointBackgroundColor: "#ef4444",
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              y: { beginAtZero: true, ticks: { precision: 0 } },
              x: { grid: { display: false } },
            },
          },
        });
      }
    })
    .catch(function (err) {
      console.error("Dashboard chart summary load error:", err);
    });
}

/**
 * 4. Scan History Trend Chart (Posture Score over Time)
 */
function initHistoryTrendChart() {
  const historyCanvas = document.getElementById("historyTrendChart");
  if (!historyCanvas) return;

  fetch("/api/summary")
    .then(function (res) {
      return res.json();
    })
    .then(function (data) {
      if (!data.scan_history || !data.scan_history.length) return;
      if (typeof Chart === "undefined") return;

      // Reverse so chronological order from left to right
      const history = data.scan_history.slice().reverse();
      const labels = history.map(function (s) {
        return "Scan #" + s.id + " (" + s.started_at.substring(0, 10) + ")";
      });
      const scores = history.map(function (s) {
        return s.posture_score != null ? s.posture_score : 100;
      });

      new Chart(historyCanvas, {
        type: "line",
        data: {
          labels: labels,
          datasets: [
            {
              label: "Posture Score",
              data: scores,
              borderColor: "#3b82f6",
              backgroundColor: "rgba(59, 130, 246, 0.15)",
              borderWidth: 2,
              fill: true,
              tension: 0.2,
              pointRadius: 5,
              pointBackgroundColor: "#3b82f6",
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
          },
          scales: {
            y: { min: 0, max: 100, ticks: { stepSize: 20 } },
          },
        },
      });
    })
    .catch(function (err) {
      console.error("History trend chart error:", err);
    });
}
