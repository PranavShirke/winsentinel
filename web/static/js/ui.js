/**
 * WinSentinel - interactive UI components (Alpine.js CSP build, vendored locally).
 *
 * The CSP build forbids inline expressions, so every behaviour lives here as a named component
 * and templates only reference properties and methods. Components:
 *   toaster, themeToggle, autoScan, palette (Ctrl+K), findingsToolbar, findingRow, registerModal.
 */

function wsToast(message, type) {
  window.dispatchEvent(new CustomEvent("toast", { detail: { message: message, type: type || "info" } }));
}
window.wsToast = wsToast;

function csrfToken() {
  var meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}

function toggleTheme() {
  var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("ws-theme", next); } catch (e) { /* ignore */ }
  // Charts read colours once at creation, so redraw them when the theme changes
  if (document.querySelector("canvas")) window.location.reload();
}

document.addEventListener("alpine:init", function () {
  var REGISTER_LABEL = { open: "Open", in_progress: "In progress", accepted: "Accepted risk", false_positive: "False positive" };

  /* ---- Shared filter state for the findings list ---- */
  Alpine.store("filters", {
    severity: "",
    status: "",
    register: "",
    q: "",
    rows: [],
    match: function (m) {
      if (this.severity && m.severity !== this.severity) return false;
      if (this.status && m.status !== this.status) return false;
      if (this.register && m.register !== this.register) return false;
      if (this.q && m.text.indexOf(this.q.toLowerCase()) === -1) return false;
      return true;
    },
    get visibleCount() {
      var self = this;
      return this.rows.filter(function (r) { return self.match(r); }).length;
    },
    get total() { return this.rows.length; },
    reset: function () { this.severity = ""; this.status = ""; this.register = ""; this.q = ""; },
  });

  /* ---- Toasts ---- */
  Alpine.data("toaster", function () {
    return {
      items: [],
      seq: 0,
      add: function (e) {
        var self = this;
        var toast = { id: ++this.seq, message: e.detail.message, cls: "toast toast-" + (e.detail.type || "info") };
        this.items.push(toast);
        setTimeout(function () {
          self.items = self.items.filter(function (t) { return t.id !== toast.id; });
        }, 4500);
      },
    };
  });

  /* ---- Theme toggle ---- */
  Alpine.data("themeToggle", function () {
    return {
      switchTheme: function () { toggleTheme(); },
    };
  });

  /* ---- Administrator-rights banner (dismissed per browser session) ---- */
  Alpine.data("elevBanner", function () {
    return {
      visible: true,
      init: function () {
        try { this.visible = sessionStorage.getItem("ws-elev-dismissed") !== "1"; } catch (e) { /* show it */ }
      },
      dismiss: function () {
        this.visible = false;
        try { sessionStorage.setItem("ws-elev-dismissed", "1"); } catch (e) { /* ignore */ }
      },
    };
  });

  /* ---- Auto-scan countdown chip ---- */
  Alpine.data("autoScan", function () {
    return {
      left: "",
      init: function () {
        var self = this;
        var next = parseInt(this.$el.dataset.next, 10) * 1000;
        function tick() {
          var s = Math.max(0, Math.round((next - Date.now()) / 1000));
          self.left = Math.floor(s / 60) + "m " + String(s % 60).padStart(2, "0") + "s";
        }
        tick();
        setInterval(tick, 1000);
      },
    };
  });

  /* ---- Command palette (Ctrl+K or /) ---- */
  Alpine.data("palette", function () {
    var timer = null;
    return {
      open: false,
      q: "",
      active: 0,
      found: [],
      base: [
        { label: "Dashboard", href: "/dashboard", hint: "Go to" },
        { label: "Findings", href: "/findings", hint: "Go to" },
        { label: "Failed findings only", href: "/findings?status=fail", hint: "Go to" },
        { label: "Alerts", href: "/alerts", hint: "Go to" },
        { label: "Software & CVEs", href: "/software", hint: "Go to" },
        { label: "Frameworks (ATT&CK / CIS)", href: "/frameworks", hint: "Go to" },
        { label: "Scan history", href: "/history", hint: "Go to" },
        { label: "Compare scans", href: "/compare", hint: "Go to" },
        { label: "Report", href: "/report", hint: "Go to" },
        { label: "Download PDF report", href: "/report/download.pdf", hint: "Export" },
        { label: "Download HTML report", href: "/report/download", hint: "Export" },
        { label: "Export findings as CSV", href: "/findings/export.csv", hint: "Export" },
        { label: "Run new scan", action: "scan", hint: "Action" },
        { label: "Switch light / dark theme", action: "theme", hint: "Action" },
      ],
      get view() {
        var q = this.q.trim().toLowerCase();
        var self = this;
        var nav = this.base.filter(function (i) { return !q || i.label.toLowerCase().indexOf(q) !== -1; });
        return nav.concat(this.found).map(function (item, i) {
          return {
            key: item.hint + item.label + i,
            label: item.label,
            hint: item.hint,
            idx: i,
            cls: "palette-item" + (i === self.active ? " active" : ""),
          };
        });
      },
      get isEmpty() { return this.view.length === 0; },
      show: function () {
        this.open = true;
        this.q = "";
        this.found = [];
        this.active = 0;
        var self = this;
        // The overlay is display:none until Alpine applies x-show, and an element that is not
        // displayed cannot take focus. Retry on the next frames until the input really has focus.
        var attempts = 0;
        (function focusInput() {
          var input = self.$refs.input;
          if (input) input.focus();
          if (document.activeElement !== input && attempts++ < 10) requestAnimationFrame(focusInput);
        })();
      },
      hide: function () { this.open = false; },
      // A key typed in the instant between the overlay opening and the input gaining focus would be
      // lost, so catch it here, focus the input and keep the character.
      capture: function (e) {
        var input = this.$refs.input;
        // defaultPrevented: the key that just opened the palette (Ctrl+K or "/") was already handled
        if (e.defaultPrevented || !this.open || !input || document.activeElement === input) return;
        input.focus();
        if (e.key && e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          this.q += e.key;
          this.onInput();
          e.preventDefault();
        }
      },
      slash: function (e) {
        var tag = (e.target.tagName || "").toLowerCase();
        if (tag === "input" || tag === "textarea" || tag === "select") return;
        e.preventDefault();
        this.show();
      },
      onInput: function () {
        var self = this;
        this.active = 0;
        clearTimeout(timer);
        var q = this.q.trim();
        if (q.length < 2) { this.found = []; return; }
        timer = setTimeout(function () {
          var params = new URLSearchParams(window.location.search);
          var url = "/api/search?q=" + encodeURIComponent(q) + (params.get("scan_id") ? "&scan_id=" + encodeURIComponent(params.get("scan_id")) : "");
          fetch(url, { credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (d) {
              self.found = (d.results || []).map(function (r) {
                return { label: r.title, hint: r.severity, href: "/findings?search=" + encodeURIComponent(r.title.slice(0, 60)) };
              });
            })
            .catch(function () { self.found = []; });
        }, 180);
      },
      move: function (e) {
        var n = this.view.length;
        if (!n) return;
        this.active = (this.active + (e.key === "ArrowDown" ? 1 : -1) + n) % n;
      },
      hover: function (e) { this.active = parseInt(e.currentTarget.dataset.idx, 10); },
      pick: function (e) { this.run(parseInt(e.currentTarget.dataset.idx, 10)); },
      enter: function () { this.run(this.active); },
      run: function (idx) {
        var q = this.q.trim().toLowerCase();
        var nav = this.base.filter(function (i) { return !q || i.label.toLowerCase().indexOf(q) !== -1; });
        var item = nav.concat(this.found)[idx];
        if (!item) return;
        this.open = false;
        if (item.action === "scan") {
          var btn = document.getElementById("btn-start-scan");
          if (btn) btn.click();
        } else if (item.action === "theme") {
          toggleTheme();
        } else if (item.href) {
          window.location.href = item.href;
        }
      },
    };
  });

  /* ---- Findings toolbar: chips, live search, sort ---- */
  Alpine.data("findingsToolbar", function () {
    function chips(kind, options) {
      var f = Alpine.store("filters");
      return options.map(function (o) {
        var count = f.rows.filter(function (r) { return o[0] === "" || r[kind] === o[0]; }).length;
        return {
          key: kind + o[0],
          kind: kind,
          value: o[0],
          label: o[1],
          count: count,
          cls: "chip" + (f[kind] === o[0] ? " on" : ""),
        };
      });
    }
    return {
      sort: "risk",
      get f() { return Alpine.store("filters"); },
      get sevChips() {
        return chips("severity", [["", "All"], ["Critical", "Critical"], ["High", "High"], ["Medium", "Medium"], ["Low", "Low"], ["Info", "Info"], ["Error", "Error"]])
          .filter(function (c) { return c.value === "" || c.count > 0; });
      },
      get statusChips() {
        return chips("status", [["", "Any status"], ["fail", "Fail"], ["pass", "Pass"], ["error", "Error"]]);
      },
      get regChips() {
        return chips("register", [["", "Any decision"], ["open", "Open"], ["in_progress", "In progress"], ["accepted", "Accepted"], ["false_positive", "False positive"]]);
      },
      pick: function (e) {
        var d = e.currentTarget.dataset;
        Alpine.store("filters")[d.kind] = d.value;
      },
      onQuery: function (e) { Alpine.store("filters").q = e.target.value; },
      reset: function () {
        Alpine.store("filters").reset();
        if (this.$refs.q) this.$refs.q.value = "";
      },
      applySort: function () {
        var rank = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Error: 0 };
        var key = this.sort;
        var bodies = Array.prototype.slice.call(document.querySelectorAll("tbody.finding"));
        if (!bodies.length) return;
        var parent = bodies[0].parentNode;
        bodies.sort(function (a, b) {
          var da = a.dataset, db = b.dataset;
          if (key === "title") return da.title.localeCompare(db.title);
          if (key === "module") return da.module.localeCompare(db.module) || (parseInt(db.risk, 10) - parseInt(da.risk, 10));
          if (key === "severity") return (rank[db.severity] - rank[da.severity]) || (parseInt(db.risk, 10) - parseInt(da.risk, 10));
          return (parseInt(db.risk, 10) - parseInt(da.risk, 10)) || da.title.localeCompare(db.title);
        });
        bodies.forEach(function (b) { parent.appendChild(b); });
      },
    };
  });

  /* ---- One finding (a <tbody> holding the summary row and the detail row) ---- */
  Alpine.data("findingRow", function () {
    var root = null;
    return {
      open: false,
      meta: null,
      init: function () {
        root = this.$el;
        var d = root.dataset;
        this.meta = {
          severity: d.severity,
          status: d.status,
          register: d.register,
          note: d.note || "",
          by: d.by || "",
          at: d.at || "",
          text: (d.title + " " + (d.text || "") + " " + d.module).toLowerCase(),
        };
        Alpine.store("filters").rows.push(this.meta);
      },
      get visible() { return Alpine.store("filters").match(this.meta); },
      get decided() { return this.meta.register === "accepted" || this.meta.register === "false_positive"; },
      get hasDecision() { return this.meta.register !== "open"; },
      get registerLabel() { return REGISTER_LABEL[this.meta.register]; },
      get registerClass() { return "reg reg-" + this.meta.register; },
      get rowClass() { return (this.open ? "is-open" : "") + (this.decided ? " decided" : ""); },
      get expanded() { return this.open ? "true" : "false"; },
      get noteText() { return this.meta.note ? this.meta.note : "No justification recorded."; },
      get byText() { return this.meta.by ? this.meta.by + ", " + this.meta.at : ""; },
      toggle: function () { this.open = !this.open; },
      openRegister: function (e) {
        e.stopPropagation();
        var d = root.dataset;
        window.dispatchEvent(new CustomEvent("open-register", {
          detail: { scan_id: d.scan, module: d.module, title: d.title, status: this.meta.register, note: this.meta.note },
        }));
      },
      onUpdated: function (e) {
        var d = root.dataset;
        if (e.detail.module === d.module && e.detail.title === d.title) {
          this.meta.register = e.detail.status;
          this.meta.note = e.detail.note;
          this.meta.by = e.detail.by;
          this.meta.at = e.detail.at;
        }
      },
    };
  });

  /* ---- Risk-register dialog ---- */
  Alpine.data("registerModal", function () {
    return {
      open: false,
      busy: false,
      error: "",
      title: "",
      module: "",
      scanId: "",
      status: "open",
      note: "",
      show: function (e) {
        var d = e.detail;
        this.title = d.title;
        this.module = d.module;
        this.scanId = d.scan_id;
        this.status = d.status || "open";
        this.note = d.note || "";
        this.error = "";
        this.busy = false;
        this.open = true;
        var self = this;
        var tries = 0;
        (function focusNote() {
          var note = self.$refs.note;
          if (note) note.focus();
          if (document.activeElement !== note && tries++ < 10) requestAnimationFrame(focusNote);
        })();
      },
      close: function () { this.open = false; },
      get needsNote() { return this.status === "accepted" || this.status === "false_positive"; },
      get saveLabel() { return this.busy ? "Saving..." : "Save decision"; },
      submit: function () {
        var self = this;
        if (this.needsNote && this.note.trim().length < 8) {
          this.error = "Please write a short justification (at least 8 characters).";
          return;
        }
        this.busy = true;
        this.error = "";
        fetch("/api/findings/status", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
          body: JSON.stringify({ scan_id: this.scanId, module: this.module, title: this.title, status: this.status, note: this.note }),
        })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
          .then(function (res) {
            self.busy = false;
            if (!res.ok) { self.error = res.body.message || "Could not save the decision."; return; }
            var now = new Date().toISOString().slice(0, 19).replace("T", " ");
            window.dispatchEvent(new CustomEvent("finding-updated", {
              detail: { module: self.module, title: self.title, status: self.status, note: self.note.trim(), by: "you", at: now },
            }));
            wsToast("Saved. Adjusted score is now " + res.body.adjusted_score + "/100.", "success");
            self.open = false;
          })
          .catch(function () { self.busy = false; self.error = "Network error. Try again."; });
      },
    };
  });
});
