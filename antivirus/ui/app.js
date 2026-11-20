/* Schutzschild – Oberfläche */
"use strict";
(() => {
  // ------------------------------------------------------------------ Helfer
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
  const nf = new Intl.NumberFormat("de-DE");
  const num = (n) => nf.format(Math.round(n || 0));

  const ICONS = {
    home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h5v-6h4v6h5V10"/>',
    scan: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/><path d="M8 11h6"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6.5-6.5"/><circle cx="12" cy="12" r="1"/>',
    cpu: '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/>',
    box: '<path d="M21 8l-9-5-9 5 9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>',
    sliders: '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
    shield: '<path d="M12 3l8 3v6c0 5-3.4 8.4-8 9.5C7.4 20.4 4 17 4 12V6z"/>',
    check: '<path d="M20 6L9 17l-5-5"/>',
    x: '<path d="M18 6L6 18M6 6l12 12"/>',
    alert: '<path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>',
    zap: '<path d="M13 2L3 14h9l-1 8 10-12h-9z"/>',
    ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',
    restore: '<path d="M3 12a9 9 0 103-6.7L3 8"/><path d="M3 3v5h5"/>',
    folder: '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',
    file: '<path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M14 3v6h6"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>',
    lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/>',
    power: '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 11-12.8 0"/>',
    refresh: '<path d="M21 12a9 9 0 01-15.5 6.2L3 16"/><path d="M3 21v-5h5"/><path d="M3 12A9 9 0 0118.5 5.8L21 8"/><path d="M21 3v5h-5"/>',
    kick: '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0114 0"/><path d="M17 8l5 5M22 8l-5 5"/>',
    bug: '<rect x="7" y="7" width="10" height="13" rx="5"/><path d="M12 7V4M9 3.5l1.5 2M15 3.5l-1.5 2M3 13h4M17 13h4M4 8l3 2M20 8l-3 2M4 19l3-2M20 19l-3-2"/>',
    stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
    activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    flask: '<path d="M9 3h6M10 3v6L4.5 18.5A2 2 0 006.2 21.5h11.6a2 2 0 001.7-3L14 9V3"/><path d="M7 15h10"/>',
    monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    arrowIn: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
    arrowOut: '<path d="M5 12h14M13 6l6 6-6 6"/>',
    ear: '<path d="M6 8.5a6 6 0 1112 0c0 3.5-3 4.5-3 7.5a3 3 0 01-6 0"/><path d="M10 8.5a2 2 0 114 0"/>',
    terminal: '<path d="M4 17l6-6-6-6M12 19h8"/>',
    mic: '<rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 11a7 7 0 0014 0M12 18v4M8 22h8"/>',
    volume: '<path d="M11 5L6 9H2v6h4l5 4z"/><path d="M15.5 8.5a5 5 0 010 7M19 5a10 10 0 010 14"/>',
    volumeOff: '<path d="M11 5L6 9H2v6h4l5 4z"/><path d="M22 9l-6 6M16 9l6 6"/>',
    send: '<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4z"/>',
  };
  const icon = (n, cls = "") => `<svg class="ic ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n] || ""}</svg>`;
  const hydrateIcons = (root = document) => $$("i[data-icon]", root).forEach((el) => { el.outerHTML = icon(el.dataset.icon); });

  const VERDICT = { gefaehrlich: ["Gefährlich", "bad"], verdaechtig: ["Verdächtig", "warn"], sauber: ["Sauber", "ok"] };
  const LEVEL_ICON = { info: "info", ok: "check", warn: "alert", danger: "zap" };

  function fmtBytes(n) {
    if (!n) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / 1024 ** i).toLocaleString("de-DE", { maximumFractionDigits: i ? 1 : 0 })} ${u[i]}`;
  }
  function fmtDur(s) {
    s = Math.round(s || 0);
    if (s < 60) return `${s} s`;
    if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
    return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
  }
  function fmtDate(ts) {
    if (!ts) return "–";
    return new Date(ts * 1000).toLocaleString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function fmtClock(ts) { return new Date(ts * 1000).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }); }
  function relTime(ts) {
    if (!ts) return "noch nie";
    const d = Date.now() / 1000 - ts;
    if (d < 60) return "gerade eben";
    if (d < 3600) return `vor ${Math.floor(d / 60)} min`;
    if (d < 86400) return `vor ${Math.floor(d / 3600)} h`;
    if (d < 172800) return "gestern";
    return `vor ${Math.floor(d / 86400)} Tagen`;
  }
  const setText = (id, v) => { const el = document.getElementById(id); if (el && el.textContent !== String(v)) el.textContent = v; };

  // ------------------------------------------------------------------ Anmeldung
  let token = null;
  try {
    const m = location.hash.match(/t=([\w-]+)/);
    if (m) {
      token = m[1];
      sessionStorage.setItem("ss-token", token);
      history.replaceState(null, "", location.pathname + "#/uebersicht");
    } else {
      token = sessionStorage.getItem("ss-token");
    }
  } catch {
    const m = location.hash.match(/t=([\w-]+)/);
    token = m ? m[1] : null;
  }

  // ------------------------------------------------------------------ API
  const S = {
    page: "uebersicht", status: null, lastEvent: -1, events: [], threats: [], scan: null,
    net: null, netFilter: "wichtig", netSearch: "", procs: null, procFilter: "alle", procSort: "risk", procSearch: "",
    logFilter: "alle", settings: null, wasScanning: false, offline: false,
  };
  const LISTENERS = [];

  async function api(path, body) {
    const opts = { method: body === undefined ? "GET" : "POST", headers: { "X-Schutzschild-Token": token || "" } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch {
      setOffline(true);
      throw new Error("Keine Verbindung zu Schutzschild");
    }
    setOffline(false);
    let data = {};
    try { data = await res.json(); } catch { /* leer */ }
    if (res.status === 401) {
      setOffline(true, "Bitte über das Startprogramm öffnen",
        "Diese Seite hat keine gültige Anmeldung. Schließe sie und starte Schutzschild neu – das Programm öffnet die Oberfläche automatisch.");
      throw new Error(data.error || "Nicht angemeldet");
    }
    if (!res.ok) throw new Error(data.error || `Fehler ${res.status}`);
    return data;
  }

  function setOffline(on, title, text) {
    S.offline = on;
    $("#offline").hidden = !on;
    if (on && title) { setText("offline-title", title); setText("offline-text", text); }
  }

  // ------------------------------------------------------------------ Toasts & Dialoge
  function toast(level, title, text = "", ms) {
    const el = document.createElement("div");
    el.className = `toast ${level}`;
    el.innerHTML = `<span class="t-icon">${icon(LEVEL_ICON[level] || "info")}</span><div><b>${esc(title)}</b>${text ? `<small>${esc(text)}</small>` : ""}</div>
      <button class="x-btn" type="button" aria-label="Schließen">${icon("x")}</button>`;
    const box = $("#toasts");
    box.prepend(el);
    while (box.children.length > 5) box.lastChild.remove();
    const close = () => { el.classList.add("out"); setTimeout(() => el.remove(), 260); };
    $(".x-btn", el).onclick = close;
    setTimeout(close, ms || (level === "danger" ? 12000 : 6000));
  }

  function notifyDesktop(title, body) {
    try {
      if (S.status?.modules?.notifications && "Notification" in window && Notification.permission === "granted" && document.hidden) {
        new Notification(title, { body, icon: "icon.svg" });
      }
    } catch { /* nicht unterstützt */ }
  }

  function modal({ title, body = "", icon: ic = "info", danger = false, confirm = "OK", cancel = "Abbrechen", checks = [] }) {
    return new Promise((resolve) => {
      const root = $("#modal-root");
      const checksHtml = checks.length ? `<div class="modal-checks">${checks.map((c) => `
        <label class="${c.disabled ? "disabled" : ""}"><input type="checkbox" data-k="${esc(c.key)}" ${c.checked ? "checked" : ""} ${c.disabled ? "disabled" : ""}>
        <span><b>${esc(c.label)}</b>${c.hint ? `<small>${esc(c.hint)}</small>` : ""}</span></label>`).join("")}</div>` : "";
      root.innerHTML = `<div class="modal-backdrop"><div class="modal ${danger ? "danger" : ""}" role="dialog" aria-modal="true">
        <div class="modal-head"><span class="m-icon">${icon(ic)}</span><h2>${esc(title)}</h2></div>
        <div class="modal-body">${body}</div>${checksHtml}
        <div class="modal-foot">${cancel ? `<button class="btn ghost" type="button" data-r="0">${esc(cancel)}</button>` : ""}
        <button class="btn ${danger ? "danger" : "primary"}" type="button" data-r="1">${esc(confirm)}</button></div></div></div>`;
      const done = (ok) => {
        const values = {};
        $$("input[data-k]", root).forEach((i) => { values[i.dataset.k] = i.checked; });
        root.innerHTML = "";
        document.removeEventListener("keydown", onKey);
        resolve({ ok, values });
      };
      const onKey = (e) => { if (e.key === "Escape") done(false); };
      document.addEventListener("keydown", onKey);
      $$("[data-r]", root).forEach((b) => { b.onclick = () => done(b.dataset.r === "1"); });
      $(".modal-backdrop", root).addEventListener("click", (e) => { if (e.target.classList.contains("modal-backdrop")) done(false); });
      $('[data-r="1"]', root).focus();
    });
  }

  async function run(btn, fn) {
    if (btn) { btn.disabled = true; btn.dataset.html = btn.innerHTML; btn.innerHTML = `${icon("refresh", "spin")}Bitte warten …`; }
    try { return await fn(); }
    catch (e) { toast("warn", "Das hat nicht geklappt", e.message); return null; }
    finally { if (btn && btn.isConnected) { btn.disabled = false; btn.innerHTML = btn.dataset.html; } }
  }

  // ------------------------------------------------------------------ Navigation
  const TITLES = {
    uebersicht: ["Übersicht", "Dein Schutz auf einen Blick"],
    scanner: ["Virenscan", "Dateien auf Schadsoftware prüfen"],
    abwehr: ["Hacker-Abwehr", "Wer ist mit deinem Computer verbunden?"],
    prozesse: ["Prozesse", "Was läuft gerade auf deinem Computer?"],
    quarantaene: ["Quarantäne", "Sicher weggesperrte Dateien"],
    protokoll: ["Protokoll", "Alles, was Schutzschild getan hat"],
    einstellungen: ["Einstellungen", "Schutz nach deinen Wünschen einstellen"],
  };

  function route() {
    const page = (location.hash.match(/^#\/(\w+)/) || [])[1];
    S.page = TITLES[page] ? page : "uebersicht";
    $$(".page").forEach((p) => { p.hidden = p.dataset.page !== S.page; });
    $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === S.page));
    setText("page-title", TITLES[S.page][0]);
    setText("page-sub", TITLES[S.page][1]);
    loadPage();
  }

  function loadPage() {
    const p = S.page;
    if (p === "uebersicht") { if (S.status) renderDashboard(S.status); loadEvents(); }
    if (p === "scanner") { loadScan(); loadThreats(); }
    if (p === "abwehr") loadNet();
    if (p === "prozesse") loadProcs();
    if (p === "quarantaene") loadQuarantine();
    if (p === "protokoll") loadEvents();
    if (p === "einstellungen") loadSettings();
  }

  // ------------------------------------------------------------------ Status-Schleife
  function shouldToast(e) {
    if (e.level === "info") return false;
    if (e.category === "Echtzeitschutz") return true;
    if (e.category === "Prozesse") return e.level === "danger";
    if (e.category === "Hacker-Abwehr") return !/^(Rauswurf|Panik)/.test(e.message);
    if (e.category === "Scan") return /(gefunden|keine Bedrohungen)/.test(e.message);
    if (e.category === "System" || e.category === "Wächter") return e.level !== "ok";
    return false;
  }

  async function tick() {
    try {
      const st = await api(`/api/status?since=${S.lastEvent}`);
      const prev = S.status;
      S.status = st;
      if (S.lastEvent >= 0 && st.events.length) {
        S.events = [...st.events.slice().reverse(), ...S.events].slice(0, 400);
        for (const e of st.events) {
          if (!shouldToast(e)) continue;
          toast(e.level, e.message, e.detail);
          if (e.level === "danger") notifyDesktop("Schutzschild: " + e.message, e.detail || "");
        }
        for (const fn of LISTENERS) { try { fn(st.events); } catch { /* Zuhörer-Fehler ignorieren */ } }
        if (S.page === "protokoll") renderLog();
        if (S.page === "uebersicht") renderDashEvents();
        if (S.page === "scanner" && st.events.some((e) => e.category === "Echtzeitschutz")) loadThreats();
        if (S.page === "quarantaene" && st.events.some((e) => /Quarant/.test(e.category + e.message))) loadQuarantine();
      }
      S.lastEvent = st.last_event_id;
      renderChrome(st);
      if (S.page === "uebersicht") renderDashboard(st);
      const scanning = st.scan.running;
      if (S.page === "scanner" && (scanning || S.wasScanning)) { loadScan(); if (!scanning) loadThreats(); }
      S.wasScanning = scanning;
      if (prev && prev.counts.threats.total !== st.counts.threats.total && S.page === "scanner" && !scanning) loadThreats();
    } catch { /* Offline-Hinweis wird in api() angezeigt */ }
    setTimeout(tick, S.status?.scan?.running && S.page === "scanner" ? 1000 : 2000);
  }

  function renderChrome(st) {
    setText("version", "v" + st.app.version);
    const p = st.protection;
    const mini = $("#mini-status");
    mini.dataset.level = p.level;
    setText("mini-title", p.title);
    setText("mini-sub", st.scan.running ? `${st.scan.label} läuft … ${Math.round(st.scan.progress)} %` : `Sicherheits-Score ${p.score}/100`);
    const chip = $("#admin-chip");
    if (chip.dataset.admin === String(st.app.admin)) { /* unverändert */ } else if (st.app.admin) {
      chip.className = "chip-btn admin";
      chip.innerHTML = `${icon("shield")}Administrator`;
      chip.title = "Alle Schutzfunktionen verfügbar";
    } else {
      chip.className = "chip-btn user";
      chip.innerHTML = `${icon("lock")}Eingeschränkt`;
      chip.title = "Klicke hier, um als Administrator neu zu starten";
    }
    chip.dataset.admin = String(st.app.admin);
    const badge = (id, n, cls = "") => { const b = $(id); b.hidden = !n; b.textContent = n; b.className = `badge ${cls}`; };
    const t = st.counts.threats;
    badge("#badge-threats", t.total, t.gefaehrlich ? "" : "warn");
    badge("#badge-net", st.network.dangerous || st.network.suspicious, st.network.dangerous ? "" : "warn");
    badge("#badge-procs", st.processes.dangerous, "");
    badge("#badge-q", st.counts.quarantine, "soft");
    $$("input[data-setting]").forEach((i) => {
      const k = i.dataset.setting;
      if (k in st.modules && document.activeElement !== i) i.checked = !!st.modules[k];
    });
  }

  // ------------------------------------------------------------------ Übersicht
  function renderDashboard(st) {
    const p = st.protection;
    $("#hero").dataset.level = p.level;
    setText("hero-title", p.title);
    const hints = p.hints.length ? p.hints : ["Alle Schutzmodule sind aktiv", "Keine Bedrohungen gefunden"];
    const html = hints.slice(0, 4).map((h) => `<li>${icon(p.hints.length ? "alert" : "check")}${esc(h)}</li>`).join("");
    const ul = $("#hero-hints");
    if (ul.dataset.html !== html) { ul.innerHTML = html; ul.dataset.html = html; }
    setText("score-num", p.score);
    $("#score-bar").style.strokeDashoffset = String(326.7 * (1 - p.score / 100));

    const t = st.counts.threats;
    setText("t-threats", t.total);
    $("#tile-threats").className = "tile" + (t.gefaehrlich ? " alert" : t.total ? " caution" : "");
    setText("t-quarantine", st.counts.quarantine);
    const n = st.network;
    setText("t-conns", n.time ? n.established : "–");
    setText("t-conns-sub", n.time ? `Verbindungen, ${n.internet} davon ins Internet` : "Wächter startet …");
    $("#tile-net").className = "tile" + (n.dangerous ? " alert" : n.suspicious ? " caution" : "");
    setText("t-blocked", st.counts.blocked);
    setText("t-sigs", num(st.counts.signatures));
    setText("t-sigs-sub", `Signaturen + ${st.counts.rules} Verhaltensregeln`);
    const last = st.history[0];
    setText("t-last", last ? relTime(last.started) : "noch nie");
    setText("t-last-sub", last ? `${last.label} · ${num(last.files)} Dateien` : "Letzter Scan");

    if (st.system.cpu !== undefined) {
      setText("m-cpu", `${Math.round(st.system.cpu)} %`);
      setText("m-ram", `${Math.round(st.system.ram)} % von ${fmtBytes(st.system.ram_total)}`);
      const cb = $("#m-cpu-bar"), rb = $("#m-ram-bar");
      cb.style.width = `${st.system.cpu}%`; cb.classList.toggle("hot", st.system.cpu > 85);
      rb.style.width = `${st.system.ram}%`; rb.classList.toggle("hot", st.system.ram > 90);
    }
    setText("sys-platform", st.app.platform);
    const facts = `<dt>Rechte</dt><dd>${st.app.admin ? "Administrator ✓" : "Normaler Benutzer"}</dd>
      <dt>Prozesse</dt><dd>${st.processes.total ? num(st.processes.total) + " laufen" : "–"}</dd>
      <dt>Läuft seit</dt><dd>${fmtDur(st.app.uptime)}</dd>`;
    const dl = $("#sys-facts");
    if (dl.dataset.html !== facts) { dl.innerHTML = facts; dl.dataset.html = facts; }
  }

  async function loadEvents() {
    try {
      const d = await api("/api/events");
      S.events = d.events;
      renderDashEvents();
      renderLog();
    } catch { /* egal */ }
  }

  const eventItem = (e) => `<li class="lv-${esc(e.level)}"><span class="tl-icon">${icon(LEVEL_ICON[e.level] || "info")}</span>
    <div class="tl-body"><b>${esc(e.message)}</b>${e.detail ? `<small>${esc(e.detail)}</small>` : ""}</div>
    <div class="tl-meta"><span>${esc(e.category)}</span><span>${e.ts ? fmtClock(e.ts) : ""}</span></div></li>`;

  function renderDashEvents() {
    const items = S.events.slice(0, 6);
    $("#dash-events").innerHTML = items.length ? items.map(eventItem).join("") : `<li class="empty">Noch keine Ereignisse.</li>`;
  }

  // ------------------------------------------------------------------ Scanner
  async function startScan(mode, path) {
    const res = await run(null, () => api("/api/scan/start", { mode, path }));
    if (!res) return;
    toast("info", `${res.label} gestartet`, "Du kannst nebenbei weiterarbeiten.");
    S.wasScanning = true;
    if (S.page !== "scanner") location.hash = "#/scanner"; else renderScan(res);
  }

  async function loadScan() {
    try { renderScan(await api("/api/scan")); } catch { /* egal */ }
  }

  function renderScan(sc) {
    S.scan = sc;
    const live = $("#scan-live");
    live.hidden = !sc.running;
    $$("[data-scan]").forEach((b) => { b.disabled = sc.running; });
    if (!sc.running) return;
    setText("scan-label", sc.label);
    setText("scan-phase", sc.phase === "sammeln" ? `Dateien werden gesammelt … (${num(sc.files_total)})` : "Dateien werden geprüft …");
    setText("scan-current", sc.current || "");
    setText("scan-pct", Math.floor(sc.progress));
    $("#scan-bar").style.strokeDashoffset = String(552.9 * (1 - sc.progress / 100));
    setText("scan-files", `${num(sc.files_done)} / ${num(sc.files_total)}`);
    setText("scan-threats", sc.threat_count);
    setText("scan-speed", num(sc.speed));
    setText("scan-time", fmtDur(sc.elapsed));
  }

  async function loadThreats() {
    try {
      const d = await api("/api/threats");
      S.threats = d.threats;
      renderThreats();
    } catch { /* egal */ }
  }

  const STATUS_LABEL = { quarantaene: ["In Quarantäne", "ok"], geloescht: ["Gelöscht", "ok"], ignoriert: ["Vertraut", "mute"], entfernt: ["Entfernt", "ok"] };

  function renderThreats() {
    const list = $("#threat-list");
    const open = S.threats.filter((t) => t.status === "offen");
    $("#quarantine-all").hidden = !open.some((t) => t.type === "file");
    if (!S.threats.length) {
      const last = S.status?.history?.[0];
      list.innerHTML = `<div class="empty-state"><div class="big-ic">${icon("shield")}</div><b>Alles sauber!</b>
        <span>${last ? `Letzter Scan ${esc(relTime(last.started))}: ${num(last.files)} Dateien geprüft, nichts gefunden.` : "Starte einen Scan, um deinen Computer zu prüfen."}</span></div>`;
      return;
    }
    list.innerHTML = S.threats.map((t) => {
      const [vLabel, vCls] = VERDICT[t.verdict] || VERDICT.verdaechtig;
      const done = t.status !== "offen";
      const reasons = t.reasons.slice(0, 5).map((r) => `<li><span class="fam">${esc(r.family)}</span>${esc(r.text)}${r.snippet ? ` <code>${esc(r.snippet)}</code>` : ""}</li>`).join("");
      let actions;
      if (done) {
        const [l, c] = STATUS_LABEL[t.status] || [t.status, "mute"];
        actions = `<span class="pill ${c}">${icon("check")}${esc(l)}</span>`;
      } else if (t.type === "autostart") {
        actions = `<button class="btn danger xs" data-act="remove" data-id="${esc(t.id)}">${icon("trash")}Eintrag entfernen</button>
          <button class="btn ghost xs" data-act="ignore" data-id="${esc(t.id)}">${icon("check")}Vertrauen</button>`;
      } else {
        actions = `<button class="btn primary xs" data-act="quarantine" data-id="${esc(t.id)}">${icon("box")}Quarantäne</button>
          <button class="btn ghost xs" data-act="delete" data-id="${esc(t.id)}">${icon("trash")}Löschen</button>
          <button class="btn ghost xs" data-act="ignore" data-id="${esc(t.id)}">${icon("check")}Vertrauen</button>`;
      }
      const meta = [t.source, fmtDate(t.found), t.size ? fmtBytes(t.size) : "", t.message].filter(Boolean).map(esc).join(" · ");
      return `<div class="threat ${done ? "done" : vCls === "bad" ? "bad" : ""}">
        <div class="threat-icon">${icon(t.type === "autostart" ? "power" : vCls === "bad" ? "bug" : "alert")}</div>
        <div><div class="threat-title">${esc(t.name)} <span class="pill ${done ? "mute" : vCls}">${vLabel} · ${t.score}</span></div>
          <div class="threat-path">${esc(t.command || t.path)}</div><ul class="reasons">${reasons}</ul><div class="threat-meta">${meta}</div></div>
        <div class="threat-actions">${actions}</div></div>`;
    }).join("");
  }

  async function threatAction(id, action, btn) {
    const t = S.threats.find((x) => x.id === id);
    if (!t) return;
    if (action === "delete") {
      const r = await modal({ title: "Endgültig löschen?", icon: "trash", danger: true, confirm: "Löschen",
        body: `<p><b>${esc(t.name)}</b> wird unwiderruflich gelöscht. Sicherer ist die Quarantäne – dort kannst du sie notfalls zurückholen.</p>` });
      if (!r.ok) return;
    }
    if (action === "ignore") {
      const r = await modal({ title: "Datei vertrauen?", icon: "check", confirm: "Ja, ich vertraue ihr",
        body: `<p>Schutzschild meldet <b>${esc(t.name)}</b> dann nie wieder. Mach das nur, wenn du dir sicher bist, dass die Datei harmlos ist.</p>` });
      if (!r.ok) return;
    }
    if (action === "remove") {
      const r = await modal({ title: "Autostart-Eintrag entfernen?", icon: "power", danger: true, confirm: "Entfernen",
        body: `<p>Der Eintrag <b>${esc(t.name)}</b> startet dann nicht mehr automatisch mit Windows:</p><p class="mono">${esc(t.command || "")}</p>` });
      if (!r.ok) return;
    }
    const res = await run(btn, () => api("/api/threat", { id, action }));
    if (res) toast(res.ok ? "ok" : "warn", res.ok ? "Erledigt" : "Nicht möglich", res.message);
    loadThreats();
  }

  // ------------------------------------------------------------------ Hacker-Abwehr
  async function loadNet() {
    try {
      S.net = await api("/api/network");
      renderNet();
    } catch { /* egal */ }
  }

  function netMatches(c) {
    const f = S.netFilter;
    if (f === "gefahr" && c.score < 30) return false;
    if (f === "internet" && c.kind !== "internet") return false;
    if (f === "lauscht" && c.direction !== "lauscht") return false;
    if (f === "wichtig" && !(c.score >= 30 || c.remote_session || (c.status_raw === "ESTABLISHED" && c.kind !== "lokal") ||
      (c.direction === "lauscht" && !["lokal", ""].includes(c.kind)))) return false;
    const q = S.netSearch.trim().toLowerCase();
    if (q && !`${c.process} ${c.pid} ${c.remote} ${c.local} ${c.exe}`.toLowerCase().includes(q)) return false;
    return true;
  }

  const KIND = { internet: ["Internet", "info"], heimnetz: ["Heimnetz", "mute"], lokal: ["Lokal", "mute"], alle: ["Alle Netze", "warn"] };

  const riskClass = (x) => (x.verdict === "gefaehrlich" ? "bad" : x.verdict === "verdaechtig" ? "warn" : x.score > 0 ? "low" : "");

  function hashAngle(s) { let h = 0; for (const ch of s) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return h % 360; }

  function renderNet() {
    const d = S.net;
    if (!d) return;
    const hero = $("#net-hero");
    const sum = d.summary;
    if (!d.available) {
      hero.dataset.level = "warn";
      setText("net-title", "Hacker-Abwehr nicht verfügbar");
      setText("net-sub", "Das Modul „psutil“ fehlt. Installiere es mit: pip install psutil – und starte Schutzschild neu.");
      return;
    }
    hero.dataset.level = sum.dangerous ? "bad" : sum.suspicious || sum.remote_sessions ? "warn" : "ok";
    setText("net-title", sum.dangerous ? `${sum.dangerous} gefährliche Verbindung${sum.dangerous > 1 ? "en" : ""} entdeckt!`
      : sum.remote_sessions ? "Fernwartung aktiv – ist das gewollt?"
        : sum.suspicious ? "Verdächtige Verbindungen gefunden" : "Keine Eindringlinge entdeckt");
    setText("net-sub", sum.dangerous ? "Wirf sie mit einem Klick raus – Schutzschild sperrt die IP und beendet das Programm dahinter."
      : `Zuletzt geprüft um ${fmtClock(sum.time)} · Der Wächter schaut alle paar Sekunden nach.`);
    setText("ns-est", num(sum.established));
    setText("ns-net", num(sum.internet));
    setText("ns-listen", num(sum.listening));
    setText("ns-bad", num(sum.dangerous));
    $("#kick-all").disabled = !sum.dangerous;
    const note = $("#net-admin-note");
    note.hidden = d.admin;
    if (!d.admin) {
      note.innerHTML = `${icon("lock")} Ohne Administratorrechte kann Schutzschild Programme beenden, aber keine IPs in der Firewall sperren und keine Verbindungen kappen.
        ${S.status?.app?.windows ? `<button class="btn ghost xs" type="button" data-elevate>Als Administrator neu starten</button>` : ""}`;
    }
    setText("fw-backend", { "windows-firewall": "Windows-Firewall", iptables: "iptables", "blackhole-route": "Blackhole-Route", keins: "keine Firewall" }[d.firewall] || "");

    // Radar
    const dots = d.connections.filter((c) => c.kind !== "lokal" && (c.status_raw === "ESTABLISHED" || c.score >= 30)).slice(0, 40);
    $("#radar-dots").innerHTML = dots.map((c) => {
      const a = (hashAngle(c.remote_ip || c.local) * Math.PI) / 180;
      const r = c.kind === "internet" ? 40 : c.kind === "heimnetz" ? 27 : 18;
      const cls = c.verdict === "gefaehrlich" ? "bad" : c.verdict === "verdaechtig" ? "warn" : "";
      return `<span class="${cls}" style="left:${50 + r * Math.cos(a)}%;top:${50 + r * Math.sin(a)}%" title="${esc(c.process)} ${esc(c.remote || c.local)}"></span>`;
    }).join("");

    // Tabelle
    const rows = d.connections.filter(netMatches);
    $("#net-table").hidden = !rows.length;
    const empty = $("#net-empty");
    empty.hidden = !!rows.length;
    empty.textContent = S.netFilter === "gefahr" ? "Keine verdächtigen Verbindungen – sehr gut!" : "Keine passenden Verbindungen.";
    $("#net-table tbody").innerHTML = rows.slice(0, 300).map((c) => {
      const cls = riskClass(c);
      const [kl, kc] = KIND[c.kind] || [c.kind, "mute"];
      const dir = c.direction === "eingehend" ? `<span class="dir in">${icon("arrowIn")}Eingehend</span>`
        : c.direction === "ausgehend" ? `<span class="dir">${icon("arrowOut")}Ausgehend</span>` : `<span class="dir">${icon("ear")}Lauscht</span>`;
      const peer = c.remote ? `<span class="mono">${esc(c.remote)}</span> <span class="pill ${kc}">${esc(kl)}</span>${c.blocked ? ` <span class="pill bad">gesperrt</span>` : ""}`
        : `<span class="mono">${esc(c.local)}</span> <span class="pill ${kc}">${esc(kl)}</span>`;
      const reasons = c.score > 0 && c.reasons.length ? `<div class="cell-reasons">${c.reasons.map((r) => `<span>${esc(r)}</span>`).join("")}</div>` : "";
      const canKick = !c.self && (c.score >= 30 || c.remote_session || (c.remote_ip && c.kind !== "lokal"));
      const btn = !canKick ? "" : c.score >= 30 || c.remote_session
        ? `<button class="btn danger xs" data-kick="${esc(c.id)}">${icon("kick")}Rauswerfen</button>`
        : `<button class="btn ghost xs icon-only" data-kick="${esc(c.id)}" title="Rauswerfen" aria-label="Rauswerfen">${icon("kick")}</button>`;
      return `<tr class="${cls === "bad" || cls === "warn" ? "row-" + cls : ""}"><td><div class="risk ${cls}">${c.score}</div></td>
        <td class="cell-main"><b>${esc(c.process)}</b> <span class="muted small">PID ${c.pid}</span>${c.exe ? `<small>${esc(c.exe)}</small>` : ""}${reasons}</td>
        <td>${dir}<div class="muted small">${esc(c.proto)}</div></td><td>${peer}</td><td>${esc(c.status)}</td><td class="actions-cell">${btn}</td></tr>`;
    }).join("");

    // Sperrliste
    $("#block-list").innerHTML = d.blocked.length ? d.blocked.map((b) => `<li><span class="tr-icon">${icon("ban")}</span>
      <div><b>${esc(b.ip)}</b> <span class="pill ${b.applied ? "ok" : "warn"}">${b.applied ? "Firewall aktiv" : "Nur Liste"}</span>
      <small>${esc(b.reason)} · ${fmtDate(b.date)}</small></div>
      <button class="x-btn" type="button" title="Sperre aufheben" data-unblock="${esc(b.ip)}">${icon("x")}</button></li>`).join("")
      : `<li class="muted small">Noch keine IP gesperrt.</li>`;
  }

  async function kick(c, btn) {
    const admin = S.net?.admin;
    const canBlock = !!c.remote_ip && ["internet", "heimnetz"].includes(c.kind);
    const reasons = c.reasons.length ? `<ul class="hint-list">${c.reasons.map((r) => `<li>${icon("alert")}${esc(r)}</li>`).join("")}</ul>` : "";
    const r = await modal({
      title: "Eindringling rauswerfen", icon: "kick", danger: true, confirm: "Jetzt rauswerfen",
      body: `<p>Programm: <b>${esc(c.process)}</b> (PID ${c.pid})<br>Verbindung: <span class="mono">${esc(c.local)}</span>${c.remote ? ` ↔ <span class="mono">${esc(c.remote)}</span>` : ""}</p>${reasons}
        ${admin ? "" : `<p class="notice">Ohne Administratorrechte kann nur das Programm beendet werden.</p>`}`,
      checks: [
        { key: "block", label: "IP-Adresse dauerhaft sperren", checked: canBlock, disabled: !canBlock,
          hint: canBlock ? `${c.remote_ip} kommt nicht mehr durch die Firewall` : "Keine fremde IP-Adresse vorhanden" },
        { key: "kill", label: `Programm „${c.process}“ beenden`, checked: !c.protected, disabled: c.protected,
          hint: c.protected ? `Geschützt: ${c.protected_reason}` : "Beendet auch alle Unterprozesse" },
      ],
    });
    if (!r.ok) return;
    const res = await run(btn, () => api("/api/network/kick", { ...c, block: !!r.values.block, kill: !!r.values.kill }));
    if (!res) return;
    await modal({
      title: res.ok ? "Rausgeworfen! 💥" : "Nur teilweise geklappt", icon: res.ok ? "check" : "alert", cancel: null, confirm: "Alles klar",
      body: `<ul class="step-list">${res.steps.map((s) => `<li>${icon(s.ok ? "check" : "x", s.ok ? "yes" : "no")}<span><b>${esc(s.step)}</b><br>${esc(s.message)}</span></li>`).join("")}</ul>`,
    });
    loadNet();
  }

  async function kickAll(btn) {
    const n = S.net?.summary?.dangerous || 0;
    const r = await modal({ title: "Alle Eindringlinge rauswerfen?", icon: "zap", danger: true, confirm: "Alle rauswerfen",
      body: `<p>Schutzschild trennt <b>${n} gefährliche Verbindung${n === 1 ? "" : "en"}</b>, sperrt die IP-Adressen und beendet die Programme dahinter (außer geschützte Systemprozesse).</p>` });
    if (!r.ok) return;
    const res = await run(btn, () => api("/api/network/kick_all", {}));
    if (!res) return;
    const ok = res.results.filter((x) => x.ok).length;
    toast(ok ? "ok" : "warn", res.count ? `${ok} von ${res.count} Eindringlingen rausgeworfen` : "Keine gefährlichen Verbindungen mehr", "Details stehen im Protokoll.");
    loadNet();
  }

  // ------------------------------------------------------------------ Prozesse
  async function loadProcs() {
    try { S.procs = await api("/api/processes"); renderProcs(); } catch { /* egal */ }
  }

  function renderProcs() {
    const d = S.procs;
    if (!d) return;
    if (!d.available) { $("#proc-empty").hidden = false; $("#proc-empty").textContent = "Das Modul „psutil“ fehlt – installiere es mit: pip install psutil"; return; }
    setText("proc-head", `Laufende Programme (${d.summary.total})`);
    const q = S.procSearch.trim().toLowerCase();
    let rows = d.processes.filter((p) => (S.procFilter !== "gefahr" || p.score >= 30) &&
      (!q || `${p.name} ${p.pid} ${p.exe} ${p.cmdline}`.toLowerCase().includes(q)));
    const sorters = { risk: (a, b) => b.score - a.score || b.cpu - a.cpu, cpu: (a, b) => b.cpu - a.cpu, mem: (a, b) => b.mem_mb - a.mem_mb,
      name: (a, b) => a.name.localeCompare(b.name, "de") };
    rows = rows.sort(sorters[S.procSort]);
    $("#proc-empty").hidden = !!rows.length;
    $("#proc-empty").textContent = "Keine passenden Prozesse.";
    $("#proc-table tbody").innerHTML = rows.slice(0, 250).map((p) => {
      const cls = riskClass(p);
      const reasons = p.reasons.length ? `<div class="cell-reasons">${p.reasons.slice(0, 4).map((r) => `<span>${esc(r.text)}</span>`).join("")}</div>` : "";
      const acts = p.self ? `<span class="pill info">Schutzschild</span>` : p.protected ? `<span class="pill mute" title="${esc(p.protected_reason)}">${icon("lock")}geschützt</span>`
        : `<button class="btn ${p.score >= 30 ? "danger" : "ghost"} xs" data-pkill="${p.pid}">${icon("x")}Beenden</button>${p.exe && p.score >= 30 ? `<button class="btn ghost xs" data-pq="${p.pid}">${icon("box")}Quarantäne</button>` : ""}`;
      return `<tr class="${cls === "bad" || cls === "warn" ? "row-" + cls : ""}"><td><div class="risk ${cls}">${p.score}</div></td>
        <td class="cell-main"><b>${esc(p.name)}</b> <span class="muted small">PID ${p.pid}</span><small>${esc(p.exe || p.cmdline || "")}</small>${reasons}</td>
        <td class="num">${p.cpu.toLocaleString("de-DE")} %</td><td class="num">${fmtBytes(p.mem_mb * 1048576)}</td>
        <td class="muted small">${esc(p.user)}</td><td class="actions-cell">${acts}</td></tr>`;
    }).join("");
  }

  async function procAction(pid, quarantine, btn) {
    const p = S.procs?.processes.find((x) => x.pid === pid);
    if (!p) return;
    const r = await modal({
      title: quarantine ? "Beenden & in Quarantäne?" : "Programm beenden?", icon: quarantine ? "box" : "x", danger: true,
      confirm: quarantine ? "Beenden & wegsperren" : "Beenden",
      body: `<p><b>${esc(p.name)}</b> (PID ${p.pid}) wird sofort beendet${quarantine ? " und die Programmdatei in Quarantäne gesperrt" : ""}. Nicht gespeicherte Daten in diesem Programm gehen verloren.</p>${p.exe ? `<p class="mono">${esc(p.exe)}</p>` : ""}`,
    });
    if (!r.ok) return;
    const res = await run(btn, () => api(quarantine ? "/api/process/quarantine" : "/api/process/kill", { pid, name: p.name }));
    if (res) toast(res.ok ? "ok" : "warn", res.ok ? "Erledigt" : "Nicht möglich", res.message);
    setTimeout(loadProcs, 400);
  }

  // ------------------------------------------------------------------ Quarantäne
  async function loadQuarantine() {
    try {
      const d = await api("/api/quarantine");
      setText("q-count", d.items.length ? `${d.items.length} Datei${d.items.length > 1 ? "en" : ""}` : "");
      $("#q-list").innerHTML = d.items.length ? d.items.map((q) => `<div class="q-item"><span class="q-icon">${icon("lock")}</span>
        <div><b>${esc(q.name)}</b><small class="mono">${esc(q.original_path)}</small><small>${esc(q.reason)} · ${fmtDate(q.date)} · ${fmtBytes(q.size)}</small></div>
        <div class="btn-row"><button class="btn ghost xs" data-qrestore="${esc(q.id)}">${icon("restore")}Wiederherstellen</button>
        <button class="btn danger xs" data-qdel="${esc(q.id)}">${icon("trash")}Löschen</button></div></div>`).join("")
        : `<div class="empty-state"><div class="big-ic">${icon("box")}</div><b>Die Quarantäne ist leer</b><span>Hier landen gefährliche Dateien, die Schutzschild weggesperrt hat.</span></div>`;
      $("#q-list").dataset.items = JSON.stringify(d.items.map((i) => [i.id, i.name]));
    } catch { /* egal */ }
  }

  async function qAction(id, restore, btn) {
    const name = (JSON.parse($("#q-list").dataset.items || "[]").find((x) => x[0] === id) || [, "Datei"])[1];
    const r = await modal(restore
      ? { title: "Wirklich wiederherstellen?", icon: "restore", danger: true, confirm: "Wiederherstellen",
        body: `<p><b>${esc(name)}</b> wurde als Bedrohung erkannt. Stelle sie nur wieder her, wenn du dir <b>ganz sicher</b> bist, dass sie harmlos ist. Sie wird danach nicht mehr gemeldet.</p>` }
      : { title: "Endgültig löschen?", icon: "trash", danger: true, confirm: "Löschen", body: `<p><b>${esc(name)}</b> wird für immer gelöscht.</p>` });
    if (!r.ok) return;
    const res = await run(btn, () => api(restore ? "/api/quarantine/restore" : "/api/quarantine/delete", { id }));
    if (res) toast("ok", restore ? "Wiederhergestellt" : "Gelöscht", res.message || "");
    loadQuarantine();
  }

  // ------------------------------------------------------------------ Protokoll
  function renderLog() {
    const f = S.logFilter;
    const items = S.events.filter((e) => f === "alle" || e.level === f);
    $("#log-list").innerHTML = items.length ? items.map((e) => eventItem({ ...e, detail: [e.detail, e.ts ? fmtDate(e.ts) : ""].filter(Boolean).join(" · ") })).join("")
      : `<li class="empty">Keine Einträge.</li>`;
  }

  // ------------------------------------------------------------------ Einstellungen
  async function loadSettings() {
    try {
      const d = await api("/api/settings");
      S.settings = d;
      const s = d.settings;
      $("#max-mb").value = s.max_file_mb;
      $("#guard-int").value = s.guard_interval;
      const pathItems = (arr, key) => arr.length ? arr.map((p) => `<li><span>${esc(p)}</span><button class="x-btn" type="button" data-rm="${esc(key)}" data-path="${esc(p)}" title="Entfernen">${icon("x")}</button></li>`).join("")
        : `<li class="muted small">Keine Einträge.</li>`;
      $("#watch-list").innerHTML = pathItems(s.watch_folders, "watch_folders");
      $("#excl-list").innerHTML = pathItems(s.exclusions, "exclusions");
      renderSigStats(d.signatures);
      const st = S.status?.app || {};
      $("#app-facts").innerHTML = `<dt>Version</dt><dd>${esc(st.version || "")}</dd><dt>System</dt><dd>${esc(st.platform || "")}</dd>
        <dt>Rechte</dt><dd>${st.admin ? "Administrator" : "Normaler Benutzer"}</dd><dt>Firewall</dt><dd>${esc(d.firewall)}</dd>
        <dt>Datenordner</dt><dd class="mono">${esc(d.data_dir)}</dd><dt>Vertrauenswürdig</dt><dd>${num(d.trusted)} Dateien</dd>`;
      $("#elevate-btn").hidden = !!st.admin;
    } catch { /* egal */ }
  }

  function renderSigStats(sig) {
    $("#sig-stats").innerHTML = `<div><b>${num(sig.total)}</b><span>Prüfsummen</span></div><div><b>${num(sig.rules)}</b><span>Verhaltensregeln</span></div>
      <div><b>${sig.online_updated ? esc(new Date(sig.online_updated).toLocaleDateString("de-DE")) : "nie"}</b><span>Online-Update</span></div>`;
  }

  async function saveSetting(changes) {
    const res = await run(null, () => api("/api/settings", changes));
    if (res && S.status) Object.assign(S.status.modules, res.settings);
    if (S.page === "einstellungen") loadSettings();
    return res;
  }

  async function editList(key, add, remove) {
    const cur = S.settings?.settings?.[key] || [];
    const next = add ? [...cur, add] : cur.filter((p) => p !== remove);
    const res = await saveSetting({ [key]: next });
    if (res) toast("ok", "Gespeichert", add ? `„${add}“ hinzugefügt` : `„${remove}“ entfernt`);
  }

  // ------------------------------------------------------------------ Ereignisse verdrahten
  function wire() {
    hydrateIcons();
    const theme = () => {
      const t = document.documentElement.dataset.theme;
      $("#theme-btn").innerHTML = icon(t === "dark" ? "sun" : "moon");
    };
    try { const saved = localStorage.getItem("ss-theme"); if (saved) document.documentElement.dataset.theme = saved; } catch { /* egal */ }
    theme();
    $("#theme-btn").onclick = () => {
      const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = t;
      try { localStorage.setItem("ss-theme", t); } catch { /* egal */ }
      theme();
    };

    document.addEventListener("click", async (e) => {
      const b = e.target.closest("button, [data-scan]");
      if (!b) return;
      if (b.dataset.scan) return startScan(b.dataset.scan);
      if (b.dataset.act) return threatAction(b.dataset.id, b.dataset.act, b);
      if (b.dataset.kick) { const c = S.net?.connections.find((x) => x.id === b.dataset.kick); if (c) kick(c, b); return; }
      if (b.dataset.unblock) {
        const res = await run(b, () => api("/api/firewall/unblock", { ip: b.dataset.unblock }));
        if (res) toast("ok", "Sperre aufgehoben", res.ip);
        return loadNet();
      }
      if (b.dataset.pkill) return procAction(Number(b.dataset.pkill), false, b);
      if (b.dataset.pq) return procAction(Number(b.dataset.pq), true, b);
      if (b.dataset.qrestore) return qAction(b.dataset.qrestore, true, b);
      if (b.dataset.qdel) return qAction(b.dataset.qdel, false, b);
      if (b.dataset.rm) return editList(b.dataset.rm, null, b.dataset.path);
      if (b.hasAttribute("data-elevate")) return elevate(b);
    });

    $("#admin-chip").onclick = () => { if (!S.status?.app?.admin) elevate($("#admin-chip")); };
    $("#elevate-btn").onclick = (e) => elevate(e.currentTarget);
    $("#scan-stop").onclick = async () => { await run(null, () => api("/api/scan/stop", {})); toast("info", "Scan wird abgebrochen …"); };
    $("#custom-scan").onsubmit = (e) => { e.preventDefault(); startScan("custom", $("#custom-path").value); };
    $("#quarantine-all").onclick = async (e) => {
      const n = S.threats.filter((t) => t.status === "offen" && t.type === "file").length;
      const r = await modal({ title: `${n} Bedrohung${n > 1 ? "en" : ""} wegsperren?`, icon: "box", confirm: "Alle in Quarantäne",
        body: "<p>Alle offenen Funde werden verschlüsselt in die Quarantäne verschoben. Du kannst sie dort jederzeit wiederherstellen.</p>" });
      if (!r.ok) return;
      const res = await run(e.currentTarget, () => api("/api/threats/all", { action: "quarantine" }));
      if (res) toast(res.ok ? "ok" : "warn", `${res.done} Datei${res.done === 1 ? "" : "en"} in Quarantäne`, res.failed ? `${res.failed} fehlgeschlagen: ${res.messages[0] || ""}` : "");
      loadThreats();
    };
    $("#eicar-btn").onclick = async (e) => {
      const res = await run(e.currentTarget, () => api("/api/eicar", {}));
      if (res) toast("info", "Testvirus erzeugt", res.realtime ? `${res.path} – der Echtzeitschutz sollte in wenigen Sekunden Alarm schlagen.`
        : `${res.path} – starte jetzt einen Schnellscan.`, 9000);
    };

    $("#kick-all").onclick = (e) => kickAll(e.currentTarget);
    $("#net-refresh").onclick = (e) => run(e.currentTarget, loadNet);
    $("#net-filter").onclick = (e) => { const b = e.target.closest("button"); if (!b) return; S.netFilter = b.dataset.f; $$("#net-filter button").forEach((x) => x.classList.toggle("on", x === b)); renderNet(); };
    $("#net-search").oninput = (e) => { S.netSearch = e.target.value; renderNet(); };
    $("#block-form").onsubmit = async (e) => {
      e.preventDefault();
      const ip = $("#block-ip").value.trim();
      if (!ip) return;
      const res = await run(e.submitter, () => api("/api/firewall/block", { ip, reason: $("#block-reason").value.trim() }));
      if (res) { toast(res.applied ? "ok" : "warn", `${res.ip} gesperrt`, res.message); $("#block-ip").value = ""; $("#block-reason").value = ""; }
      loadNet();
    };

    $("#proc-filter").onclick = (e) => { const b = e.target.closest("button"); if (!b) return; S.procFilter = b.dataset.f; $$("#proc-filter button").forEach((x) => x.classList.toggle("on", x === b)); renderProcs(); };
    $("#proc-sort").onchange = (e) => { S.procSort = e.target.value; renderProcs(); };
    $("#proc-search").oninput = (e) => { S.procSearch = e.target.value; renderProcs(); };

    $("#log-filter").onclick = (e) => { const b = e.target.closest("button"); if (!b) return; S.logFilter = b.dataset.f; $$("#log-filter button").forEach((x) => x.classList.toggle("on", x === b)); renderLog(); };
    $("#log-clear").onclick = async () => {
      const r = await modal({ title: "Protokoll leeren?", icon: "trash", danger: true, confirm: "Leeren", body: "<p>Alle Einträge werden gelöscht.</p>" });
      if (!r.ok) return;
      await run(null, () => api("/api/events/clear", {}));
      S.events = [];
      renderLog();
    };

    $$("input[data-setting]").forEach((input) => {
      input.addEventListener("change", async () => {
        const key = input.dataset.setting;
        if (key === "notifications" && input.checked && "Notification" in window && Notification.permission === "default") {
          try { await Notification.requestPermission(); } catch { /* egal */ }
        }
        if (key === "auto_kick" && input.checked) {
          const r = await modal({ title: "Automatischer Rauswurf", icon: "zap", danger: true, confirm: "Einschalten",
            body: "<p>Schutzschild wirft dann <b>gefährliche</b> Verbindungen ohne Rückfrage raus und beendet die Programme dahinter. Normale Programme sind nicht betroffen.</p>" });
          if (!r.ok) { input.checked = false; return; }
        }
        const res = await saveSetting({ [key]: input.checked });
        if (res) {
          $$(`input[data-setting="${key}"]`).forEach((i) => { i.checked = !!res.settings[key]; });
          toast("ok", "Gespeichert", `${input.closest(".toggle-row").querySelector("b").textContent}: ${input.checked ? "an" : "aus"}`, 2500);
        }
      });
    });
    $("#max-mb").onchange = (e) => saveSetting({ max_file_mb: Number(e.target.value) });
    $("#guard-int").onchange = (e) => saveSetting({ guard_interval: Number(e.target.value) });
    $("#watch-form").onsubmit = (e) => { e.preventDefault(); const v = $("#watch-input").value.trim(); if (v) { $("#watch-input").value = ""; editList("watch_folders", v); } };
    $("#excl-form").onsubmit = (e) => { e.preventDefault(); const v = $("#excl-input").value.trim(); if (v) { $("#excl-input").value = ""; editList("exclusions", v); } };
    $("#sig-form").onsubmit = async (e) => {
      e.preventDefault();
      const res = await run(e.submitter, () => api("/api/signatures/add", { hash: $("#sig-hash").value.trim(), name: $("#sig-name").value.trim() }));
      if (res) { toast("ok", "Signatur hinzugefügt"); $("#sig-hash").value = ""; $("#sig-name").value = ""; renderSigStats(res.signatures); }
    };
    $("#sig-update").onclick = async (e) => {
      const res = await run(e.currentTarget, () => api("/api/signatures/update", {}));
      if (res) { toast("ok", `${num(res.added)} neue Signaturen`, `Insgesamt ${num(res.total)} Online-Signaturen`); renderSigStats(res.signatures); }
    };
    $("#quit-btn").onclick = async () => {
      const r = await modal({ title: "Schutzschild beenden?", icon: "power", danger: true, confirm: "Beenden",
        body: "<p>Dein Computer ist dann nicht mehr durch Schutzschild geschützt (Windows Defender läuft natürlich weiter).</p>" });
      if (!r.ok) return;
      await run(null, () => api("/api/shutdown", {}));
      setTimeout(() => setOffline(true, "Schutzschild wurde beendet", "Du kannst dieses Fenster jetzt schließen."), 600);
    };

    window.addEventListener("hashchange", route);
    setInterval(() => {
      if (document.hidden || S.offline) return;
      if (S.page === "abwehr") loadNet();
      if (S.page === "prozesse") loadProcs();
    }, 4000);
  }

  async function elevate(btn) {
    const r = await modal({ title: "Als Administrator neu starten?", icon: "lock", confirm: "Neu starten",
      body: "<p>Mit Administratorrechten kann Schutzschild Angreifer in der Firewall sperren, Verbindungen kappen und geschützte Schädlinge entfernen. Windows fragt gleich nach deiner Erlaubnis.</p>" });
    if (!r.ok) return;
    const res = await run(btn, () => api("/api/elevate", {}));
    if (!res) return;
    if (res.ok) {
      toast("info", "Neustart …", res.message);
      setTimeout(() => setOffline(true, "Schutzschild startet neu", "Gleich öffnet sich ein neues Fenster mit Administratorrechten. Dieses hier kannst du schließen."), 1200);
    } else {
      await modal({ title: "Administratorrechte", icon: "lock", cancel: null, body: `<p>${esc(res.message)}</p>` });
    }
  }

  // ------------------------------------------------------------------ Schnittstelle für Jarvis
  window.Schutzschild = {
    api, icon, esc, toast, modal,
    navigate: (page) => { location.hash = "#/" + page; },
    setTheme: (t) => {
      document.documentElement.dataset.theme = t;
      try { localStorage.setItem("ss-theme", t); } catch { /* egal */ }
      $("#theme-btn").innerHTML = icon(t === "dark" ? "sun" : "moon");
    },
    elevate: () => elevate(null),
    refresh: () => { loadPage(); },
    status: () => S.status,
    onEvents: (fn) => { LISTENERS.push(fn); },
    ready: () => !!token,
  };

  // ------------------------------------------------------------------ Start
  wire();
  if (!token) {
    setOffline(true, "Bitte über das Startprogramm öffnen",
      "Starte Schutzschild mit „start.bat“ (Windows) bzw. „start.sh“ – die Oberfläche öffnet sich dann automatisch.");
    return;
  }
  route();
  tick();
})();
