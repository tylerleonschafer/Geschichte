/* J.A.R.V.I.S. – Sprachassistent von Schutzschild
 *
 * Hören:   Web Speech API des Browsers (Chrome und Edge). Tippen geht überall.
 * Sprechen: Sprachausgabe des Browsers (speechSynthesis), deutsche Stimme.
 * Denken:  Der Schutzschild-Server (/api/jarvis) – läuft lokal auf deinem PC.
 */
"use strict";
(() => {
  const SS = window.Schutzschild;
  if (!SS || !SS.ready()) return;
  const { api, icon, esc, toast } = SS;
  const $ = (s) => document.querySelector(s);
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  const canSpeak = "speechSynthesis" in window;
  const WAKE = /\b(jarvis|jarwis|javis|dschawis|jervis)\b[\s,.!]*/i;

  const store = {
    get(k, d) { try { const v = localStorage.getItem("jarvis-" + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem("jarvis-" + k, JSON.stringify(v)); } catch { /* egal */ } },
  };
  const J = {
    open: false, voice: store.get("voice", true), wake: false, state: "idle", pending: null,
    rec: null, recMode: null, recError: null, voiceObj: null, activated: false, greeted: false,
    busy: false, privacyShown: false, interimEl: null, speakToken: 0,
  };

  const orb = $("#jarvis-orb");
  const panel = $("#jarvis");
  const log = $("#jarvis-log");
  const input = $("#jarvis-text");
  const mic = $("#jarvis-mic");

  // ------------------------------------------------------------------ Anzeige
  function setState(s) {
    J.state = s;
    orb.dataset.state = s;
    panel.dataset.state = s;
    const labels = { listening: "Ich höre zu …", thinking: "Denke nach …", speaking: "Spricht …" };
    $("#jarvis-status").textContent = labels[s] || (J.wake ? "Hört auf „Jarvis“ …" : "Bereit");
  }

  function renderTools() {
    const v = $("#jarvis-voice");
    v.innerHTML = icon(J.voice ? "volume" : "volumeOff");
    v.classList.toggle("on", J.voice);
    v.title = J.voice ? "Sprachausgabe ausschalten" : "Sprachausgabe einschalten";
    const w = $("#jarvis-wake");
    w.innerHTML = icon("ear");
    w.hidden = !SR;
    w.classList.toggle("on", J.wake);
    w.title = J.wake ? "Nicht mehr auf „Jarvis“ hören" : "Ständig auf „Jarvis“ hören";
    $("#jarvis-close").innerHTML = icon("x");
    mic.innerHTML = icon("mic");
    mic.disabled = !SR;
    mic.title = SR ? "Sprechen (Alt+J)" : "Spracheingabe gibt es in Chrome und Edge – tippen geht immer";
    $(".jarvis-send").innerHTML = icon("send");
    orb.classList.toggle("wake", J.wake);
    setState(J.state);
  }

  function addMsg(who, text, opts = {}) {
    const el = document.createElement("div");
    el.className = `jmsg ${who} ${opts.mood || ""}`;
    const items = opts.items && opts.items.length ? `<ul>${opts.items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>` : "";
    const confirm = opts.confirm ? `<div class="jconfirm"><button type="button" class="btn ${opts.mood === "danger" ? "danger" : "primary"} xs" data-j="Ja">Ja</button>
      <button type="button" class="btn ghost xs" data-j="Nein">Nein</button></div>` : "";
    el.innerHTML = esc(text) + items + confirm;
    log.appendChild(el);
    while (log.children.length > 80) log.firstChild.remove();
    log.scrollTop = log.scrollHeight;
    return el;
  }

  function showInterim(text) {
    if (!J.interimEl) J.interimEl = addMsg("user interim", "");
    J.interimEl.textContent = text || "…";
    log.scrollTop = log.scrollHeight;
  }
  function clearInterim() { if (J.interimEl) { J.interimEl.remove(); J.interimEl = null; } }
  function closeConfirms() { log.querySelectorAll(".jconfirm").forEach((c) => c.remove()); }

  // ------------------------------------------------------------------ Sprechen
  const VOICE_PREFS = [/conrad/i, /killian/i, /florian/i, /stefan/i, /markus/i, /yannick/i, /google deutsch/i, /de-de/i];
  function pickVoice() {
    if (!canSpeak) return null;
    const voices = speechSynthesis.getVoices().filter((v) => /^de([-_]|$)/i.test(v.lang));
    for (const p of VOICE_PREFS) { const v = voices.find((x) => p.test(x.name)); if (v) return v; }
    return voices[0] || null;
  }
  if (canSpeak) {
    J.voiceObj = pickVoice();
    speechSynthesis.addEventListener?.("voiceschanged", () => { J.voiceObj = pickVoice(); });
  }

  const speakable = (t) => String(t)
    .replace(/J\.A\.R\.V\.I\.S\./g, "Jarvis").replace(/\bz\. ?B\./g, "zum Beispiel")
    .replace(/\(PID \d+\)|PID \d+/g, "").replace(/[„“"•✓✗→]/g, " ").replace(/↔/g, " mit ").replace(/\s+/g, " ");

  function speak(text, after) {
    const token = ++J.speakToken;
    const finish = (runAfter) => {
      if (token !== J.speakToken) return;
      J.speakToken++;
      setState("idle");
      resumeWake();
      if (runAfter && after) after();
    };
    if (!J.voice || !canSpeak || !text) { finish(true); return; }
    pauseWake();
    speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(speakable(text));
    u.lang = "de-DE";
    if (J.voiceObj) u.voice = J.voiceObj;
    u.rate = 1.04;
    u.pitch = 0.92;
    u.onstart = () => { if (token === J.speakToken) setState("speaking"); };
    u.onend = () => finish(true);
    u.onerror = (e) => finish(!/interrupted|canceled/.test(e.error || ""));
    speechSynthesis.speak(u);
    setTimeout(() => finish(true), 4000 + text.length * 95); // falls der Browser "fertig" nie meldet
  }
  function stopSpeaking() {
    if (!canSpeak) return;
    J.speakToken++;
    speechSynthesis.cancel();
    if (J.state === "speaking") setState("idle");
  }

  // ------------------------------------------------------------------ Hören
  function reportRecError(err) {
    if (!err || err === "aborted") return;
    const msg = {
      "no-speech": "Ich habe nichts gehört. Drück noch mal aufs Mikrofon und sprich einfach los.",
      "not-allowed": "Ich darf das Mikrofon nicht benutzen. Erlaube den Zugriff über das Symbol links in der Adressleiste.",
      "service-not-allowed": "Dein Browser erlaubt hier keine Spracheingabe. Tippen geht aber immer.",
      "audio-capture": "Ich finde kein Mikrofon. Ist eins angeschlossen?",
      network: "Für die Spracherkennung braucht dein Browser eine Internetverbindung. Tippen geht auch ohne.",
    }[err] || `Spracheingabe-Fehler: ${err}`;
    addMsg("bot", msg, { mood: "warn" });
  }

  function privacyNote() {
    if (J.privacyShown) return;
    J.privacyShown = true;
    addMsg("bot", "Hinweis: Die Spracherkennung übernimmt dein Browser. Chrome und Edge schicken die Aufnahme dafür an Google bzw. Microsoft. Getippte Befehle bleiben komplett auf deinem PC.", { mood: "info" });
  }

  function stopRec() {
    const r = J.rec;
    J.rec = null;
    J.recMode = null;
    if (r) { try { r.abort(); } catch { /* egal */ } }
  }

  function listen() {
    if (!SR) {
      toast("info", "Spracheingabe nicht verfügbar", "Sie funktioniert in Chrome und Edge. Tippen geht immer.");
      return;
    }
    if (J.recMode === "command") { const r = J.rec; J.recMode = "stopping"; try { r.stop(); } catch { /* egal */ } return; }
    openPanel(false);
    privacyNote();
    stopSpeaking();
    stopRec();
    J.activated = true;
    const rec = new SR();
    rec.lang = "de-DE";
    rec.interimResults = true;
    rec.continuous = false;
    rec.maxAlternatives = 1;
    let finalText = "";
    rec.onresult = (e) => {
      let interim = "";
      finalText = "";
      for (const r of e.results) { if (r.isFinal) finalText += r[0].transcript; else interim += r[0].transcript; }
      showInterim((finalText + interim).replace(WAKE, ""));
    };
    rec.onerror = (e) => { J.recError = e.error; };
    rec.onend = () => {
      if (J.rec !== rec) return;
      J.rec = null;
      J.recMode = null;
      const text = finalText.replace(WAKE, " ").trim();
      if (text) {
        send(text, { spoken: true });
      } else {
        clearInterim();
        setState("idle");
        reportRecError(J.recError);
        resumeWake();
      }
      J.recError = null;
    };
    J.rec = rec;
    J.recMode = "command";
    setState("listening");
    try { rec.start(); } catch { J.rec = null; J.recMode = null; setState("idle"); }
  }

  // Ständig zuhören: wartet auf das Wort "Jarvis"
  function startWake() {
    if (!J.wake || !SR || J.rec || J.busy || J.state === "speaking") return;
    const rec = new SR();
    rec.lang = "de-DE";
    rec.continuous = true;
    rec.interimResults = false;
    rec.onresult = (e) => {
      for (let i = e.resultIndex; i < e.results.length; i++) {
        if (!e.results[i].isFinal) continue;
        const said = e.results[i][0].transcript;
        const m = said.match(WAKE);
        if (!m) continue;
        const command = said.slice(m.index + m[0].length).trim();
        stopRec();
        openPanel(false);
        if (command.length > 1) send(command, { spoken: true });
        else speak("Ja?", () => listen());
        return;
      }
    };
    rec.onerror = (e) => {
      if (e.error === "not-allowed" || e.error === "service-not-allowed" || e.error === "audio-capture") {
        J.wake = false;
        renderTools();
        reportRecError(e.error);
      }
    };
    rec.onend = () => {
      if (J.rec !== rec) return;
      J.rec = null;
      J.recMode = null;
      setTimeout(startWake, 400);
    };
    J.rec = rec;
    J.recMode = "wake";
    try { rec.start(); } catch { J.rec = null; J.recMode = null; }
  }
  function pauseWake() { if (J.recMode === "wake") stopRec(); }
  function resumeWake() { if (J.wake) setTimeout(startWake, 600); }

  // ------------------------------------------------------------------ Denken (Server fragen)
  function doAction(a) {
    if (!a) return;
    if (a.type === "navigate") SS.navigate(a.page);
    else if (a.type === "theme") SS.setTheme(a.value);
    else if (a.type === "refresh") SS.refresh();
    else if (a.type === "elevate") SS.elevate();
    else if (a.type === "mute" || a.type === "unmute") {
      J.voice = a.type === "unmute";
      store.set("voice", J.voice);
      if (!J.voice) stopSpeaking();
      renderTools();
    }
  }

  async function ask(text, { show = true, spoken = false } = {}) {
    text = (text || "").trim();
    if (!text || J.busy) return;
    J.activated = true;
    clearInterim();
    closeConfirms();
    if (show) addMsg("user", text);
    J.busy = true;
    setState("thinking");
    const typing = addMsg("bot typing", "");
    typing.innerHTML = "<span></span><span></span><span></span>";
    let res;
    try {
      res = await api("/api/jarvis", { text, pending: J.pending });
    } catch (e) {
      res = { reply: `Ich erreiche Schutzschild gerade nicht: ${e.message}`, speak: "Ich erreiche Schutzschild gerade nicht.",
        mood: "warn", items: [], action: null, confirm: null };
    } finally {
      typing.remove();
      J.busy = false;
    }
    J.pending = res.confirm || null;
    addMsg("bot", res.reply, { mood: res.mood, items: res.items, confirm: !!res.confirm });
    doAction(res.action);
    // Hat Jarvis etwas gefragt und du hast gesprochen, hört er danach direkt auf deine Antwort.
    speak(res.speak ?? res.reply, () => { if (res.confirm && spoken && SR) listen(); });
  }
  const send = (text, opts) => ask(text, opts);

  // ------------------------------------------------------------------ Fenster
  function openPanel(greet = true) {
    if (J.open) return;
    J.open = true;
    panel.hidden = false;
    orb.setAttribute("aria-expanded", "true");
    if (!J.greeted) {
      J.greeted = true;
      if (greet) ask("Hallo", { show: false });
      else addMsg("bot", "Hallo! Ich bin Jarvis. Sag „Hilfe“, um zu sehen, was ich kann.");
    }
    setTimeout(() => input.focus(), 60);
  }
  function closePanel() {
    J.open = false;
    panel.hidden = true;
    orb.setAttribute("aria-expanded", "false");
    stopSpeaking();
    if (J.recMode === "command") stopRec();
    clearInterim();
    setState("idle");
  }

  // ------------------------------------------------------------------ Verdrahtung
  orb.addEventListener("click", () => (J.open ? closePanel() : openPanel(true)));
  $("#jarvis-close").addEventListener("click", closePanel);
  mic.addEventListener("click", listen);
  $("#jarvis-voice").addEventListener("click", () => {
    J.voice = !J.voice;
    store.set("voice", J.voice);
    if (!J.voice) stopSpeaking();
    renderTools();
    toast("info", J.voice ? "Jarvis spricht wieder" : "Jarvis ist stumm", J.voice ? "" : "Antworten erscheinen nur noch als Text.", 2500);
  });
  $("#jarvis-wake").addEventListener("click", () => {
    J.wake = !J.wake;
    if (J.wake) {
      privacyNote();
      addMsg("bot", "Ich höre jetzt ständig zu. Sag einfach „Jarvis“ und dann deinen Befehl – zum Beispiel „Jarvis, Statusbericht“.", { mood: "ok" });
      startWake();
    } else {
      pauseWake();
      addMsg("bot", "Okay, ich höre nur noch zu, wenn du aufs Mikrofon drückst.");
    }
    renderTools();
  });
  $("#jarvis-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = input.value;
    input.value = "";
    ask(v);
  });
  $("#jarvis-chips").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (b) ask(b.textContent);
  });
  log.addEventListener("click", (e) => {
    const b = e.target.closest("[data-j]");
    if (b) ask(b.dataset.j);
  });
  document.addEventListener("keydown", (e) => {
    if (e.altKey && e.code === "KeyJ") {
      e.preventDefault();
      listen();
    } else if (e.key === "Escape" && J.open && !document.querySelector("#modal-root .modal")) {
      closePanel();
    }
  });

  // Wichtige Ereignisse ansagen, sobald du Jarvis einmal benutzt hast
  SS.onEvents((events) => {
    if (!J.activated) return;
    for (const e of events) {
      const scanDone = e.category === "Scan" && /(gefunden|keine Bedrohungen)/.test(e.message);
      if (e.level !== "danger" && !scanDone) continue;
      if (/per Jarvis/.test(e.message)) continue;
      const text = e.level === "danger" ? `Achtung! ${e.message}` : e.message;
      addMsg("bot", text, { mood: e.level === "danger" ? "danger" : e.level === "ok" ? "ok" : "warn" });
      if (!J.busy && J.state !== "listening") speak(text);
    }
  });

  renderTools();
})();
