"""J.A.R.V.I.S. – der Sprachassistent von Schutzschild.

"Just A Really Vigilant Intrusion Shield": Jarvis versteht einfache deutsche
Sätze wie "Starte einen Schnellscan" oder "Wirf die Hacker raus" und
antwortet in ganzen Sätzen. Das Verstehen passiert komplett lokal auf deinem
PC – mit Mustern (regulären Ausdrücken), ohne KI aus dem Internet.

Gefährliche Aktionen (alle rauswerfen, alles in Quarantäne, IP sperren)
fragt Jarvis vorher nach. Die Oberfläche schickt die Antwort ("ja"/"nein")
zusammen mit der offenen Rückfrage (`pending`) zurück.
"""
from __future__ import annotations

import random
import re
from datetime import datetime

from . import config
from .firewall import FirewallError, validate_ip
from .scanner import ScanError

WEEKDAYS = ["Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag", "Sonntag"]
MONTHS = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober",
          "November", "Dezember"]
JOKES = [
    "Warum ist der Computer erkältet? Er hatte zu viele Fenster offen.",
    "Treffen sich zwei Viren. Sagt der eine: Du siehst aber schlecht aus. Sagt der andere: "
    "Ich glaube, ich hab mir ein Antivirus eingefangen.",
    "Ich würde dir ja einen UDP-Witz erzählen. Aber ich weiß nicht, ob er ankommt.",
    "Ich habe mein Passwort auf „falsch“ geändert. Wenn ich es vergesse, sagt mir der Computer: "
    "Ihr Passwort ist falsch.",
    "Was macht ein Hacker im Garten? Er sucht nach Hintertürchen im Gartenzaun.",
]

NAV = r"\b(zeig\w*|oeffne\w*|geh\w*|wechsel\w*|bring\w*|navigier\w*|anzeigen)\b"
ON = r"\b(an|ein|einschalten|anschalten|aktivier\w*|anmachen|starten?)\b"
OFF = r"\b(aus|ausschalten|abschalten|deaktivier\w*|ausmachen|stopp?\w*|beend\w*)\b"
YES = r"^(ja|jo|jap|jep|jawohl|yes|ok|okay|klar|sicher|mach( das| es| schon)?|los|tu es|bestaetig\w*|genau|" \
      r"auf jeden fall|gerne?|unbedingt|natuerlich)\b"
NO = r"^(nein|ne|nee|no|nicht|stopp?|abbrech\w*|lieber nicht|doch nicht|vergiss es|cancel|halt)\b"

MODULES = [  # (Schlüssel, Muster, Satzanfang, Verb)
    ("auto_kick", r"auto\w*\s*(rauswurf|kick|abwehr)|rauswurf automatisch", "Der automatische Rauswurf", "ist"),
    ("auto_quarantine", r"auto\w*\s*quarantaene", "Die Auto-Quarantäne", "ist"),
    ("realtime", r"echt ?zeit", "Der Echtzeitschutz", "ist"),
    ("guard", r"waechter|ueberwachung", "Der Netzwerk-Wächter", "ist"),
    ("notifications", r"benachrichtigung|desktop ?meldung", "Die Desktop-Benachrichtigungen", "sind"),
]
PAGES = [
    (r"uebersicht|startseite|dashboard|start\b", "uebersicht", "die Übersicht"),
    (r"scanner|virenscan|scan\b", "scanner", "den Virenscan"),
    (r"abwehr|hacker|netzwerk|verbindung", "abwehr", "die Hacker-Abwehr"),
    (r"prozess|programme|task", "prozesse", "die Prozesse"),
    (r"quarantaene", "quarantaene", "die Quarantäne"),
    (r"protokoll|log|verlauf|ereignis", "protokoll", "das Protokoll"),
    (r"einstellung|optionen|konfig", "einstellungen", "die Einstellungen"),
]
WAKE = re.compile(r"\b(jarvis|jarwis|javis|dschawis|jervis)\b[\s,!.]*", re.I)
IP_RE = re.compile(r"\b(\d{1,3}(?:\s*[.,]\s*\d{1,3}){3})\b")
PATH_RE = re.compile(r"\bscann?e?n?\s+(?:den\s+|die\s+|das\s+)?(?:ordner\s+|datei\s+|laufwerk\s+)?"
                     r"([A-Za-z]:[\\/]?.*|/\S.*|~.*)$", re.I)


def normalize(text: str) -> str:
    t = WAKE.sub(" ", text or "").lower()
    for a, b in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss")):
        t = t.replace(a, b)
    t = re.sub(r"[^\w\s.:/\\-]", " ", t)
    t = re.sub(r"\b(bitte|mal)\b", " ", t)
    return re.sub(r"\s+", " ", t).strip(" .")


def fmt(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def plural(n: int, one: str, many: str) -> str:
    return f"{fmt(n)} {one if n == 1 else many}"


def say(text: str, items=None, action=None, confirm=None, speak=None, mood: str = "info") -> dict:
    return {"reply": text, "items": items or [], "action": action, "confirm": confirm,
            "speak": speak or text, "mood": mood}


class Jarvis:
    def __init__(self, app):
        self.app = app
        self.intents = [
            (r"\b(hilfe|was kannst du|was kann ich (sagen|fragen)|befehle|wie funktionierst du)\b", self._help),
            (r"\b(wer bist du|was bist du|wie heisst du|stell dich vor)\b", self._identity),
            (r"\bwie geht(s| es)? (dir|euch)\b|\bwie gehts\b$", self._how_are_you),
            (r"^(danke\w*|vielen dank|super|cool|klasse|toll|gut gemacht|nice|perfekt)\b", self._thanks),
            (r"\b(wie spaet|uhrzeit|wie viel uhr|welcher tag|welches datum|datum)\b", self._time),
            (r"\b(witz|lustig|bring mich zum lachen)", self._joke),
            (r"\b(sei still|ruhe|stumm|halt die klappe|nicht (mehr )?sprechen|psst)\b", self._mute),
            (r"\b(sprich wieder|ton an|stimme an|rede wieder)\b", self._unmute),
            (r"\b(dunkl\w*|dark|nacht ?modus|helle?s?|light|tag ?modus)\b.*\b(design|modus|mode|ansicht|theme|farbe)|"
             r"\b(design|modus|ansicht|theme)\b.*\b(dunkel|hell)", self._theme),
            ("|".join(m[1] for m in MODULES), self._toggle),
            (r"\b(entsperr\w*|freigeb\w*|gib\b.*\bfrei)\b", self._unblock_ip),
            (r"\bsperr\w*\b.*\d{1,3}\s*[.,]\s*\d{1,3}", self._block_ip),
            (r"\b(wirf|werf|schmeiss|kick|rauswurf|rauswerfen|rausschmeiss|verjag|vertreib)\w*.*"
             r"(hacker|eindringling|angreifer|verbindung|feind|raus\b|alle)|"
             r"\b(hacker|eindringling|angreifer)\w*.*\b(raus|weg|kick\w*|blockier\w*|sperr\w*|vertreib\w*|trenn\w*)|"
             r"\bpanik", self._kick_all),
            (r"\b(alle|alles|bedrohungen|viren|funde)\b.*\b(quarantaene|wegsperr\w*|einsperr\w*)|"
             r"\b(quarantaene|wegsperr\w*)\b.*\b(alle|alles)\b", self._quarantine_all),
            (r"(scan|suche)\w*.*\b(stopp?\w*|abbrech\w*|beend\w*|anhalt\w*)|\b(stopp?\w*|abbrech\w*|beend\w*)\b.*scan",
             self._scan_stop),
            (r"\b(wie weit|fortschritt|wie lange noch|wie lang noch|stand)\b.*scan|scan\w*.*\b(fortschritt|wie weit)",
             self._scan_progress),
            (r"\b(letzte[nrs]?|wann)\b.*scan", self._last_scan),
            (r"\b(test ?virus|eicar|testdatei|teste?\w* (den |meinen |deinen |unseren )?schutz|schutz testen)\b",
             self._testvirus),
            (r"\b(signatur|virendefinition|virendatenbank|datenbank)\w*.*\b(aktualisier\w*|update\w*|neu\w*|laden)|"
             r"\b(aktualisier\w*|update\w*)\b.*\b(signatur|viren|datenbank)", self._sig_update),
            (r"hacker|eindringling|angreifer|gehackt|\bverbunden\b|verbindung|netzwerk|internet|fernzugriff|"
             r"fernwartung|anydesk|teamviewer|spion|beobachtet|ueberwacht mich|jemand\s+(auf|in|an|mit)\b",
             self._hacker_check),
            (r"\bscann?e?n?\s+(den |die |das )?(ordner |datei |laufwerk )?([a-z]:|/|~)", self._custom_scan),
            (r"\b(voll\w*|komplett\w*|gruendlich\w*|ganze[nrs]?|tief\w*)\b.*\b(scan\w*|pruef\w*|untersuch\w*|durchsuch\w*|check\w*)|"
             r"\b(scan\w*|pruef\w*|untersuch\w*|durchsuch\w*)\b.*\b(voll\w*|komplett\w*|gruendlich\w*|ganze[nrs]? "
             r"(pc|computer|rechner|festplatte|system))", self._full_scan),
            (r"\b(starte?|mach|fuehr\w*|beginn\w*|los|scann?e?n?|pruef\w*|check\w*|untersuch\w*|durchsuch\w*)\b.*"
             r"\b(scan\w*|viren|pc|computer|rechner|dateien|downloads|festplatte|system)\b|"
             r"schnell ?scan|viren ?scan|^scann?e?n?$", self._quick_scan),
            (r"bedrohung|\bvir(us|en)\b|schaedling|\bfunde?\b|gefunden|malware|trojaner|infiziert|befallen|verseucht",
             self._threats),
            (r"quarantaene", self._quarantine_info),
            (r"\bcpu\b|prozessor|langsam|ruckel\w*|lagg\w*|leistung|ressourcen|arbeitsspeicher|\bram\b|prozess|"
             r"task ?manager|was laeuft|programme laufen|miner|bremst", self._processes),
            (r"administrator|admin ?rechte|\badmin\b", self._admin),
            (NAV + r".*\b(" + "|".join(p[0] for p in PAGES) + r")", self._navigate),
            (r"status|bericht|\blage\b|sicher|geschuetzt|alles (ok|gut|klar|in ordnung)|zustand|score|ueberblick|"
             r"zusammenfassung|wie geht(s| es) (meinem|dem|unserem) (pc|computer|rechner)|gefahr|probleme?", self._status),
        ]
        self.intents = [(re.compile(p), h) for p, h in self.intents]

    # ------------------------------------------------------------------ Einstieg
    def handle(self, text: str, pending: dict | None = None) -> dict:
        raw = (text or "").strip()[:500]
        t = normalize(raw)
        if pending:
            if re.search(YES, t):
                return self._run(lambda: self._confirmed(pending))
            if re.search(NO, t):
                return say("Alles klar, ich mache nichts.", mood="info")
        greeted = False
        m = re.match(r"^(hallo|hi|hey|servus|moin|na|huhu|guten (morgen|tag|abend)|gruess (dich|gott))\b\s*", t)
        if m:
            greeted, t = True, t[m.end():].strip()
        if not t:
            return self._run(self._greet) if greeted or not raw else say("Ja? Ich höre.", speak="Ja?")
        for pattern, handler in self.intents:
            if pattern.search(t):
                return self._run(lambda: handler(t, raw))
        return self._fallback()

    def _run(self, fn) -> dict:
        try:
            return fn()
        except Exception as exc:  # Jarvis soll nie die Oberfläche kaputt machen
            return say(f"Da ist leider etwas schiefgelaufen: {exc}", mood="warn")

    # ------------------------------------------------------------------ Helfer
    def _nav(self, t: str, page: str) -> dict | None:
        return {"type": "navigate", "page": page} if re.search(NAV, t) else None

    def _status_line(self) -> tuple[str, dict]:
        st = self.app.status(-1)
        p = st["protection"]
        mood = {"ok": "ok", "warn": "warn", "bad": "danger"}[p["level"]]
        tail = {"ok": "Alles im grünen Bereich.", "warn": "Es gibt ein paar Lücken.",
                "bad": "Achtung, es gibt Gefahr!"}[p["level"]]
        return f"Sicherheits-Score {p['score']} von 100. {tail}", {**st, "mood": mood}

    # ------------------------------------------------------------------ Smalltalk
    def _greet(self, *_):
        hour = datetime.now().hour
        hello = "Guten Morgen" if hour < 11 else "Guten Tag" if hour < 18 else "Guten Abend"
        line, st = self._status_line()
        return say(f"{hello}! Jarvis ist online und hält Wache. {line}", items=st["protection"]["hints"][:3],
                   mood=st["mood"])

    def _identity(self, *_):
        return say("Ich bin J.A.R.V.I.S. – „Just A Really Vigilant Intrusion Shield“, der Sprachassistent von "
                   "Schutzschild. Ich scanne Dateien, behalte dein Netzwerk im Blick und werfe Eindringlinge raus. "
                   "Sag „Hilfe“, dann zeige ich dir, was ich kann.",
                   speak="Ich bin Jarvis, der Sprachassistent von Schutzschild. Ich scanne Dateien, behalte dein "
                         "Netzwerk im Blick und werfe Eindringlinge raus. Sag Hilfe, dann zeige ich dir, was ich kann.")

    def _how_are_you(self, *_):
        return say("Mir geht's bestens – alle Schaltkreise laufen kühl, und ich halte Wache.")

    def _thanks(self, *_):
        return say(random.choice(["Gern geschehen!", "Immer zu Diensten.", "Dafür bin ich da.",
                                  "Kein Problem – ich passe weiter auf."]), mood="ok")

    def _time(self, *_):
        now = datetime.now()
        return say(f"Es ist {now:%H:%M} Uhr – {WEEKDAYS[now.weekday()]}, der {now.day}. {MONTHS[now.month - 1]} "
                   f"{now.year}.")

    def _joke(self, *_):
        return say(random.choice(JOKES))

    def _mute(self, *_):
        return say("Okay, ich bin still. Meine Antworten stehen weiter hier im Chat.", action={"type": "mute"},
                   speak="")

    def _unmute(self, *_):
        return say("Ich spreche wieder mit dir.", action={"type": "unmute"})

    def _theme(self, t, _raw):
        dark = bool(re.search(r"dunkl|dunkel|dark|nacht", t))
        return say(f"Ich schalte auf das {'dunkle' if dark else 'helle'} Design um.",
                   action={"type": "theme", "value": "dark" if dark else "light"})

    def _help(self, *_):
        items = [
            "„Statusbericht“ – wie sicher ist mein Computer?",
            "„Starte einen Schnellscan“ oder „Vollständiger Scan“",
            "„Wie weit ist der Scan?“ · „Scan abbrechen“",
            "„Ist jemand mit meinem PC verbunden?“ – Hacker-Check",
            "„Wirf die Hacker raus!“ – Panik-Knopf",
            "„Welche Viren hast du gefunden?“ · „Alles in Quarantäne“",
            "„Was bremst meinen PC?“ – Prozesse prüfen",
            "„Echtzeitschutz aus“ · „Automatischer Rauswurf an“",
            "„Sperre IP 45.13.12.7“ · „Entsperre IP …“",
            "„Teste den Schutz“ – harmloser Testvirus",
            "„Zeig die Einstellungen“ · „Helles Design“ · „Erzähl einen Witz“",
        ]
        return say("Sag oder tippe zum Beispiel:", items=items,
                   speak="Frag mich nach dem Status, lass mich scannen, oder sag: Wirf die Hacker raus. "
                         "Hier im Fenster steht alles, was ich kann.")

    def _fallback(self) -> dict:
        return say("Das habe ich leider nicht verstanden. Probier zum Beispiel „Statusbericht“, "
                   "„Starte einen Schnellscan“ oder „Wirf die Hacker raus“. Mit „Hilfe“ siehst du alles.",
                   speak="Das habe ich leider nicht verstanden. Sag Hilfe, dann zeige ich dir, was ich kann.",
                   mood="warn")

    # ------------------------------------------------------------------ Status & Einstellungen
    def _status(self, *_):
        line, st = self._status_line()
        items = st["protection"]["hints"] or ["Echtzeitschutz und Netzwerk-Wächter sind aktiv",
                                              "Keine offenen Bedrohungen, keine verdächtigen Verbindungen"]
        if st["scan"]["running"]:
            items = [f"{st['scan']['label']} läuft gerade ({round(st['scan']['progress'])} %)"] + items
        return say(line, items=items, speak=line + " " + ". ".join(items[:3]) + ".", mood=st["mood"])

    def _toggle(self, t, raw):
        for key, pattern, label, verb in MODULES:
            if re.search(pattern, t):
                break
        else:  # pragma: no cover
            return self._fallback()
        question = raw.strip().endswith("?") or re.match(r"^(ist|sind|laeuft|laufen|was ist|wie ist|steht)\b", t)
        want = None if question else False if re.search(OFF, t) else True if re.search(ON, t) else None
        current = self.app.settings.get(key)
        if want is None:
            return say(f"{label} {verb} gerade {'eingeschaltet' if current else 'ausgeschaltet'}.")
        self.app.settings.update({key: want})
        self.app.events.add("info", "Jarvis", f"{label} per Sprachbefehl {'an' if want else 'aus'}geschaltet")
        text = f"{label} {verb} jetzt {'an' if want else 'aus'}."
        mood = "ok"
        if not want and key in ("realtime", "guard"):
            text += " Achtung: Damit bist du weniger geschützt."
            mood = "warn"
        if want and key == "auto_kick":
            text += " Ab jetzt werfe ich gefährliche Eindringlinge sofort raus, ohne zu fragen."
        return say(text, action={"type": "refresh"}, mood=mood)

    def _admin(self, *_):
        if config.is_admin():
            return say("Ich habe bereits Administratorrechte – alle Schutzfunktionen sind verfügbar.", mood="ok")
        if config.IS_WINDOWS:
            return say("Mit Administratorrechten kann ich Angreifer in der Firewall sperren und Verbindungen "
                       "kappen. Windows fragt dich gleich um Erlaubnis.", action={"type": "elevate"})
        return say(self.app.elevate()["message"])

    def _navigate(self, t, _raw):
        for pattern, page, name in PAGES:
            if re.search(pattern, t):
                return say(f"Ich öffne {name}.", action={"type": "navigate", "page": page})
        return self._fallback()  # pragma: no cover

    # ------------------------------------------------------------------ Scans
    def _start_scan(self, mode: str, path: str | None = None) -> dict:
        try:
            snap = self.app.scanner.start(mode, path)
        except ScanError as exc:
            return say(str(exc), mood="warn")
        return say(f"Alles klar, ich starte den {snap['label']}. Ich sage dir Bescheid, sobald ich fertig bin.",
                   action={"type": "navigate", "page": "scanner"}, mood="ok")

    def _quick_scan(self, *_):
        return self._start_scan("quick")

    def _full_scan(self, *_):
        return self._start_scan("full")

    def _custom_scan(self, _t, raw):
        m = PATH_RE.search(WAKE.sub("", raw).strip())
        if not m:
            return say("Welchen Ordner soll ich scannen? Tippe zum Beispiel: „Scanne D:\\“.")
        return self._start_scan("custom", m.group(1).strip().strip('"„“'))

    def _scan_stop(self, *_):
        if not self.app.scanner.running:
            return say("Es läuft gerade kein Scan.")
        self.app.scanner.stop()
        return say("Ich breche den Scan ab.", mood="ok")

    def _scan_progress(self, *_):
        sc = self.app.scanner.snapshot(with_threats=False)
        if not sc["running"]:
            return self._last_scan()
        if sc["phase"] == "sammeln":
            return say(f"Ich sammle noch Dateien – bisher {fmt(sc['files_total'])}.")
        return say(f"Der {sc['label']} ist zu {round(sc['progress'])} Prozent fertig: "
                   f"{fmt(sc['files_done'])} von {fmt(sc['files_total'])} Dateien geprüft, "
                   f"bisher {plural(sc['threat_count'], 'Fund', 'Funde')}.")

    def _last_scan(self, *_):
        hist = self.app.scanner.history
        if not hist:
            return say("Du hast noch nie gescannt. Sag „Starte einen Schnellscan“, und ich lege los.", mood="warn")
        h = hist[0]
        when = datetime.fromtimestamp(h["started"] or 0)
        found = "nichts gefunden" if not h["threats"] else plural(h["threats"], "Bedrohung", "Bedrohungen") + " gefunden"
        return say(f"Der letzte {h['label']} war am {when:%d.%m.} um {when:%H:%M} Uhr: "
                   f"{fmt(h['files'])} Dateien geprüft, {found}.")

    def _testvirus(self, *_):
        res = self.app.create_eicar()
        extra = (" Der Echtzeitschutz sollte gleich Alarm schlagen." if res["realtime"]
                 else " Sag „Schnellscan“, damit ich ihn finde.")
        return say("Ich habe die harmlose EICAR-Testdatei in deinem Download-Ordner abgelegt." + extra)

    def _sig_update(self, *_):
        try:
            res = self.app.sigdb.update_online()
        except Exception as exc:
            reason = getattr(exc, "reason", None) or exc
            return say(f"Das Update hat leider nicht geklappt: {reason}", speak="Das Update hat leider nicht "
                       "geklappt. Bist du mit dem Internet verbunden?", mood="warn")
        self.app.events.add("ok", "Signaturen", f"{res['added']} neue Signaturen geladen (per Jarvis)")
        return say(f"Fertig! {res['added']} neue Signaturen geladen, jetzt kenne ich {res['total']} "
                   "Schadprogramme aus dem Internet.", mood="ok")

    # ------------------------------------------------------------------ Bedrohungen
    def _open_threats(self) -> list[dict]:
        return [t for t in self.app.threats.all() if t["status"] == "offen"]

    def _threats(self, t, _raw):
        open_items = self._open_threats()
        if not open_items:
            hist = self.app.scanner.history
            hint = "" if hist else " Allerdings hast du noch nie gescannt."
            return say("Keine offenen Bedrohungen – alles sauber!" + hint, action=self._nav(t, "scanner"),
                       mood="ok")
        bad = sum(1 for x in open_items if x["verdict"] == "gefaehrlich")
        items = [f"{x['name']} – {'gefährlich' if x['verdict'] == 'gefaehrlich' else 'verdächtig'}: "
                 f"{x['reasons'][0]['text'] if x['reasons'] else ''}" for x in open_items[:5]]
        files = sum(1 for x in open_items if x.get("type") == "file")
        text = (f"Ich habe {plural(len(open_items), 'offene Bedrohung', 'offene Bedrohungen')} gefunden, "
                f"davon {bad} gefährlich.")
        if files:
            return say(text + " Soll ich alle in die Quarantäne sperren?", items=items,
                       confirm={"action": "quarantine_all"}, mood="danger" if bad else "warn")
        return say(text, items=items, action={"type": "navigate", "page": "scanner"}, mood="warn")

    def _quarantine_all(self, *_):
        files = [x for x in self._open_threats() if x.get("type") == "file"]
        if not files:
            return say("Es gibt nichts, was ich wegsperren müsste.", mood="ok")
        return say(f"Soll ich {plural(len(files), 'Datei', 'Dateien')} in die Quarantäne sperren? Sag „Ja“ oder „Nein“.",
                   items=[x["name"] for x in files[:5]], confirm={"action": "quarantine_all"}, mood="warn")

    def _quarantine_info(self, t, _raw):
        items = self.app.quarantine.list()
        if not items:
            return say("Die Quarantäne ist leer.", action=self._nav(t, "quarantaene"))
        return say(f"In der Quarantäne {'liegt' if len(items) == 1 else 'liegen'} "
                   f"{plural(len(items), 'Datei', 'Dateien')}, sicher verschlüsselt.",
                   items=[f"{q['name']} – {q['reason']}" for q in items[:5]], action=self._nav(t, "quarantaene"))

    # ------------------------------------------------------------------ Netzwerk
    def _hacker_check(self, t, _raw):
        if not self.app.net.available:
            return say("Für den Hacker-Check fehlt das Modul psutil. Installiere es mit „pip install psutil“.",
                       mood="warn")
        snap = self.app.net.snapshot()
        conns = [c for c in snap["connections"] if not c["self"]]
        s = snap["summary"]
        danger = [c for c in conns if c["score"] >= 70]
        warn = [c for c in conns if 30 <= c["score"] < 70 or (c["remote_session"] and c["score"] < 70)]
        nav = self._nav(t, "abwehr")

        def describe(c):
            peer = f" ↔ {c['remote']}" if c["remote"] else f" auf {c['local']}"
            return f"{c['process']} (PID {c['pid']}){peer}: {c['reasons'][0] if c['reasons'] else ''}"

        if danger:
            n = len(danger)
            return say(f"Achtung! Ich sehe {plural(n, 'gefährliche Verbindung', 'gefährliche Verbindungen')}. "
                       f"Soll ich {'sie' if n > 1 else 'den Eindringling'} rauswerfen?",
                       items=[describe(c) for c in danger[:5]], confirm={"action": "kick_all"}, mood="danger",
                       action=nav or {"type": "navigate", "page": "abwehr"})
        if warn:
            return say(f"Niemand Gefährliches, aber mir {'ist' if len(warn) == 1 else 'sind'} "
                       f"{plural(len(warn), 'Verbindung', 'Verbindungen')} aufgefallen. Schau sie dir in der "
                       "Hacker-Abwehr an.", items=[describe(c) for c in warn[:5]], mood="warn",
                       action=nav or {"type": "navigate", "page": "abwehr"})
        return say(f"Niemand Fremdes ist mit deinem Computer verbunden. Ich überwache gerade "
                   f"{plural(s['established'], 'Verbindung', 'Verbindungen')}, {s['internet']} davon ins Internet – "
                   "alle unauffällig.", action=nav, mood="ok")

    def _kick_all(self, t, raw):
        if not self.app.net.available:
            return say("Für den Rauswurf fehlt das Modul psutil.", mood="warn")
        snap = self.app.net.snapshot()
        danger = [c for c in snap["connections"] if c["score"] >= 70 and not c["self"]]
        if not danger:
            return say(f"Gute Nachricht: Gerade ist kein gefährlicher Eindringling verbunden. Ich habe "
                       f"{plural(snap['summary']['total'], 'Verbindung', 'Verbindungen')} geprüft.", mood="ok")
        items = [f"{c['process']} (PID {c['pid']}) {c['remote'] or c['local']}" for c in danger[:5]]
        return say(f"Ich habe {plural(len(danger), 'Eindringling', 'Eindringlinge')} im Visier. Soll ich "
                   f"{'sie' if len(danger) > 1 else 'ihn'} rauswerfen? Sag „Ja“ oder „Nein“.", items=items,
                   confirm={"action": "kick_all"}, mood="danger")

    def _extract_ip(self, raw: str) -> str | None:
        m = IP_RE.search(raw)
        return re.sub(r"\s*[.,]\s*", ".", m.group(1)) if m else None

    def _block_ip(self, _t, raw):
        ip = self._extract_ip(raw)
        if not ip:
            return say("Welche IP-Adresse soll ich sperren? Sag zum Beispiel: „Sperre IP 45.13.12.7“.")
        try:
            ip = validate_ip(ip)
        except FirewallError as exc:
            return say(str(exc), mood="warn")
        return say(f"Soll ich die IP-Adresse {ip} dauerhaft sperren?", confirm={"action": "block_ip", "ip": ip},
                   mood="warn")

    def _unblock_ip(self, _t, raw):
        ip = self._extract_ip(raw)
        if not ip:
            blocked = self.app.firewall.list()
            if not blocked:
                return say("Auf der Sperrliste steht keine IP-Adresse.")
            return say("Welche IP soll ich wieder freigeben?", items=[b["ip"] for b in blocked[:5]])
        try:
            self.app.firewall.unblock(ip)
        except FirewallError as exc:
            return say(str(exc), mood="warn")
        self.app.events.add("info", "Firewall", f"Sperre für {ip} aufgehoben (per Jarvis)")
        return say(f"Die Sperre für {ip} ist aufgehoben.", mood="ok")

    # ------------------------------------------------------------------ Prozesse
    def _processes(self, t, _raw):
        if not self.app.procs.available:
            return say("Für die Prozess-Prüfung fehlt das Modul psutil.", mood="warn")
        snap = self.app.procs.snapshot()
        procs = [p for p in snap["processes"] if not p["self"] and p["pid"] not in (0,)
                 and "idle" not in p["name"].lower()]
        bad = [p for p in procs if p["score"] >= 30]
        nav = self._nav(t, "prozesse")
        if bad:
            return say(f"Mir {'ist' if len(bad) == 1 else 'sind'} {plural(len(bad), 'verdächtiges Programm', 'verdächtige Programme')} "
                       "aufgefallen. Du kannst sie auf der Seite „Prozesse“ beenden.",
                       items=[f"{p['name']} (PID {p['pid']}): {p['reasons'][0]['text'] if p['reasons'] else ''}"
                              for p in bad[:5]], action=nav or {"type": "navigate", "page": "prozesse"},
                       mood="danger" if any(p["score"] >= 70 for p in bad) else "warn")
        top = sorted(procs, key=lambda p: (-p["cpu"], -p["mem_mb"]))[:3]
        sysinfo = self.app.status(-1)["system"]
        load = f" Der Prozessor ist zu {round(sysinfo['cpu'])} Prozent ausgelastet." if sysinfo else ""
        return say("Keine verdächtigen Programme." + load + " Am meisten brauchen gerade:",
                   items=[f"{p['name']} – {p['cpu']:.0f} % CPU, {p['mem_mb']:.0f} MB" for p in top],
                   speak="Keine verdächtigen Programme." + load + " Am meisten braucht gerade "
                         + (top[0]["name"] if top else "nichts") + ".",
                   action=nav, mood="ok")

    # ------------------------------------------------------------------ Bestätigte Aktionen
    def _confirmed(self, pending: dict) -> dict:
        action = pending.get("action")
        if action == "kick_all":
            res = self.app.net.kick_all()
            if not res["count"]:
                return say("Die Eindringlinge sind schon weg – es gibt niemanden mehr rauszuwerfen.", mood="ok")
            ok = sum(1 for r in res["results"] if r["ok"])
            items = [f"{r['process']}" + (f" ↔ {r['remote']}" if r["remote"] else "") + ": " + ", ".join(
                f"{s['step']} {'✓' if s['ok'] else '✗'}" for s in r["steps"]) for r in res["results"][:5]]
            if ok == res["count"]:
                return say(f"Erledigt! {plural(ok, 'Eindringling', 'Eindringlinge')} rausgeworfen. "
                           "Die Tür ist wieder zu.", items=items, mood="ok")
            return say(f"{ok} von {res['count']} Eindringlingen rausgeworfen. Für den Rest brauche ich "
                       "Administratorrechte.", items=items, mood="warn")
        if action == "quarantine_all":
            files = [x for x in self._open_threats() if x.get("type") == "file"]
            results = [self.app.threat_action(x["id"], "quarantine") for x in files]
            ok = sum(1 for r in results if r["ok"])
            failed = [r["message"] for r in results if not r["ok"]]
            if not files:
                return say("Es war nichts mehr da, was ich wegsperren müsste.", mood="ok")
            return say(f"{plural(ok, 'Datei', 'Dateien')} sicher in die Quarantäne gesperrt."
                       + (f" {len(failed)} ging nicht." if failed else ""), items=failed[:3],
                       mood="ok" if not failed else "warn", action={"type": "refresh"})
        if action == "block_ip":
            try:
                entry = self.app.firewall.block(str(pending.get("ip", "")), "Per Jarvis gesperrt")
            except FirewallError as exc:
                return say(str(exc), mood="warn")
            self.app.events.add("ok" if entry["applied"] else "warn", "Firewall", f"IP {entry['ip']} gesperrt (per Jarvis)",
                                entry["message"])
            if entry["applied"]:
                return say(f"{entry['ip']} ist gesperrt und kommt nicht mehr durch die Firewall.", mood="ok")
            return say(f"{entry['ip']} steht jetzt auf der Sperrliste. {entry['message']}", mood="warn")
        return say("Diese Rückfrage ist abgelaufen. Sag mir einfach noch mal, was ich tun soll.")
