"""Der Virenscanner: prüft Dateien mit Prüfsummen, Regeln und Heuristiken."""
from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import threading
import time
import uuid
import zipfile
import zlib
from collections import Counter
from pathlib import Path

from . import config
from .signatures import match_rules

MB = 1024 * 1024
CONTENT_LIMIT = 4 * MB
MALICIOUS = 70
SUSPICIOUS = 30

SCRIPT_EXT = {".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
              ".hta", ".sh", ".bash", ".zsh", ".command", ".py", ".pyw", ".php", ".phtml", ".pl", ".rb",
              ".lua", ".html", ".htm", ".svg", ".reg", ".inf", ".desktop", ".service", ".applescript",
              ".sct", ".xsl", ".url"}
BINARY_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".ocx", ".so", ".dylib",
              ".bin", ".elf", ".jar"}
OFFICE_ZIP_EXT = {".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltm", ".xlsb", ".xlam", ".pptx",
                  ".pptm", ".potm", ".ppsm"}
OFFICE_OLE_EXT = {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".rtf"}
EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".bat", ".cmd", ".vbs", ".vbe", ".js",
            ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".lnk", ".jar", ".reg", ".msc", ".sh", ".command",
            ".app", ".appimage", ".apk"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".odt", ".csv",
             ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".mp3", ".mp4", ".avi", ".mov", ".mkv",
             ".wav", ".zip", ".rar", ".7z"}
SCRIPT_HOST_EXT = {".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".scr"}
NO_HASH_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff", ".raw", ".cr2",
               ".mp3", ".mp4", ".m4a", ".m4v", ".avi", ".mov", ".mkv", ".webm", ".wav", ".flac", ".ogg",
               ".opus", ".aac", ".wma", ".wmv", ".ttf", ".otf", ".woff", ".woff2", ".psd", ".blend",
               ".vmdk", ".vdi", ".qcow2", ".pak", ".vpk", ".unity3d", ".assets"}
EXE_KINDS = {"pe", "elf", "macho"}
CODE_TARGETS = frozenset({"script", "binary", "office", "lnk"})

BAIT_DOC = re.compile(r"(rechnung|invoice|mahnung|zahlung|payment|bewerbung|lebenslauf|paket|sendung|dhl|dpd|"
                      r"hermes|bestellung|auftrag|vertrag|kontoauszug|steuer|dokument|document)", re.I)
BAIT_CHEAT = re.compile(r"(crack|keygen|cheat|aimbot|wallhack|robux|v-?bucks|mod.?menu|injector|"
                        r"kms.?activator|free.?fire.?hack)", re.I)

SKIP_SYSTEM_DIRS = {"/proc", "/sys", "/dev", "/run", "/snap"} if not config.IS_WINDOWS else set()


def _norm(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


class Locations:
    """Erkennt, ob eine Datei in einem 'gefährlichen' Ordner liegt."""

    def __init__(self):
        self.refresh()

    def refresh(self) -> None:
        self.downloads = [_norm(config.downloads_dir())]
        self.temp = [_norm(p) for p in config.temp_dirs()]
        self.autostart = [_norm(p) for p in config.autostart_dirs()]

    def classify(self, path) -> str:
        s = _norm(path)
        for label, prefixes in (("autostart", self.autostart), ("temp", self.temp),
                                ("downloads", self.downloads)):
            for prefix in prefixes:
                if s == prefix or s.startswith(prefix.rstrip(os.sep) + os.sep):
                    return label
        return ""

    def risky(self, path) -> bool:
        return self.classify(path) in ("temp", "downloads")


LOCATIONS = Locations()


def verdict_for(score: int) -> str:
    if score >= MALICIOUS:
        return "gefaehrlich"
    if score >= SUSPICIOUS:
        return "verdaechtig"
    return "sauber"


def detect_kind(head: bytes, ext: str) -> str:
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") or \
            (head[:4] == b"\xca\xfe\xba\xbe" and ext != ".class"):
        return "macho"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8")):
        return "image"
    return "other"


def targets_for(kind: str, ext: str, location: str = "") -> frozenset:
    t = {"other"}
    if kind in EXE_KINDS or ext in BINARY_EXT:
        t.add("binary")
    if ext in SCRIPT_EXT or kind == "script":
        t.add("script")
    if ext == ".lnk" or kind == "lnk":
        t.add("lnk")
    if ext in OFFICE_OLE_EXT or ext in OFFICE_ZIP_EXT or kind == "rtf":
        t.add("office")
    if location == "autostart" and len(t) == 1:
        t.add("script")
    return frozenset(t)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


class Findings:
    def __init__(self):
        self.items: list[dict] = []
        self._seen: set = set()

    def add(self, score: int, text: str, family: str, snippet: str = "") -> None:
        key = (text, family)
        if key in self._seen:
            return
        self._seen.add(key)
        self.items.append({"score": score, "text": text, "family": family, "snippet": snippet})

    @property
    def score(self) -> int:
        return min(100, sum(i["score"] for i in self.items))

    def sorted(self) -> list[dict]:
        return sorted(self.items, key=lambda i: -i["score"])


def name_findings(name: str, ext: str, f: Findings, prefix: str = "") -> None:
    low = name.lower()
    if "‮" in name:
        f.add(70, prefix + "Unsichtbares Umkehr-Zeichen täuscht eine falsche Dateiendung vor", "Tarnung")
    parts = low.split(".")
    if len(parts) >= 3 and "." + parts[-2] in DECOY_EXT and ext in EXEC_EXT:
        f.add(60, prefix + f"Getarnte Dateiendung: sieht aus wie .{parts[-2]}, ist aber ein Programm ({ext})", "Tarnung")
    if ext in EXEC_EXT and re.search(r"(\s{4,}|_{6,})\.[^.]+$", name):
        f.add(50, prefix + "Versteckt die echte Endung hinter vielen Leerzeichen", "Tarnung")
    if ext in EXEC_EXT:
        if BAIT_CHEAT.search(low):
            f.add(30, prefix + "Crack/Cheat/Gratis-Programm – darin steckt sehr oft Schadsoftware", "Köder")
        elif BAIT_DOC.search(low):
            f.add(20, prefix + "Typischer Köder-Name (Rechnung, Paket, Bewerbung …) für ein Programm", "Köder")


def analyze(data: bytes, name: str, ext: str, kind: str, targets: frozenset, f: Findings, db,
            sha: str | None, md5: str | None, prefix: str = "") -> None:
    """Analysiert den Inhalt einer Datei (oder eines Archiv-Eintrags)."""
    known = db.lookup(sha, md5)
    if known:
        f.add(100, prefix + f"Bekannte Schadsoftware: {known}", "Signatur")

    if kind in EXE_KINDS or kind in ("ole", "lnk") or "lnk" in targets:
        rule_data = data + b"\n" + data.replace(b"\x00", b"")  # findet auch UTF-16-Text
    elif data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            rule_data = data.decode("utf-16").encode("utf-8", "replace")
        except UnicodeDecodeError:
            rule_data = data.replace(b"\x00", b"")
    else:
        rule_data = data
    for hit in match_rules(rule_data, targets, ext):
        f.add(hit.rule.score, prefix + hit.rule.name, hit.rule.family, hit.snippet)

    name_findings(name, ext, f, prefix)

    if kind in EXE_KINDS and ext in DECOY_EXT:
        f.add(65, prefix + f"Programm tarnt sich als {ext}-Datei", "Tarnung")
    if kind == "pe":
        if b"UPX0" in data[:4096] and b"UPX1" in data[:4096]:
            f.add(10, prefix + "Mit UPX gepackt (häufig bei Schadsoftware)", "Verschleierung")
    if kind == "ole" and ext in OFFICE_OLE_EXT and b"_vba_project" in rule_data.lower():
        f.add(15, prefix + "Enthält Makros (kleine Programme im Dokument)", "Makro-Virus")


def analyze_zip(path: Path, f: Findings, db) -> None:
    budget = 60 * MB
    encrypted_exec = False
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist()[:400]:
                if info.is_dir():
                    continue
                mname = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
                mext = os.path.splitext(mname)[1].lower()
                prefix = f"Im Archiv „{mname[:60]}“: "
                if info.flag_bits & 0x1:
                    encrypted_exec = encrypted_exec or mext in EXEC_EXT
                    name_findings(mname, mext, f, prefix)
                    continue
                interesting = mext in SCRIPT_EXT or mext in BINARY_EXT or mext in EXEC_EXT or info.file_size <= 4096
                if not interesting or info.file_size > 20 * MB or info.file_size > budget:
                    name_findings(mname, mext, f, prefix)
                    continue
                try:
                    data = zf.read(info)
                except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, OSError):
                    continue
                budget -= len(data)
                kind = detect_kind(data[:4096], mext)
                analyze(data[:CONTENT_LIMIT], mname, mext, kind, targets_for(kind, mext), f, db,
                        hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(), prefix)
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        return
    if encrypted_exec:
        f.add(25, "Passwortgeschütztes Archiv mit Programm darin (Trick gegen Virenscanner)", "Tarnung")


def analyze_office_zip(path: Path, f: Findings) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            vba = [n for n in names if n.lower().endswith("vbaproject.bin")]
            if vba:
                f.add(15, "Enthält Makros (kleine Programme im Dokument)", "Makro-Virus")
            for n in vba[:2]:
                if zf.getinfo(n).file_size > 20 * MB:
                    continue
                data = zf.read(n)
                for hit in match_rules(data + b"\n" + data.replace(b"\x00", b""), {"office"}):
                    f.add(hit.rule.score, hit.rule.name, hit.rule.family, hit.snippet)
            for n in names:
                if n.lower().endswith(".rels") and "settings" in n.lower():
                    content = zf.read(n)[:200_000]
                    if re.search(rb"attachedTemplate[^>]{0,300}External|External[^>]{0,300}attachedTemplate",
                                 content) and b"http" in content.lower():
                        f.add(50, "Lädt beim Öffnen eine Vorlage aus dem Internet nach (Template-Injection)",
                              "Makro-Virus")
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, NotImplementedError, zlib.error):
        return


def scan_file(path, db, allow, max_bytes: int, location: str | None = None) -> dict | None:
    """Scannt eine einzelne Datei. Gibt None zurück, wenn es keine normale Datei ist."""
    path = Path(path)
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    if location is None:
        location = LOCATIONS.classify(path)
    ext = path.suffix.lower()
    name = path.name
    size = st.st_size

    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as fh:
        head = fh.read(4096)
        kind = detect_kind(head, ext)
        targets = targets_for(kind, ext, location)
        limit = CONTENT_LIMIT if targets & CODE_TARGETS else len(head)
        hashed = size <= max_bytes and (ext not in NO_HASH_EXT or kind in EXE_KINDS)
        buf = bytearray(head)
        md5.update(head)
        sha.update(head)
        if hashed:
            while True:
                chunk = fh.read(MB)
                if not chunk:
                    break
                md5.update(chunk)
                sha.update(chunk)
                if len(buf) < limit:
                    buf += chunk[: limit - len(buf)]
        elif len(buf) < limit:
            buf += fh.read(limit - len(buf))

    sha_hex = sha.hexdigest() if hashed else None
    md5_hex = md5.hexdigest() if hashed else None
    result = {"path": str(path), "name": name, "size": size, "sha256": sha_hex, "kind": kind,
              "location": location, "score": 0, "verdict": "sauber", "reasons": [], "trusted": False}
    if allow.contains(sha_hex):
        result["trusted"] = True
        return result

    f = Findings()
    data = bytes(buf)
    analyze(data, name, ext, kind, targets, f, db, sha_hex, md5_hex)

    is_exec = ext in EXEC_EXT or kind in EXE_KINDS
    if location == "temp" and is_exec:
        f.add(10, "Programm liegt im Temp-Ordner", "Fundort")
    if location in ("temp", "downloads") and ext in SCRIPT_HOST_EXT:
        f.add(15, "Windows-Skript aus dem Internet – startet beim Doppelklick sofort", "Fundort")
    if location == "autostart" and (is_exec or "script" in targets):
        f.add(15, "Startet automatisch mit dem System", "Fundort")
    hidden = bool(getattr(st, "st_file_attributes", 0) & 2) or (not config.IS_WINDOWS and name.startswith("."))
    if hidden and is_exec:
        f.add(10, "Versteckte Programmdatei", "Tarnung")
    if kind == "pe" and size <= 8 * MB and entropy(data[:MB]) > 7.4:
        f.add(15, "Inhalt ist stark verschlüsselt oder gepackt", "Verschleierung")
    if kind == "zip" and size <= 300 * MB:
        if ext in OFFICE_ZIP_EXT:
            analyze_office_zip(path, f)
        elif ext == ".zip":
            analyze_zip(path, f, db)

    result["reasons"] = f.sorted()
    result["score"] = f.score
    result["verdict"] = verdict_for(f.score)
    return result


def scan_command(command: str) -> Findings:
    """Prüft eine Befehlszeile (z. B. Autostart-Eintrag oder Prozess-Aufruf)."""
    f = Findings()
    for hit in match_rules(command.encode("utf-8", "replace"), {"cmdline"}):
        f.add(hit.rule.score, hit.rule.name, hit.rule.family, hit.snippet)
    return f


# --------------------------------------------------------------------------
# Gefundene Bedrohungen
# --------------------------------------------------------------------------

class ThreatStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._items: dict[str, dict] = {}

    def add(self, result: dict, source: str, kind: str = "file", extra: dict | None = None) -> str:
        with self._lock:
            for t in self._items.values():
                if t["status"] == "offen" and t["path"] == result["path"] and t.get("sha256") == result.get("sha256"):
                    t.update(score=result["score"], verdict=result["verdict"], reasons=result["reasons"])
                    return t["id"]
            tid = uuid.uuid4().hex[:12]
            threat = dict(result)
            threat.update(id=tid, source=source, found=time.time(), status="offen", message="", type=kind)
            if extra:
                threat.update(extra)
            self._items[tid] = threat
            if len(self._items) > 2000:
                closed = [k for k, v in self._items.items() if v["status"] != "offen"]
                for k in closed[: len(self._items) - 2000]:
                    del self._items[k]
            return tid

    def get(self, tid: str) -> dict | None:
        with self._lock:
            t = self._items.get(tid)
            return dict(t) if t else None

    def get_many(self, ids) -> list[dict]:
        with self._lock:
            return [dict(self._items[i]) for i in ids if i in self._items]

    def all(self) -> list[dict]:
        with self._lock:
            items = [dict(t) for t in self._items.values()]
        return sorted(items, key=lambda t: (t["status"] != "offen", -t["score"], -t["found"]))

    def set_status(self, tid: str, status: str, message: str = "") -> None:
        with self._lock:
            if tid in self._items:
                self._items[tid].update(status=status, message=message)

    def open_counts(self) -> dict:
        with self._lock:
            open_items = [t for t in self._items.values() if t["status"] == "offen"]
        return {"total": len(open_items),
                "gefaehrlich": sum(1 for t in open_items if t["verdict"] == "gefaehrlich"),
                "verdaechtig": sum(1 for t in open_items if t["verdict"] == "verdaechtig")}


# --------------------------------------------------------------------------
# Scan-Steuerung
# --------------------------------------------------------------------------

MODE_LABELS = {"quick": "Schnellscan", "full": "Vollständiger Scan", "custom": "Eigener Scan"}


class ScanError(Exception):
    pass


class ScanManager:
    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self.state = self._fresh_state()
        history = config.read_json(config.HISTORY_FILE, [])
        self.history: list[dict] = history if isinstance(history, list) else []

    @staticmethod
    def _fresh_state(mode=None) -> dict:
        return {"running": False, "mode": mode, "label": MODE_LABELS.get(mode, ""), "phase": "bereit",
                "files_total": 0, "files_done": 0, "bytes_done": 0, "errors": 0, "current": "",
                "started": None, "finished": None, "threat_ids": [], "targets": []}

    # -- Ziele -------------------------------------------------------------
    def _roots_for(self, mode: str, custom: str | None) -> tuple[list, list]:
        roots: list[tuple[Path, int | None]] = []
        extra_files: list[Path] = []
        if mode == "quick":
            roots.append((config.downloads_dir(), 3))
            roots += [(d, 2) for d in config.desktop_dirs()]
            roots += [(d, 2) for d in config.temp_dirs()]
            roots += [(d, 2) for d in config.autostart_dirs()]
            for entry in config.windows_run_entries():
                target = config.command_target(entry["command"])
                if target:
                    extra_files.append(target)
        elif mode == "full":
            roots.append((config.HOME, None))
            roots += [(d, None) for d in config.temp_dirs()]
            roots += [(d, None) for d in config.autostart_dirs()]
        elif mode == "custom":
            if not custom or not custom.strip():
                raise ScanError("Bitte gib einen Ordner oder eine Datei an.")
            p = Path(os.path.expandvars(os.path.expanduser(custom.strip().strip('"'))))
            if not p.exists():
                raise ScanError(f"„{p}“ wurde nicht gefunden.")
            if p.is_file():
                extra_files.append(p)
            else:
                roots.append((p, None))
        else:
            raise ScanError("Unbekannte Scan-Art.")
        roots = [(r, d) for r, d in roots if r.is_dir()]
        return roots, extra_files

    def start(self, mode: str, custom: str | None = None) -> dict:
        with self._lock:
            if self.state["running"]:
                raise ScanError("Es läuft bereits ein Scan.")
            roots, extra = self._roots_for(mode, custom)
            self._cancel.clear()
            self.state = self._fresh_state(mode)
            self.state.update(running=True, phase="sammeln", started=time.time(),
                              targets=[str(r) for r, _ in roots] + [str(e) for e in extra])
            self._thread = threading.Thread(target=self._run, args=(mode, roots, extra), daemon=True,
                                            name="scan")
            self._thread.start()
        self.app.events.add("info", "Scan", f"{MODE_LABELS[mode]} gestartet")
        return self.snapshot()

    def stop(self) -> None:
        self._cancel.set()

    @property
    def running(self) -> bool:
        return self.state["running"]

    def _excluded(self) -> list[str]:
        ex = [_norm(config.DATA_DIR), _norm(config.BASE_DIR)]
        ex += [_norm(e) for e in self.app.settings.get("exclusions")]
        ex += [_norm(d) for d in SKIP_SYSTEM_DIRS]
        return ex

    def _collect(self, roots, extra) -> list[Path]:
        excluded = self._excluded()

        def is_excluded(p: str) -> bool:
            n = _norm(p)
            return any(n == e or n.startswith(e.rstrip(os.sep) + os.sep) for e in excluded)

        files: list[Path] = []
        seen: set[str] = set()
        for p in extra:
            key = _norm(p)
            if key not in seen and not is_excluded(str(p)):
                seen.add(key)
                files.append(p)
        for root, max_depth in roots:
            root_depth = str(root).rstrip(os.sep).count(os.sep)
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if self._cancel.is_set():
                    return files
                if is_excluded(dirpath):
                    dirnames[:] = []
                    continue
                if max_depth is not None and dirpath.rstrip(os.sep).count(os.sep) - root_depth >= max_depth:
                    dirnames[:] = []
                dirnames[:] = [d for d in dirnames if not is_excluded(os.path.join(dirpath, d))]
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    key = os.path.normcase(full)
                    if key in seen:
                        continue
                    seen.add(key)
                    files.append(Path(full))
                self.state["files_total"] = len(files)
                if len(files) >= 3_000_000:
                    return files
        return files

    def _scan_autostart_registry(self) -> None:
        for entry in config.windows_run_entries():
            f = scan_command(entry["command"])
            if f.score >= SUSPICIOUS:
                result = {"path": f"Autostart: {entry['name']}", "name": entry["name"], "size": 0,
                          "sha256": None, "kind": "autostart", "location": "autostart", "score": f.score,
                          "verdict": verdict_for(f.score), "reasons": f.sorted(), "trusted": False,
                          "command": entry["command"]}
                tid = self.app.threats.add(result, "Autostart-Prüfung", kind="autostart",
                                           extra={"reg": {"hive": entry["hive"], "key": entry["key"],
                                                          "name": entry["name"]}})
                self.state["threat_ids"].append(tid)

    def _run(self, mode: str, roots, extra) -> None:
        st = self.state
        label = MODE_LABELS[mode]
        try:
            if mode == "quick":
                self._scan_autostart_registry()
            files = self._collect(roots, extra)
            st.update(files_total=len(files), phase="scannen")
            max_bytes = self.app.settings.get("max_file_mb") * MB
            db, allow = self.app.sigdb, self.app.allowlist
            for path in files:
                if self._cancel.is_set():
                    break
                st["current"] = str(path)
                try:
                    result = scan_file(path, db, allow, max_bytes)
                except (OSError, MemoryError):
                    st["errors"] += 1
                    st["files_done"] += 1
                    continue
                except Exception:  # eine kaputte Datei soll nie den ganzen Scan stoppen
                    st["errors"] += 1
                    st["files_done"] += 1
                    continue
                st["files_done"] += 1
                if result is None:
                    continue
                st["bytes_done"] += result["size"]
                if result["verdict"] != "sauber":
                    st["threat_ids"].append(self.app.threats.add(result, label))
            st["phase"] = "abgebrochen" if self._cancel.is_set() else "fertig"
        except Exception as exc:  # pragma: no cover - Schutz vor unerwarteten Fehlern
            st["phase"] = "fehler"
            self.app.events.add("warn", "Scan", f"{label} mit Fehler beendet", str(exc))
        finally:
            st["running"] = False
            st["finished"] = time.time()
            st["current"] = ""
        self._record(st, label)

    def _record(self, st: dict, label: str) -> None:
        threats = self.app.threats.get_many(st["threat_ids"])
        bad = sum(1 for t in threats if t["verdict"] == "gefaehrlich")
        sus = len(threats) - bad
        duration = (st["finished"] or time.time()) - (st["started"] or time.time())
        entry = {"mode": st["mode"], "label": label, "phase": st["phase"], "started": st["started"],
                 "duration": round(duration, 1), "files": st["files_done"], "threats": len(threats),
                 "dangerous": bad}
        self.history = ([entry] + self.history)[:30]
        try:
            config.write_json(config.HISTORY_FILE, self.history)
        except OSError:
            pass
        if st["phase"] == "abgebrochen":
            self.app.events.add("info", "Scan", f"{label} abgebrochen nach {st['files_done']} Dateien")
        elif st["phase"] == "fertig":
            if threats:
                level = "danger" if bad else "warn"
                self.app.events.add(level, "Scan", f"{label}: {bad} gefährliche und {sus} verdächtige Dateien gefunden",
                                    f"{st['files_done']} Dateien in {duration:.0f} s geprüft")
            else:
                self.app.events.add("ok", "Scan", f"{label}: keine Bedrohungen gefunden",
                                    f"{st['files_done']} Dateien in {duration:.0f} s geprüft")

    def snapshot(self, with_threats: bool = True) -> dict:
        st = dict(self.state)
        ids = list(st.pop("threat_ids"))
        now = time.time()
        elapsed = ((st["finished"] or now) - st["started"]) if st["started"] else 0
        total = st["files_total"] or 0
        st["elapsed"] = round(elapsed, 1)
        st["progress"] = round(100 * st["files_done"] / total, 1) if total and st["phase"] != "sammeln" else 0
        st["speed"] = round(st["files_done"] / elapsed, 1) if elapsed > 0 else 0
        st["threat_count"] = len(ids)
        if with_threats:
            st["threats"] = self.app.threats.get_many(ids)
        st["last"] = self.history[0] if self.history else None
        return st
