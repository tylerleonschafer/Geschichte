"""Verbindet alle Schutzmodule zu einer Anwendung."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from . import config
from .events import EventLog
from .firewall import Firewall
from .netguard import NetGuard
from .processes import ProcessGuard
from .quarantine import Quarantine, QuarantineError
from .realtime import GuardThread, RealtimeWatcher
from .scanner import ScanManager, ThreatStore
from .signatures import EICAR, Allowlist, SignatureDB

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class App:
    def __init__(self):
        config.ensure_dirs()
        self.started = time.time()
        self.settings = config.Settings(config.SETTINGS_FILE)
        self.events = EventLog(config.EVENTS_FILE)
        self.allowlist = Allowlist(config.ALLOWLIST_FILE)
        self.sigdb = SignatureDB()
        self.quarantine = Quarantine(config.QUARANTINE_DIR)
        self.firewall = Firewall(config.BLOCKLIST_FILE)
        self.threats = ThreatStore()
        self.scanner = ScanManager(self)
        self.procs = ProcessGuard(self)
        self.net = NetGuard(self)
        self.realtime = RealtimeWatcher(self)
        self.guard = GuardThread(self)
        self.shutdown_callback = None

    def start(self) -> None:
        self.firewall.reapply()
        self.realtime.start()
        self.guard.start()
        admin = "mit Administratorrechten" if config.is_admin() else "ohne Administratorrechte"
        self.events.add("info", "System", f"Schutzschild {config.VERSION} gestartet ({admin})",
                        config.platform_name())
        if psutil is None:
            self.events.add("warn", "System", "Modul „psutil“ fehlt – Hacker-Abwehr und Prozesse sind aus",
                            "Installiere es mit: pip install psutil")

    def stop(self) -> None:
        self.scanner.stop()
        self.realtime.stop_event.set()
        self.guard.stop_event.set()

    # -- Bedrohungen behandeln --------------------------------------------------
    def threat_action(self, tid: str, action: str, quiet: bool = False) -> dict:
        threat = self.threats.get(tid)
        if not threat:
            return {"ok": False, "message": "Bedrohung nicht gefunden."}
        if threat["status"] != "offen":
            return {"ok": False, "message": "Diese Bedrohung wurde bereits behandelt."}
        name = threat["name"]
        try:
            if threat.get("type") == "autostart":
                if action not in ("remove", "ignore"):
                    return {"ok": False, "message": "Für Autostart-Einträge: entfernen oder ignorieren."}
                if action == "remove":
                    reg = threat["reg"]
                    config.remove_windows_run_entry(reg["hive"], reg["key"], reg["name"])
                    self.threats.set_status(tid, "entfernt", "Autostart-Eintrag gelöscht")
                    self.events.add("ok", "Scan", f"Autostart-Eintrag „{name}“ entfernt")
                    return {"ok": True, "message": f"Autostart-Eintrag „{name}“ wurde entfernt."}
            if action == "quarantine":
                reason = threat["reasons"][0]["text"] if threat["reasons"] else "Bedrohung"
                meta = self.quarantine.add(threat["path"], reason, threat.get("sha256"))
                self.threats.set_status(tid, "quarantaene", "In Quarantäne gesperrt")
                if not quiet:
                    self.events.add("ok", "Quarantäne", f"„{name}“ in Quarantäne gesperrt", threat["path"])
                return {"ok": True, "message": f"„{name}“ ist jetzt sicher weggesperrt.", "id": meta["id"]}
            if action == "delete":
                path = Path(threat["path"])
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                self.threats.set_status(tid, "geloescht", "Endgültig gelöscht")
                self.events.add("ok", "Scan", f"„{name}“ endgültig gelöscht", threat["path"])
                return {"ok": True, "message": f"„{name}“ wurde gelöscht."}
            if action == "ignore":
                if threat.get("sha256"):
                    self.allowlist.add(threat["sha256"])
                self.threats.set_status(tid, "ignoriert", "Als vertrauenswürdig markiert")
                self.events.add("info", "Scan", f"„{name}“ als vertrauenswürdig markiert", threat["path"])
                return {"ok": True, "message": f"„{name}“ wird künftig nicht mehr gemeldet."}
        except QuarantineError as exc:
            return {"ok": False, "message": str(exc)}
        except PermissionError:
            return {"ok": False, "message": "Zugriff verweigert – starte Schutzschild als Administrator."}
        except OSError as exc:
            return {"ok": False, "message": f"Fehler: {exc.strerror or exc}"}
        return {"ok": False, "message": "Unbekannte Aktion."}

    def quarantine_process(self, pid: int, expected_name: str) -> dict:
        res = self.procs.kill(pid, expected_name)
        if not res["ok"]:
            return res
        exe = res.get("exe")
        if not exe or not os.path.isfile(exe):
            return {"ok": True, "message": res["message"] + " Die Programmdatei wurde nicht gefunden."}
        time.sleep(0.5)  # Windows gibt die Datei erst kurz nach dem Beenden frei
        try:
            self.quarantine.add(exe, f"Prozess {res['name']} manuell gestoppt")
        except QuarantineError as exc:
            return {"ok": False, "message": res["message"] + " Quarantäne fehlgeschlagen: " + str(exc)}
        self.events.add("ok", "Prozesse", f"{res['name']} beendet und in Quarantäne gesperrt", exe)
        return {"ok": True, "message": res["message"] + " Die Programmdatei ist in Quarantäne."}

    # -- Testvirus ----------------------------------------------------------------
    def create_eicar(self) -> dict:
        folder = config.downloads_dir()
        if not folder.is_dir():
            folder = config.DATA_DIR
        target = folder / "schutzschild-testvirus.txt"
        target.write_bytes(EICAR + b"\r\n")
        config.fix_owner(target)
        self.events.add("info", "Test", "EICAR-Testvirus erzeugt", str(target))
        return {"ok": True, "path": str(target), "realtime": self.settings.get("realtime") and any(
            os.path.normcase(str(target)).startswith(os.path.normcase(f)) for f in self.settings.get("watch_folders"))}

    # -- Neustart als Administrator ---------------------------------------------
    def elevate(self) -> dict:
        if config.is_admin():
            return {"ok": False, "message": "Schutzschild läuft bereits als Administrator."}
        if not config.IS_WINDOWS:
            script = Path(sys.argv[0]).resolve()
            return {"ok": False, "message": f"Starte im Terminal: sudo {sys.executable} {script}"}
        import ctypes
        script = str(Path(sys.argv[0]).resolve())
        params = " ".join(f'"{a}"' for a in [script, *sys.argv[1:]])
        code = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params,
                                                   str(config.BASE_DIR), 1)
        if code <= 32:
            return {"ok": False, "message": "Der Neustart wurde abgebrochen."}
        if self.shutdown_callback:
            self.shutdown_callback(delay=1.5)
        return {"ok": True, "message": "Schutzschild startet als Administrator neu …"}

    # -- Übersicht ----------------------------------------------------------------
    def protection(self) -> dict:
        s = self.settings
        hints = []
        score = 100
        counts = self.threats.open_counts()
        net = self.net.last_summary
        if counts["gefaehrlich"]:
            score -= 45
            hints.append(f"{counts['gefaehrlich']} gefährliche Datei(en) warten auf dich")
        elif counts["verdaechtig"]:
            score -= 15
            hints.append(f"{counts['verdaechtig']} verdächtige Datei(en) solltest du prüfen")
        if net.get("dangerous"):
            score -= 40
            hints.append(f"{net['dangerous']} gefährliche Netzwerkverbindung(en) aktiv")
        elif net.get("remote_sessions"):
            score -= 10
            hints.append("Eine Fernwartungs-Sitzung ist aktiv")
        if not s.get("realtime"):
            score -= 15
            hints.append("Echtzeitschutz ist ausgeschaltet")
        if not s.get("guard"):
            score -= 15
            hints.append("Netzwerk-Wächter ist ausgeschaltet")
        last = self.scanner.history[0] if self.scanner.history else None
        if not last or time.time() - (last.get("started") or 0) > 7 * 86400:
            score -= 10
            hints.append("Seit über einer Woche kein Scan – starte einen Schnellscan")
        if not config.is_admin():
            score -= 5
            hints.append("Ohne Administratorrechte kann die Firewall keine Angreifer sperren")
        if psutil is None:
            score -= 10
            hints.append("Modul psutil fehlt – installiere es für die Hacker-Abwehr")
        score = max(0, min(100, score))
        if counts["gefaehrlich"] or net.get("dangerous"):
            level, title = "bad", "Gefahr erkannt!"
        elif score >= 80:
            level, title = "ok", "Du bist geschützt"
        else:
            level, title = "warn", "Achtung – Schutz lückenhaft"
        return {"score": score, "level": level, "title": title, "hints": hints}

    def status(self, since: int = 0) -> dict:
        system = {}
        if psutil:
            vm = psutil.virtual_memory()
            system = {"cpu": psutil.cpu_percent(None), "ram": vm.percent,
                      "ram_total": vm.total, "boot": psutil.boot_time()}
        scan = self.scanner.snapshot(with_threats=False)
        return {
            "app": {"name": config.APP_NAME, "version": config.VERSION, "platform": config.platform_name(),
                    "admin": config.is_admin(), "psutil": psutil is not None, "windows": config.IS_WINDOWS,
                    "uptime": round(time.time() - self.started), "data_dir": str(config.DATA_DIR)},
            "protection": self.protection(),
            "modules": {k: self.settings.get(k) for k in ("realtime", "guard", "auto_kick", "auto_quarantine",
                                                          "notifications")},
            "counts": {"threats": self.threats.open_counts(), "quarantine": self.quarantine.count(),
                       "blocked": len(self.firewall.blocked_set()), "signatures": self.sigdb.stats()["total"],
                       "rules": self.sigdb.stats()["rules"]},
            "network": self.net.last_summary,
            "processes": self.procs.last_summary,
            "scan": scan,
            "history": self.scanner.history[:5],
            "system": system,
            "events": self.events.since(since) if since >= 0 else [],
            "last_event_id": self.events.last_id,
        }
