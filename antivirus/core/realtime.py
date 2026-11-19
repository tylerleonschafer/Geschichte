"""Echtzeitschutz & Wächter-Threads, die im Hintergrund laufen."""
from __future__ import annotations

import os
import threading
import time

from .scanner import MB, MALICIOUS, SUSPICIOUS, scan_file

PARTIAL_EXT = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload")


class RealtimeWatcher(threading.Thread):
    """Beobachtet z. B. den Download-Ordner und prüft jede neue Datei sofort."""

    def __init__(self, app, interval: float = 2.0):
        super().__init__(daemon=True, name="echtzeitschutz")
        self.app = app
        self.interval = interval
        self.stop_event = threading.Event()
        self._known: dict[str, tuple] = {}
        self._pending: dict[str, tuple] = {}
        self._folders: tuple = ()

    def _snapshot(self, folders) -> dict[str, tuple]:
        result: dict[str, tuple] = {}
        for folder in folders:
            stack = [(folder, 0)]
            while stack and len(result) < 30_000:
                current, depth = stack.pop()
                try:
                    with os.scandir(current) as it:
                        for entry in it:
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    if depth < 2:
                                        stack.append((entry.path, depth + 1))
                                elif entry.is_file(follow_symlinks=False):
                                    st = entry.stat(follow_symlinks=False)
                                    result[entry.path] = (st.st_mtime, st.st_size)
                            except OSError:
                                continue
                except OSError:
                    continue
        return result

    def run(self) -> None:
        while not self.stop_event.wait(self.interval):
            try:
                self._tick()
            except Exception as exc:  # pragma: no cover
                self.app.events.add("warn", "Echtzeitschutz", "Fehler im Echtzeitschutz", str(exc))
                self.stop_event.wait(10)

    def _tick(self) -> None:
        if not self.app.settings.get("realtime"):
            self._folders = ()
            return
        folders = tuple(f for f in self.app.settings.get("watch_folders") if os.path.isdir(f))
        current = self._snapshot(folders)
        if folders != self._folders:  # neue Ordnerliste: erst einmal nur merken
            self._folders = folders
            self._known = current
            self._pending.clear()
            return
        for path, sig in current.items():
            if self._known.get(path) != sig and not path.lower().endswith(PARTIAL_EXT):
                self._pending[path] = sig
        self._known = current
        for path, sig in list(self._pending.items()):
            if current.get(path) is None:
                del self._pending[path]
            elif current[path] == sig and self._stable(path, sig):
                del self._pending[path]
                self._check(path)

    @staticmethod
    def _stable(path: str, sig: tuple) -> bool:
        return time.time() - sig[0] >= 1.5

    def _check(self, path: str) -> None:
        max_bytes = self.app.settings.get("max_file_mb") * MB
        try:
            result = scan_file(path, self.app.sigdb, self.app.allowlist, max_bytes)
        except (OSError, MemoryError):
            return
        if not result or result["score"] < SUSPICIOUS:
            return
        tid = self.app.threats.add(result, "Echtzeitschutz")
        name = result["name"]
        top = result["reasons"][0]["text"] if result["reasons"] else ""
        if result["score"] >= MALICIOUS and self.app.settings.get("auto_quarantine"):
            outcome = self.app.threat_action(tid, "quarantine", quiet=True)
            if outcome.get("ok"):
                self.app.events.add("danger", "Echtzeitschutz",
                                    f"Gefahr gebannt: „{name}“ wurde in Quarantäne gesperrt", top)
                return
        level = "danger" if result["score"] >= MALICIOUS else "warn"
        word = "Gefährliche" if level == "danger" else "Verdächtige"
        self.app.events.add(level, "Echtzeitschutz", f"{word} Datei entdeckt: „{name}“", top)


class GuardThread(threading.Thread):
    """Überprüft regelmäßig Netzwerkverbindungen und Prozesse."""

    def __init__(self, app):
        super().__init__(daemon=True, name="waechter")
        self.app = app
        self.stop_event = threading.Event()
        self._proc_alerts: dict[tuple, float] = {}
        self._ticks = 0

    def run(self) -> None:
        self.stop_event.wait(3)
        while not self.stop_event.is_set():
            interval = self.app.settings.get("guard_interval")
            if self.app.settings.get("guard"):
                try:
                    self.app.net.guard_tick()
                    if self._ticks % 3 == 0:
                        self._check_processes()
                except Exception as exc:  # pragma: no cover
                    self.app.events.add("warn", "Wächter", "Fehler im Netzwerk-Wächter", str(exc))
                self._ticks += 1
            self.stop_event.wait(interval)

    def _check_processes(self) -> None:
        if not self.app.procs.available:
            return
        now = time.time()
        for p in self.app.procs.snapshot()["processes"]:
            if p["score"] < MALICIOUS or p["self"]:
                continue
            key = (p["pid"], p["name"])
            if now - self._proc_alerts.get(key, 0) < 900:
                continue
            self._proc_alerts[key] = now
            reason = p["reasons"][0]["text"] if p["reasons"] else ""
            self.app.events.add("danger", "Prozesse", f"Gefährlicher Prozess: {p['name']} (PID {p['pid']})", reason)
