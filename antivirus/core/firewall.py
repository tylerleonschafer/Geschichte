"""Firewall-Sperren: hält rausgeworfene Angreifer dauerhaft draußen.

Windows: Regeln in der Windows-Firewall (netsh)
Linux:   iptables/ip6tables (oder eine Blackhole-Route, falls iptables fehlt)
macOS:   Blackhole-Route
Ohne Administratorrechte wird die IP trotzdem gemerkt: der Netzwerk-Wächter
markiert dann jede Verbindung dorthin als gefährlich.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import threading
import time
from pathlib import Path

from . import config

RULE_PREFIX = "Schutzschild-Sperre"


class FirewallError(Exception):
    pass


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    kwargs = {}
    if config.IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, **kwargs)
    except FileNotFoundError:
        return 127, f"{cmd[0]} nicht gefunden"
    except subprocess.TimeoutExpired:
        return 124, "Zeitüberschreitung"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def validate_ip(value: str) -> str:
    value = (value or "").strip()
    if value.lower().startswith("::ffff:"):
        value = value[7:]
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise FirewallError(f"„{value}“ ist keine gültige IP-Adresse.")
    if ip.is_loopback or ip.is_unspecified:
        raise FirewallError("Diese Adresse gehört zu deinem eigenen Computer und kann nicht gesperrt werden.")
    if ip.is_multicast:
        raise FirewallError("Multicast-Adressen können nicht gesperrt werden.")
    try:
        from .netguard import own_ips
        if str(ip) in own_ips():
            raise FirewallError("Das ist die IP-Adresse deines eigenen Computers – die kann nicht gesperrt werden.")
    except ImportError:
        pass
    return str(ip)


class Firewall:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        data = config.read_json(path, {})
        self.entries: dict[str, dict] = data if isinstance(data, dict) else {}

    # -- Backend -------------------------------------------------------------
    @staticmethod
    def backend() -> str:
        if config.IS_WINDOWS:
            return "windows-firewall"
        if config.IS_LINUX and shutil.which("iptables"):
            return "iptables"
        if config.IS_LINUX and shutil.which("ip"):
            return "blackhole-route"
        if config.IS_MAC:
            return "blackhole-route"
        return "keins"

    def _apply(self, ip: str) -> tuple[bool, str]:
        if not config.is_admin():
            return False, ("Nicht als Administrator gestartet – die IP ist auf der Sperrliste, "
                           "aber die Firewall-Regel fehlt noch.")
        v6 = ":" in ip
        backend = self.backend()
        if backend == "windows-firewall":
            name = f"name={RULE_PREFIX}-{ip}"
            results = [run(["netsh", "advfirewall", "firewall", "add", "rule", name, f"dir={d}",
                            "action=block", f"remoteip={ip}", "enable=yes"]) for d in ("in", "out")]
            bad = [out for rc, out in results if rc != 0]
            return (not bad), ("Windows-Firewall-Regel erstellt" if not bad else f"netsh-Fehler: {bad[0][:200]}")
        if backend == "iptables":
            tool = "ip6tables" if v6 else "iptables"
            if not shutil.which(tool):
                return False, f"{tool} ist nicht installiert"
            for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
                rule = [chain, flag, ip, "-m", "comment", "--comment", RULE_PREFIX, "-j", "DROP"]
                if run([tool, "-C", *rule])[0] != 0:
                    rc, out = run([tool, "-I", *rule])
                    if rc != 0:
                        return False, f"{tool}-Fehler: {out[:200]}"
            return True, f"{tool}-Regel erstellt"
        if backend == "blackhole-route":
            if config.IS_MAC:
                cmd = ["route", "-n", "add", "-inet6" if v6 else "-inet", "-host", ip,
                       "::1" if v6 else "127.0.0.1", "-blackhole"]
            else:
                cmd = ["ip", "-6" if v6 else "-4", "route", "replace", "blackhole", ip]
            rc, out = run(cmd)
            return rc == 0, ("Datenverkehr zu dieser IP wird verworfen" if rc == 0 else f"Fehler: {out[:200]}")
        return False, "Auf diesem System gibt es keine unterstützte Firewall."

    def _remove(self, ip: str) -> tuple[bool, str]:
        if not config.is_admin():
            return False, "Zum Entfernen der Firewall-Regel werden Administratorrechte benötigt."
        v6 = ":" in ip
        backend = self.backend()
        if backend == "windows-firewall":
            rc, out = run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}-{ip}"])
            return rc == 0, out[:200]
        if backend == "iptables":
            tool = "ip6tables" if v6 else "iptables"
            for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
                rule = [chain, flag, ip, "-m", "comment", "--comment", RULE_PREFIX, "-j", "DROP"]
                while run([tool, "-C", *rule])[0] == 0:
                    if run([tool, "-D", *rule])[0] != 0:
                        break
            return True, "Regel entfernt"
        if backend == "blackhole-route":
            if config.IS_MAC:
                cmd = ["route", "-n", "delete", "-inet6" if v6 else "-inet", "-host", ip]
            else:
                cmd = ["ip", "-6" if v6 else "-4", "route", "del", "blackhole", ip]
            rc, out = run(cmd)
            return rc == 0, out[:200]
        return False, "Keine Firewall verfügbar"

    def _save(self) -> None:
        config.write_json(self.path, self.entries)

    # -- Öffentliche Funktionen ---------------------------------------------------
    def block(self, ip: str, reason: str = "") -> dict:
        ip = validate_ip(ip)
        applied, message = self._apply(ip)
        with self._lock:
            old = self.entries.get(ip, {})
            self.entries[ip] = {"ip": ip, "reason": (reason or old.get("reason") or "Manuell gesperrt")[:200],
                                "date": old.get("date") or time.time(),
                                "applied": applied or bool(old.get("applied")), "message": message,
                                "private": ipaddress.ip_address(ip).is_private}
            self._save()
            return dict(self.entries[ip])

    def unblock(self, ip: str) -> dict:
        ip = (ip or "").strip()
        with self._lock:
            entry = self.entries.get(ip)
            if not entry:
                raise FirewallError("Diese IP steht nicht auf der Sperrliste.")
        ok, message = self._remove(ip) if entry.get("applied") else (True, "")
        if entry.get("applied") and not ok:
            raise FirewallError(message or "Firewall-Regel konnte nicht entfernt werden.")
        with self._lock:
            self.entries.pop(ip, None)
            self._save()
        return {"ip": ip, "message": message}

    def reapply(self) -> None:
        """Nach einem Neustart: Regeln wiederherstellen (iptables vergisst sie sonst)."""
        if not config.is_admin() or not self.entries:
            return
        for ip in list(self.entries):
            if self.backend() == "windows-firewall" and self.entries[ip].get("applied"):
                continue
            applied, message = self._apply(ip)
            with self._lock:
                if ip in self.entries:
                    self.entries[ip].update(applied=applied, message=message)
        with self._lock:
            self._save()

    def blocked_set(self) -> set[str]:
        with self._lock:
            return set(self.entries)

    def list(self) -> list[dict]:
        with self._lock:
            return sorted((dict(e) for e in self.entries.values()), key=lambda e: -e.get("date", 0))
