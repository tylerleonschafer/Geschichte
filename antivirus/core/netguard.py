"""Netzwerk-Wächter: erkennt Eindringlinge und wirft sie raus.

Ein "Rauswurf" besteht aus drei Schritten:
  1. Die IP des Angreifers in der Firewall sperren (er kommt nicht wieder rein)
  2. Die bestehende Verbindung sofort kappen
  3. Das Programm beenden, über das die Verbindung lief (z. B. eine Hintertür)
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
import socket
import struct
import threading
import time

from . import config
from .firewall import FirewallError, run
from .processes import HACK_TOOLS, REMOTE_TOOLS, SCRIPT_HOSTS, SHELLS, base_name, is_protected
from .scanner import LOCATIONS, verdict_for

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

REMOTE_ACCESS_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "Remotedesktop (RDP)", 5900: "VNC", 5901: "VNC", 5902: "VNC",
    5938: "TeamViewer", 7070: "AnyDesk", 6568: "AnyDesk", 21118: "RustDesk", 4899: "Radmin",
    5985: "WinRM", 5986: "WinRM", 445: "Windows-Dateifreigabe (SMB)", 3283: "Apple Remote Desktop",
    5631: "pcAnywhere",
}
BACKDOOR_PORTS = {
    4444: "Metasploit", 1337: "„Elite“-Hackerport", 31337: "Back Orifice", 12345: "NetBus",
    27374: "SubSeven", 6666: "IRC-Botnetz", 6667: "IRC-Botnetz", 5552: "njRAT", 1604: "DarkComet",
    4782: "Quasar RAT", 6606: "AsyncRAT", 7707: "AsyncRAT", 8808: "AsyncRAT", 2404: "Remcos RAT",
    54984: "NanoCore RAT", 50050: "Cobalt Strike",
}
MINING_PORTS = {3333, 5555, 7777, 14433, 14444, 45560, 45700}
STATUS_DE = {"ESTABLISHED": "Verbunden", "LISTEN": "Lauscht", "TIME_WAIT": "Wird beendet",
             "CLOSE_WAIT": "Schließt", "SYN_SENT": "Verbindet …", "SYN_RECV": "Verbindet …",
             "FIN_WAIT1": "Schließt", "FIN_WAIT2": "Schließt", "LAST_ACK": "Schließt", "CLOSING": "Schließt",
             "CLOSE": "Geschlossen", "NONE": "–"}


_OWN_IPS: dict[str, object] = {"time": 0.0, "ips": set()}


def own_ips() -> set[str]:
    """Alle IP-Adressen dieses Computers (Verbindungen dorthin sind 'lokal')."""
    if psutil and time.time() - _OWN_IPS["time"] > 60:
        ips = set()
        try:
            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        ips.add(_clean_ip(a.address))
        except (OSError, psutil.Error):
            pass
        _OWN_IPS.update(time=time.time(), ips=ips)
    return _OWN_IPS["ips"]  # type: ignore[return-value]


def ip_kind(ip: str) -> str:
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unbekannt"
    if addr.is_loopback or (ip in own_ips() and not addr.is_unspecified):
        return "lokal"
    if addr.is_unspecified:
        return "alle"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private or addr.is_link_local:
        return "heimnetz"
    return "internet"


def _clean_ip(ip: str) -> str:
    ip = ip or ""
    if ip.lower().startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip.split("%")[0]


def _fmt(ip: str, port: int) -> str:
    if not ip:
        return ""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def cut_connection(lip: str, lport: int, rip: str, rport: int) -> tuple[bool, str]:
    """Trennt eine einzelne TCP-Verbindung, ohne das Programm zu beenden."""
    if not (lip and rip and lport and rport):
        return False, "Keine aktive Verbindung zum Trennen"
    if not config.is_admin():
        return False, "Zum Trennen werden Administratorrechte benötigt"
    if config.IS_WINDOWS:
        if ":" in lip or ":" in rip:
            return False, "Direktes Trennen geht unter Windows nur bei IPv4"
        try:
            import ctypes
            from ctypes import wintypes

            class MIB_TCPROW(ctypes.Structure):
                _fields_ = [("dwState", wintypes.DWORD), ("dwLocalAddr", wintypes.DWORD),
                            ("dwLocalPort", wintypes.DWORD), ("dwRemoteAddr", wintypes.DWORD),
                            ("dwRemotePort", wintypes.DWORD)]

            row = MIB_TCPROW(12,  # MIB_TCP_STATE_DELETE_TCB
                             struct.unpack("<I", socket.inet_aton(lip))[0], socket.htons(lport),
                             struct.unpack("<I", socket.inet_aton(rip))[0], socket.htons(rport))
            code = ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row))
        except Exception as exc:
            return False, f"Fehler: {exc}"
        if code == 0:
            return True, "Verbindung gekappt"
        return False, f"Windows-Fehler {code}"
    if config.IS_LINUX:
        if not shutil.which("ss"):
            return False, "Werkzeug „ss“ fehlt"
        dst = f"[{rip}]:{rport}" if ":" in rip else f"{rip}:{rport}"
        src = f"[{lip}]:{lport}" if ":" in lip else f"{lip}:{lport}"
        rc, out = run(["ss", "-K", "-t", "-n", "dst", dst, "src", src])
        if rc == 0 and str(rport) in out:
            return True, "Verbindung gekappt"
        return False, "Der Kernel erlaubt das Trennen nicht – das Programm wird stattdessen beendet"
    return False, "Unter macOS nicht möglich – das Programm wird stattdessen beendet"


class NetGuard:
    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()
        self.last_summary = {"total": 0, "established": 0, "internet": 0, "listening": 0, "suspicious": 0,
                             "dangerous": 0, "remote_sessions": 0, "time": 0}
        self._alerted: dict[str, float] = {}

    @property
    def available(self) -> bool:
        return psutil is not None

    # -- Daten sammeln ----------------------------------------------------------
    @staticmethod
    def _raw() -> list[dict]:
        def norm(c, pid):
            laddr = (_clean_ip(c.laddr.ip), c.laddr.port) if c.laddr else ("", 0)
            raddr = (_clean_ip(c.raddr.ip), c.raddr.port) if c.raddr else ("", 0)
            return {"pid": pid, "type": c.type, "laddr": laddr, "raddr": raddr, "status": c.status}

        try:
            return [norm(c, c.pid) for c in psutil.net_connections(kind="inet")]
        except psutil.AccessDenied:
            result = []  # macOS ohne Admin: Prozess für Prozess abfragen
            for p in psutil.process_iter(["pid"]):
                try:
                    getter = getattr(p, "net_connections", None) or p.connections
                    result += [norm(c, p.pid) for c in getter(kind="inet")]
                except (psutil.Error, OSError):
                    continue
            return result

    def snapshot(self) -> dict:
        if not psutil:
            return {"available": False, "connections": [], "summary": self.last_summary,
                    "blocked": self.app.firewall.list()}
        raw = self._raw()
        procs = {}
        for p in psutil.process_iter(["pid", "name", "exe"]):
            procs[p.info["pid"]] = p.info
        blocked = self.app.firewall.blocked_set()
        listen_ports = {c["laddr"][1] for c in raw if c["status"] == "LISTEN"}
        conns = []
        for c in raw:
            if c["status"] in ("TIME_WAIT", "CLOSE") and not c["pid"]:
                continue
            conns.append(self._evaluate(c, listen_ports, procs, blocked))
        conns.sort(key=lambda c: (-c["score"], c["direction"] != "eingehend", c["process"].lower()))
        summary = {
            "total": len(conns),
            "established": sum(1 for c in conns if c["status_raw"] == "ESTABLISHED"),
            "internet": sum(1 for c in conns if c["kind"] == "internet" and c["status_raw"] == "ESTABLISHED"),
            "listening": sum(1 for c in conns if c["direction"] == "lauscht" and c["kind"] not in ("lokal",)),
            "suspicious": sum(1 for c in conns if c["verdict"] == "verdaechtig"),
            "dangerous": sum(1 for c in conns if c["verdict"] == "gefaehrlich"),
            "remote_sessions": sum(1 for c in conns if c["remote_session"]),
            "time": time.time(),
        }
        self.last_summary = summary
        return {"available": True, "connections": conns, "summary": summary,
                "blocked": self.app.firewall.list(), "admin": config.is_admin(),
                "firewall": self.app.firewall.backend()}

    def _evaluate(self, c: dict, listen_ports: set, procs: dict, blocked: set) -> dict:
        pid = c["pid"] or 0
        info = procs.get(pid) or {}
        pname = info.get("name") or ("System" if pid in (0, 4) else "?")
        exe = info.get("exe") or ""
        base = base_name(pname)
        lip, lport = c["laddr"]
        rip, rport = c["raddr"]
        status = c["status"] or "NONE"
        proto = "TCP" if c["type"] == socket.SOCK_STREAM else "UDP"
        if status == "LISTEN" or (proto == "UDP" and not rip):
            direction = "lauscht"
        elif lport in listen_ports:
            direction = "eingehend"
        else:
            direction = "ausgehend"
        kind = ip_kind(rip) if rip else ip_kind(lip)
        reasons: list[str] = []
        score = 0

        def add(points: int, text: str):
            nonlocal score
            score += points
            reasons.append(text)

        established = status == "ESTABLISHED"
        remote = kind in ("internet", "heimnetz")
        remote_session = False
        if rip and rip in blocked:
            add(95, "Diese IP steht auf deiner Sperrliste")
        if base in HACK_TOOLS:
            add(80, f"Bekanntes Hacker-Werkzeug: {HACK_TOOLS[base]}")
        if base in REMOTE_TOOLS and established and remote:
            remote_session = True
            add(40, f"{REMOTE_TOOLS[base]} ist online – damit kann jemand deinen PC fernsteuern. "
                    "Betrüger („Microsoft-Support“) nutzen genau das!")
        if direction == "eingehend" and established and lport in REMOTE_ACCESS_PORTS:
            svc = REMOTE_ACCESS_PORTS[lport]
            remote_session = remote_session or remote
            if kind == "internet":
                add(85, f"Jemand aus dem Internet ist per {svc} mit deinem PC verbunden!")
            elif kind == "heimnetz":
                add(45, f"Ein Gerät aus deinem Heimnetz ist per {svc} mit deinem PC verbunden")
        if direction == "lauscht" and kind in ("alle", "internet", "heimnetz") and lport in BACKDOOR_PORTS:
            add(75, f"Offener Hintertür-Port {lport} ({BACKDOOR_PORTS[lport]})")
        if direction == "eingehend" and remote and lport in BACKDOOR_PORTS:
            add(70, f"Fremder Rechner hängt an Hintertür-Port {lport} ({BACKDOOR_PORTS[lport]})")
        if direction == "ausgehend" and remote and rport in BACKDOOR_PORTS:
            add(65, f"Verbindung zu typischem Hacker-Port {rport} ({BACKDOOR_PORTS[rport]})")
        if direction == "ausgehend" and kind == "internet" and rport in MINING_PORTS:
            add(40, f"Mögliche Verbindung zu einem Krypto-Mining-Pool (Port {rport})")
        if base in SHELLS:
            if direction == "lauscht" and kind not in ("lokal", ""):
                add(80, "Eine Konsole wartet auf Verbindungen von außen (Bind-Shell)")
            elif established and remote:
                if rport in (80, 443):
                    add(45, "Eine Konsole lädt Daten aus dem Internet")
                else:
                    add(80, "Eine Konsole ist direkt mit einem fremden Rechner verbunden (Reverse-Shell?)")
        if base in SCRIPT_HOSTS and remote and status in ("ESTABLISHED", "SYN_SENT"):
            add(65, f"Windows-Hilfsprogramm {pname} hat eine Internetverbindung (typisch für Schadsoftware)")
        if exe and remote and status in ("ESTABLISHED", "LISTEN", "SYN_SENT") and LOCATIONS.risky(exe):
            add(30, "Das Programm läuft aus einem Temp- oder Download-Ordner")
        if direction == "lauscht" and kind == "alle" and lport in REMOTE_ACCESS_PORTS:
            add(15, f"{REMOTE_ACCESS_PORTS[lport]} ist von außen erreichbar (Port {lport} offen)")
        if kind == "lokal" and score > 20:
            score = 20
            reasons.append("Nur innerhalb deines PCs – keine Gefahr von außen")
        is_self = pid == os.getpid()
        if is_self:
            score, reasons = 0, ["Das ist Schutzschild selbst"]
        score = min(100, score)
        protected, why = is_protected(pid, pname, exe) if pid else (True, "Systemverbindung")
        key = f"{pid}|{lip}|{lport}|{rip}|{rport}|{status}"
        return {
            "id": hashlib.sha1(key.encode()).hexdigest()[:12], "pid": pid, "process": pname, "exe": exe,
            "proto": proto, "local": _fmt(lip, lport), "remote": _fmt(rip, rport), "local_ip": lip,
            "local_port": lport, "remote_ip": rip, "remote_port": rport, "kind": kind,
            "direction": direction, "status": STATUS_DE.get(status, status.title()), "status_raw": status,
            "score": score, "verdict": verdict_for(score), "reasons": reasons, "protected": protected,
            "protected_reason": why, "self": is_self, "blocked": bool(rip and rip in blocked),
            "remote_session": remote_session,
        }

    # -- Rauswurf ---------------------------------------------------------------
    def kick(self, data: dict, source: str = "manuell") -> dict:
        try:
            pid = int(data.get("pid") or 0)
            lport = int(data.get("local_port") or 0)
            rport = int(data.get("remote_port") or 0)
        except (TypeError, ValueError):
            raise ValueError("Ungültige Verbindungsdaten.")
        name = str(data.get("process") or "")[:120]
        rip = _clean_ip(str(data.get("remote_ip") or ""))
        lip = _clean_ip(str(data.get("local_ip") or ""))
        do_block = bool(data.get("block", True)) and ip_kind(rip) in ("internet", "heimnetz")
        do_kill = bool(data.get("kill", True)) and pid > 0
        steps = []
        if do_block:
            try:
                entry = self.app.firewall.block(rip, f"Rauswurf ({name or 'unbekannt'})")
                steps.append({"step": "Firewall-Sperre", "ok": entry["applied"], "message": entry["message"]})
            except FirewallError as exc:
                steps.append({"step": "Firewall-Sperre", "ok": False, "message": str(exc)})
        if rip and rport and lport and str(data.get("proto", "TCP")) == "TCP":
            ok, msg = cut_connection(lip, lport, rip, rport)
            steps.append({"step": "Verbindung kappen", "ok": ok, "message": msg})
        if do_kill:
            res = self.app.procs.kill(pid, expected_name=name or None)
            steps.append({"step": "Programm beenden", "ok": res["ok"], "message": res["message"]})
        success = any(s["ok"] for s in steps)
        who = f"{name or 'Unbekannt'}" + (f" ↔ {rip}" if rip else "")
        detail = " · ".join(f"{s['step']}: {'✓' if s['ok'] else '✗'} {s['message']}" for s in steps)
        prefix = "Automatischer Rauswurf" if source == "auto" else "Rauswurf"
        self.app.events.add("ok" if success else "warn", "Hacker-Abwehr",
                            f"{prefix}: {who} {'erfolgreich' if success else 'nur teilweise möglich'}", detail)
        return {"ok": success, "steps": steps}

    def kick_all(self) -> dict:
        snap = self.snapshot()
        done, results = set(), []
        for c in snap["connections"]:
            if c["score"] < 70 or c["self"]:
                continue
            key = (c["pid"], c["remote_ip"])
            if key in done:
                continue
            done.add(key)
            payload = dict(c, block=bool(c["remote_ip"]), kill=not c["protected"])
            results.append({"process": c["process"], "remote": c["remote"], **self.kick(payload)})
        if not results:
            self.app.events.add("info", "Hacker-Abwehr", "Panik-Knopf: keine gefährlichen Verbindungen gefunden")
        return {"count": len(results), "results": results}

    # -- Wächter ------------------------------------------------------------------
    def guard_tick(self) -> None:
        if not psutil:
            return
        snap = self.snapshot()
        now = time.time()
        auto = self.app.settings.get("auto_kick")
        for c in snap["connections"]:
            if c["self"] or c["score"] < 40:
                continue
            key = f"{c['pid']}|{c['remote_ip'] or c['local']}|{c['score'] >= 70}"
            if now - self._alerted.get(key, 0) < 600:
                continue
            self._alerted[key] = now
            who = f"{c['process']} (PID {c['pid']})" + (f" ↔ {c['remote']}" if c["remote"] else f" auf {c['local']}")
            if c["score"] >= 70:
                self.app.events.add("danger", "Hacker-Abwehr", f"Gefährliche Verbindung: {who}",
                                    " · ".join(c["reasons"]))
                if auto:
                    self.kick(dict(c, block=bool(c["remote_ip"]), kill=not c["protected"]), source="auto")
            else:
                self.app.events.add("warn", "Hacker-Abwehr", f"Verdächtige Verbindung: {who}",
                                    " · ".join(c["reasons"]))
        if len(self._alerted) > 2000:
            self._alerted = {k: v for k, v in self._alerted.items() if now - v < 600}
