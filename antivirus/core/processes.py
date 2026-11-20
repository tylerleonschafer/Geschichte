"""Prozess-Wächter: findet verdächtige laufende Programme und beendet sie."""
from __future__ import annotations

import os
import re
import time

from . import config
from .scanner import LOCATIONS, MB, scan_command, scan_file, verdict_for

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def base_name(name: str) -> str:
    n = (name or "").strip().lower()
    return n[:-4] if n.endswith(".exe") else n


# Fernwartungs-Programme: legal, aber Betrüger ("Microsoft-Support") nutzen sie gern.
REMOTE_TOOLS = {
    "teamviewer": "TeamViewer", "teamviewer_service": "TeamViewer", "tv_w32": "TeamViewer",
    "tv_x64": "TeamViewer", "anydesk": "AnyDesk", "rustdesk": "RustDesk", "ammyy_admin": "Ammyy Admin",
    "aa_v3": "Ammyy Admin", "supremo": "Supremo", "supremoservice": "Supremo", "ultraviewer": "UltraViewer",
    "ultraviewer_service": "UltraViewer", "ultraviewer_desktop": "UltraViewer",
    "screenconnect.clientservice": "ScreenConnect", "screenconnect.windowsclient": "ScreenConnect",
    "connectwisecontrol.client": "ConnectWise", "srservice": "Splashtop", "strwinclt": "Splashtop",
    "splashtop": "Splashtop", "quickassist": "Windows-Remotehilfe", "rutserv": "Remote Utilities",
    "rfusclient": "Remote Utilities", "tvnserver": "TightVNC", "winvnc": "VNC", "vncserver": "VNC",
    "vncserver-x11": "VNC", "x11vnc": "VNC", "lmiguardiansvc": "LogMeIn", "logmein": "LogMeIn",
    "g2ax_comm_customer": "GoTo Assist", "zohomeeting": "Zoho Assist", "dwrcs": "DameWare",
    "rserver3": "Radmin", "aeroadmin": "AeroAdmin", "hoptodesk": "HopToDesk", "getscreen": "Getscreen",
    "remotepc": "RemotePC", "netsupport": "NetSupport", "client32": "NetSupport",
}

# Werkzeuge, die (fast) nur Angreifer auf einem Heim-PC laufen lassen.
HACK_TOOLS = {
    "mimikatz": "Mimikatz (Passwort-Diebstahl)", "nc": "Netcat", "ncat": "Ncat", "netcat": "Netcat",
    "nc64": "Netcat", "lazagne": "LaZagne (Passwort-Diebstahl)", "rubeus": "Rubeus",
    "sharphound": "SharpHound", "meterpreter": "Meterpreter", "beacon": "Cobalt Strike Beacon",
    "njrat": "njRAT", "darkcomet": "DarkComet", "quasar": "Quasar RAT", "asyncrat": "AsyncRAT",
    "remcos": "Remcos RAT", "nanocore": "NanoCore RAT", "chisel": "Chisel (Tunnel)",
    "frpc": "FRP-Tunnel", "ngrok": "ngrok (macht deinen PC aus dem Internet erreichbar)",
    "hydra": "Hydra (Passwort-Knacker)", "crackmapexec": "CrackMapExec", "plink": "Plink-Tunnel",
}

MINERS = {"xmrig": "XMRig", "xmr-stak": "XMR-Stak", "nanominer": "NanoMiner", "phoenixminer": "PhoenixMiner",
          "t-rex": "T-Rex", "nbminer": "NBMiner", "lolminer": "lolMiner", "minerd": "Miner",
          "cpuminer": "CPU-Miner", "ethminer": "EthMiner", "gminer": "GMiner"}

SHELLS = {"cmd", "powershell", "pwsh", "bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh"}
SCRIPT_HOSTS = {"wscript", "cscript", "mshta", "rundll32", "regsvr32"}

_WIN = os.environ.get("SystemRoot", r"C:\Windows").lower()
_S32, _WOW = _WIN + r"\system32", _WIN + r"\syswow64"
SYSTEM_EXES = {
    "svchost.exe": (_S32, _WOW), "lsass.exe": (_S32,), "csrss.exe": (_S32,), "winlogon.exe": (_S32,),
    "services.exe": (_S32,), "smss.exe": (_S32,), "wininit.exe": (_S32,), "spoolsv.exe": (_S32,),
    "taskhostw.exe": (_S32,), "dwm.exe": (_S32,), "explorer.exe": (_WIN,), "rundll32.exe": (_S32, _WOW),
    "conhost.exe": (_S32,), "dllhost.exe": (_S32, _WOW), "ctfmon.exe": (_S32, _WOW), "sihost.exe": (_S32,),
    "runtimebroker.exe": (_S32,), "searchindexer.exe": (_S32,), "lsm.exe": (_S32,),
    "taskmgr.exe": (_S32, _WOW), "regsvr32.exe": (_S32, _WOW), "cmd.exe": (_S32, _WOW),
    "wmiprvse.exe": (_S32 + r"\wbem", _WOW + r"\wbem"), "audiodg.exe": (_S32,),
    "fontdrvhost.exe": (_S32,), "powershell.exe": (_S32 + r"\windowspowershell\v1.0",
                                                   _WOW + r"\windowspowershell\v1.0"),
}
LOOKALIKE_NAMES = {base_name(n) for n in SYSTEM_EXES} | {"chrome", "firefox", "msedge", "iexplore"}
CRITICAL_WIN = {"system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe",
                "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe",
                "dwm.exe", "memory compression", "secure system", "msmpeng.exe", "explorer.exe"}
CRITICAL_UNIX = {"systemd", "init", "launchd", "kernel_task", "kthreadd", "windowserver", "loginwindow",
                 "xorg", "xwayland", "gnome-shell", "kwin_x11", "kwin_wayland", "plasmashell", "dbus-daemon",
                 "systemd-logind", "gdm", "gdm3", "sddm", "lightdm"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def osa_distance(a: str, b: str) -> int:
    """Tippfehler-Abstand (Damerau-Levenshtein, vereinfacht)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def lookalike(name: str) -> str | None:
    base = base_name(name)
    if len(base) < 5 or base in LOOKALIKE_NAMES:
        return None
    leet = base.translate(LEET)
    for real in LOOKALIKE_NAMES:
        if leet == real or (abs(len(real) - len(base)) <= 1 and osa_distance(base, real) == 1):
            return real
    return None


_ANCESTORS: set[int] = set()


def _ancestors() -> set[int]:
    if not _ANCESTORS and psutil:
        try:
            _ANCESTORS.update(p.pid for p in psutil.Process(os.getpid()).parents())
        except Exception:
            pass
    return _ANCESTORS


def is_protected(pid: int, name: str, exe: str) -> tuple[bool, str]:
    if pid in (0, 1, 4) or pid == os.getpid():
        return True, "das ist ein Kernbestandteil des Systems" if pid != os.getpid() else "das ist Schutzschild selbst"
    if pid in _ancestors():
        return True, "Schutzschild läuft in diesem Programm"
    n = (name or "").lower()
    if config.IS_WINDOWS:
        if n in CRITICAL_WIN:
            allowed = SYSTEM_EXES.get(n)
            if not exe or not allowed or os.path.dirname(exe).lower() in allowed:
                return True, "Windows würde abstürzen, wenn man ihn beendet"
    elif n in CRITICAL_UNIX:
        return True, "das System würde abstürzen oder dich abmelden"
    return False, ""


class ProcessGuard:
    def __init__(self, app):
        self.app = app
        self._hash_cache: dict[str, tuple] = {}
        self.last_summary = {"total": 0, "suspicious": 0, "dangerous": 0, "remote_tools": 0}

    @property
    def available(self) -> bool:
        return psutil is not None

    def _exe_check(self, exe: str, budget: list[int]) -> dict | None:
        """Prüft die Programmdatei (mit Zwischenspeicher, damit es schnell bleibt)."""
        try:
            st = os.stat(exe)
        except OSError:
            return None
        key = (st.st_mtime, st.st_size)
        cached = self._hash_cache.get(exe)
        if cached and cached[0] == key:
            return cached[1]
        if budget[0] <= 0 or st.st_size > 80 * MB:
            return None
        budget[0] -= 1
        try:
            result = scan_file(exe, self.app.sigdb, self.app.allowlist, 80 * MB)
        except (OSError, MemoryError):
            result = None
        self._hash_cache[exe] = (key, result)
        return result

    def evaluate(self, info: dict, budget: list[int]) -> tuple[int, list[dict], bool, str]:
        pid = info.get("pid") or 0
        name = info.get("name") or ""
        exe = info.get("exe") or ""
        cmdline = " ".join(info.get("cmdline") or [])
        base = base_name(name)
        reasons: list[dict] = []

        def add(score, text, family):
            reasons.append({"score": score, "text": text, "family": family, "snippet": ""})

        protected, why = is_protected(pid, name, exe)
        if pid == os.getpid():
            return 0, [], True, why
        if base in HACK_TOOLS:
            add(80, f"Bekanntes Hacker-Werkzeug: {HACK_TOOLS[base]}", "Hacker-Werkzeug")
        if base in MINERS:
            add(60, f"Krypto-Miner ({MINERS[base]}) – nutzt deinen PC zum Geldschürfen", "Krypto-Miner")
        if base in REMOTE_TOOLS:
            add(20, f"Fernwartungs-Software ({REMOTE_TOOLS[base]}) – damit kann jemand deinen PC steuern",
                "Fernzugriff")
        if config.IS_WINDOWS and exe and name.lower() in SYSTEM_EXES:
            if os.path.dirname(exe).lower() not in SYSTEM_EXES[name.lower()]:
                add(75, f"Gibt sich als Windows-Systemprozess „{name}“ aus, liegt aber woanders", "Tarnung")
        real = lookalike(name)
        if real:
            score = 75 if base.translate(LEET) == real else 45
            add(score, f"Name ähnelt dem echten Programm „{real}“ (Tippfehler-Trick)", "Tarnung")
        if base.startswith(("kworker", "kthreadd", "ksoftirqd", "migration/")) and exe:
            add(75, "Tarnt sich als Linux-Kernel-Prozess", "Tarnung")
        if exe.endswith(" (deleted)"):
            add(40, "Programmdatei wurde nach dem Start gelöscht (Spuren verwischt)", "Tarnung")
        elif exe and LOCATIONS.risky(exe):
            add(25, "Läuft aus einem Temp- oder Download-Ordner", "Fundort")
        if cmdline:
            for item in scan_command(cmdline).items:
                add(item["score"], f"Aufruf: {item['text']}", item["family"])
        if exe and not exe.endswith(" (deleted)"):
            res = self._exe_check(exe, budget)
            if res and res.get("score", 0) >= 30:
                for r in res["reasons"][:3]:
                    add(r["score"], f"Programmdatei: {r['text']}", r["family"])
        seen, unique = set(), []
        for r in sorted(reasons, key=lambda r: -r["score"]):
            if r["text"] not in seen:
                seen.add(r["text"])
                unique.append(r)
        return min(100, sum(r["score"] for r in unique)), unique, protected, why

    def snapshot(self) -> dict:
        if not psutil:
            return {"available": False, "processes": [], "summary": self.last_summary}
        cpus = psutil.cpu_count() or 1
        budget = [40]
        out = []
        attrs = ["pid", "name", "exe", "username", "memory_info", "create_time", "cmdline", "ppid"]
        for p in psutil.process_iter(attrs):
            info = p.info
            try:
                cpu = p.cpu_percent(None) / cpus
            except (psutil.Error, OSError):
                cpu = 0.0
            score, reasons, protected, why = self.evaluate(info, budget)
            mem = info.get("memory_info")
            out.append({
                "pid": info["pid"], "ppid": info.get("ppid"), "name": info.get("name") or "?",
                "exe": info.get("exe") or "", "user": (info.get("username") or "").split("\\")[-1],
                "cpu": round(cpu, 1), "mem_mb": round(mem.rss / MB, 1) if mem else 0,
                "started": info.get("create_time"),
                "cmdline": " ".join(info.get("cmdline") or [])[:400],
                "score": score, "verdict": verdict_for(score), "reasons": reasons,
                "protected": protected, "protected_reason": why, "self": info["pid"] == os.getpid(),
            })
        out.sort(key=lambda p: (-p["score"], -p["cpu"], -p["mem_mb"]))
        summary = {"total": len(out),
                   "suspicious": sum(1 for p in out if p["verdict"] == "verdaechtig"),
                   "dangerous": sum(1 for p in out if p["verdict"] == "gefaehrlich"),
                   "remote_tools": sum(1 for p in out if base_name(p["name"]) in REMOTE_TOOLS)}
        self.last_summary = summary
        return {"available": True, "processes": out, "summary": summary, "time": time.time()}

    def kill(self, pid: int, expected_name: str | None = None, tree: bool = True) -> dict:
        if not psutil:
            return {"ok": False, "message": "psutil fehlt – bitte installieren."}
        try:
            proc = psutil.Process(int(pid))
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, OSError):
                exe = ""
        except psutil.NoSuchProcess:
            return {"ok": True, "message": "Prozess war bereits beendet."}
        except psutil.AccessDenied:
            return {"ok": False, "message": "Zugriff verweigert – starte Schutzschild als Administrator."}
        if expected_name and name.lower() != expected_name.lower():
            return {"ok": False, "message": "Der Prozess hat sich inzwischen geändert – bitte neu laden."}
        protected, why = is_protected(proc.pid, name, exe)
        if protected:
            return {"ok": False, "message": f"{name} ist geschützt: {why}."}
        victims = [proc]
        if tree:
            try:
                victims += [c for c in proc.children(recursive=True)
                            if not is_protected(c.pid, c.name(), "")[0]]
            except psutil.Error:
                pass
        for v in victims:
            try:
                v.terminate()
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                return {"ok": False, "message": f"Zugriff auf {name} verweigert – starte als Administrator."}
        _, alive = psutil.wait_procs(victims, timeout=3)
        for v in alive:
            try:
                v.kill()
            except psutil.Error:
                pass
        _, alive = psutil.wait_procs(alive, timeout=2)
        if alive:
            return {"ok": False, "message": f"{name} ließ sich nicht beenden."}
        extra = f" (+ {len(victims) - 1} Unterprozesse)" if len(victims) > 1 else ""
        return {"ok": True, "message": f"{name} (PID {pid}) wurde beendet{extra}.", "exe": exe, "name": name}

    def summary_line(self, pid: int) -> str:
        try:
            return psutil.Process(pid).name()
        except Exception:
            return f"PID {pid}"


_SAFE_PID = re.compile(r"^\d{1,9}$")


def parse_pid(value) -> int:
    if not _SAFE_PID.match(str(value)):
        raise ValueError("Ungültige Prozess-ID.")
    return int(value)
