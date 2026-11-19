"""Grundeinstellungen, Pfade und Plattform-Helfer für Schutzschild."""
from __future__ import annotations

import json
import os
import platform
import re
import sys
import tempfile
import threading
from pathlib import Path

APP_NAME = "Schutzschild"
VERSION = "1.0.0"

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

BASE_DIR = Path(__file__).resolve().parent.parent
UI_DIR = BASE_DIR / "ui"
SIGNATURE_DIR = BASE_DIR / "signaturen"


def user_home() -> Path:
    """Home-Ordner des echten Benutzers – auch wenn mit sudo gestartet."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root" and not IS_WINDOWS:
        candidate = Path(os.path.expanduser(f"~{sudo_user}"))
        if candidate.is_dir():
            return candidate
    return Path.home()


HOME = user_home()
DATA_DIR = Path(os.environ.get("SCHUTZSCHILD_HOME") or HOME / ".schutzschild")
QUARANTINE_DIR = DATA_DIR / "quarantaene"
SETTINGS_FILE = DATA_DIR / "einstellungen.json"
EVENTS_FILE = DATA_DIR / "protokoll.jsonl"
BLOCKLIST_FILE = DATA_DIR / "sperrliste.json"
ALLOWLIST_FILE = DATA_DIR / "vertrauenswuerdig.json"
CUSTOM_SIG_FILE = DATA_DIR / "eigene_signaturen.txt"
ONLINE_SIG_FILE = DATA_DIR / "online_signaturen.txt"
HISTORY_FILE = DATA_DIR / "scan_verlauf.json"


# --------------------------------------------------------------------------
# Dateien & Rechte
# --------------------------------------------------------------------------

def fix_owner(path: Path) -> None:
    """Wurde per sudo gestartet, gehören neue Dateien wieder dem echten Benutzer."""
    if IS_WINDOWS or os.geteuid() != 0:
        return
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass


def ensure_dirs() -> None:
    for directory in (DATA_DIR, QUARANTINE_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        fix_owner(directory)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    fix_owner(path)


def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def platform_name() -> str:
    if IS_WINDOWS:
        release = platform.release()
        try:
            if release == "10" and int(platform.version().split(".")[-1]) >= 22000:
                release = "11"
        except ValueError:
            pass
        return f"Windows {release}"
    if IS_MAC:
        return f"macOS {platform.mac_ver()[0]}"
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Linux"


# --------------------------------------------------------------------------
# Wichtige Ordner
# --------------------------------------------------------------------------

def _unique_existing(paths) -> list[Path]:
    seen, result = set(), []
    for p in paths:
        try:
            if not p or not p.is_dir():
                continue
            key = os.path.normcase(str(p.resolve()))
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            result.append(p)
    return result


def _win_known_folder(guid: str) -> Path | None:
    """Fragt Windows nach dem echten Pfad (z. B. Desktop im OneDrive)."""
    try:
        import ctypes
        import uuid
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        u = uuid.UUID(guid)
        g = GUID(u.fields[0], u.fields[1], u.fields[2], (ctypes.c_ubyte * 8)(*u.bytes[8:]))
        out = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out)) != 0:
            return None
        value = out.value
        ctypes.windll.ole32.CoTaskMemFree(out)
        return Path(value) if value else None
    except Exception:
        return None


def _xdg_dir(key: str, fallback: str) -> Path:
    cfg = HOME / ".config" / "user-dirs.dirs"
    try:
        for line in cfg.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"XDG_{key}_DIR="):
                value = line.split("=", 1)[1].strip().strip('"')
                return Path(value.replace("$HOME", str(HOME)))
    except OSError:
        pass
    return HOME / fallback


def downloads_dir() -> Path:
    if IS_WINDOWS:
        p = _win_known_folder("374DE290-123F-4565-9164-39C4925E467B")
        if p:
            return p
    if IS_LINUX:
        return _xdg_dir("DOWNLOAD", "Downloads")
    return HOME / "Downloads"


def desktop_dirs() -> list[Path]:
    candidates = []
    if IS_WINDOWS:
        candidates.append(_win_known_folder("B4BFCC3A-DB2C-424C-B029-7FE99A87C641"))
    if IS_LINUX:
        candidates.append(_xdg_dir("DESKTOP", "Desktop"))
    candidates += [HOME / "Desktop", HOME / "OneDrive" / "Desktop", HOME / "Schreibtisch"]
    return _unique_existing(candidates)


def temp_dirs() -> list[Path]:
    candidates = [Path(tempfile.gettempdir())]
    if IS_WINDOWS:
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        candidates.append(Path(windir) / "Temp")
    else:
        candidates += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    return _unique_existing(candidates)


def autostart_dirs() -> list[Path]:
    if IS_WINDOWS:
        candidates = []
        for var, sub in (("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
                         ("PROGRAMDATA", r"Microsoft\Windows\Start Menu\Programs\StartUp")):
            base = os.environ.get(var)
            if base:
                candidates.append(Path(base) / sub)
    elif IS_MAC:
        candidates = [HOME / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
                      Path("/Library/LaunchDaemons")]
    else:
        candidates = [HOME / ".config/autostart", Path("/etc/xdg/autostart"),
                      HOME / ".local/bin", Path("/etc/cron.d"), Path("/etc/systemd/system")]
    return _unique_existing(candidates)


def windows_run_entries() -> list[dict]:
    """Liest die Autostart-Einträge aus der Windows-Registry."""
    if not IS_WINDOWS:
        return []
    import winreg
    keys = [
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    entries = []
    for hive, label, sub in keys:
        try:
            with winreg.OpenKey(hive, sub) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if isinstance(value, str) and value.strip():
                        entries.append({"hive": label, "key": sub, "name": name, "command": value})
        except OSError:
            continue
    return entries


def remove_windows_run_entry(hive: str, key: str, name: str) -> None:
    import winreg
    root = winreg.HKEY_CURRENT_USER if hive == "HKCU" else winreg.HKEY_LOCAL_MACHINE
    with winreg.OpenKey(root, key, 0, winreg.KEY_SET_VALUE) as handle:
        winreg.DeleteValue(handle, name)


def command_target(command: str) -> Path | None:
    """Findet die Programmdatei in einer Befehlszeile wie '"C:\\x\\y.exe" -start'."""
    cmd = os.path.expandvars(command.strip())
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        exe = cmd[1:end] if end > 0 else cmd[1:]
    else:
        m = re.match(r"(.+?\.(exe|bat|cmd|vbs|js|ps1|scr|com))(\s|$)", cmd, re.IGNORECASE)
        exe = m.group(1) if m else (cmd.split() or [""])[0]
    try:
        p = Path(exe)
        return p if exe and p.is_file() else None
    except OSError:
        return None


# --------------------------------------------------------------------------
# Einstellungen
# --------------------------------------------------------------------------

class Settings:
    BOOL_KEYS = ("realtime", "guard", "auto_kick", "auto_quarantine", "notifications")
    INT_KEYS = {"max_file_mb": (1, 4096), "guard_interval": (2, 60)}
    LIST_KEYS = ("watch_folders", "exclusions")

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self.data = self.defaults()
        stored = read_json(path, {})
        if isinstance(stored, dict):
            try:
                self.update(stored, save=False)
            except ValueError:
                pass

    @staticmethod
    def defaults() -> dict:
        watch = [str(downloads_dir())] + [str(p) for p in desktop_dirs()]
        return {
            "realtime": True,
            "guard": True,
            "auto_kick": False,
            "auto_quarantine": True,
            "notifications": True,
            "max_file_mb": 150,
            "guard_interval": 5,
            "watch_folders": list(dict.fromkeys(watch)),
            "exclusions": [],
        }

    def get(self, key):
        with self._lock:
            value = self.data[key]
            return list(value) if isinstance(value, list) else value

    def all(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self.data))

    def update(self, changes: dict, save: bool = True) -> dict:
        with self._lock:
            new = dict(self.data)
            for key, value in changes.items():
                if key in self.BOOL_KEYS:
                    new[key] = bool(value)
                elif key in self.INT_KEYS:
                    lo, hi = self.INT_KEYS[key]
                    try:
                        new[key] = max(lo, min(hi, int(value)))
                    except (TypeError, ValueError):
                        raise ValueError(f"Ungültiger Wert für {key}")
                elif key in self.LIST_KEYS:
                    if not isinstance(value, list):
                        raise ValueError(f"{key} muss eine Liste sein")
                    cleaned = [str(v).strip() for v in value if str(v).strip()]
                    new[key] = list(dict.fromkeys(cleaned))[:50]
            self.data = new
            if save:
                write_json(self.path, self.data)
            return self.all()
