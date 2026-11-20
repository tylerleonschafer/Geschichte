"""Signaturen: bekannte Prüfsummen (Hashes) und Verhaltensmuster (Regeln).

Jede Regel beschreibt ein typisches Verhalten von Schadsoftware, z. B.
"löscht Sicherungskopien" (Erpressungstrojaner) oder "öffnet eine
Reverse-Shell" (Hintertür). Die Muster sind reguläre Ausdrücke.
`hints` sind kurze Stichwörter, die vorher schnell gesucht werden – nur wenn
eins davon vorkommt, läuft der (langsamere) reguläre Ausdruck.
"""
from __future__ import annotations

import csv
import io
import re
import threading
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import config

# Der EICAR-Teststring wird absichtlich in Stücken gespeichert, damit andere
# Virenscanner diese Quelltextdatei nicht selbst für einen Testvirus halten.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE!$H+H*"

ALL = frozenset({"script", "binary", "office", "lnk", "cmdline", "other"})
CODE = frozenset({"script", "binary", "office", "lnk", "cmdline"})
SCRIPT = frozenset({"script", "office", "lnk", "cmdline"})
SCRIPT_ONLY = frozenset({"script", "cmdline"})
WEB_EXT = (".html", ".htm", ".svg", ".css", ".json", ".xml", ".map")


@dataclass(frozen=True)
class Pattern:
    hints: tuple
    regex: re.Pattern


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    family: str
    score: int
    patterns: tuple
    need_all: bool
    targets: frozenset
    skip_ext: frozenset


def P(hints, regex: bytes) -> Pattern:
    if isinstance(hints, bytes):
        hints = (hints,)
    return Pattern(tuple(h.lower() for h in hints), re.compile(regex, re.IGNORECASE))


def R(rule_id, name, family, score, *patterns, need_all=False, targets=CODE, skip_ext=()):
    return Rule(rule_id, name, family, score, tuple(patterns), need_all,
                frozenset(targets), frozenset(skip_ext))


RULES: list[Rule] = [
    # --- Testvirus ---------------------------------------------------------
    R("eicar", "EICAR-Testvirus (harmlose Testdatei)", "Testvirus", 100,
      P(b"eicar-standard", re.escape(EICAR)), targets=ALL),

    # --- Hintertüren / Reverse-Shells -------------------------------------
    R("revshell_devtcp", "Reverse-Shell: verbindet die Konsole mit einem fremden Rechner", "Hintertür", 80,
      P(b"/dev/", rb"/dev/(tcp|udp)/[\w.\-]+/\d+")),
    R("revshell_nc", "Reverse-Shell mit Netcat", "Hintertür", 80,
      P((b"nc", b"netcat"), rb"\b(nc|ncat|netcat)(\.exe)?\s[^\n]{0,80}\s-[ec]\s*\S*(sh|cmd|powershell)\b")),
    R("revshell_mkfifo", "Reverse-Shell über eine Named Pipe", "Hintertür", 75,
      P(b"mkfifo", rb"mkfifo\s+\S+[^\n]{0,160}\b(nc|ncat|netcat|telnet|openssl)\b")),
    R("revshell_py", "Python-Hintertür (Socket + Konsole)", "Hintertür", 75,
      P(b"socket", rb"socket\.socket\s*\("),
      P(b"connect", rb"\.connect\s*\(\s*\("),
      P((b"dup2", b"pty", b"sh", b"cmd"),
        rb"(os\.dup2\s*\(|pty\.spawn\s*\(|subprocess\.\w+\(\s*\[\s*['\"](/bin/)?(ba)?sh['\"]|['\"]cmd(\.exe)?['\"])"),
      need_all=True, targets=SCRIPT_ONLY),
    R("revshell_ps", "PowerShell-Hintertür (TCP-Client + Befehlsausführung)", "Hintertür", 85,
      P(b"tcpclient", rb"Net\.Sockets\.TCPClient"),
      P(b"getstream", rb"GetStream\s*\(\)"),
      P((b"iex", b"invoke-expression"), rb"(\biex\b|Invoke-Expression)"),
      need_all=True),
    R("php_webshell", "Web-Hintertür (Webshell) führt fremde Befehle aus", "Hintertür", 85,
      P((b"$_get", b"$_post", b"$_request", b"$_cookie"),
        rb"\b(eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*(base64_decode\s*\(\s*)?(stripslashes\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE)\b")),
    R("persist_ssh", "Schmuggelt einen fremden SSH-Schlüssel ein", "Hintertür", 45,
      P(b"authorized_keys", rb">>?\s*\S*\.ssh/authorized_keys"), targets=SCRIPT_ONLY),

    # --- Downloader / Nachlader -------------------------------------------
    R("ps_webclient", "Lädt Programmcode aus dem Internet und führt ihn aus", "Downloader", 60,
      P(b"webclient", rb"Net\.WebClient"),
      P(b"download", rb"\.Download(String|File|Data)\s*\("),
      P((b"iex", b"invoke-expression", b"start-process"), rb"(\biex\b|Invoke-Expression|Start-Process)"),
      need_all=True),
    R("ps_pipe_iex", "Führt direkt aus dem Internet geladenen Code aus", "Downloader", 30,
      P((b"iex", b"invoke-expression"),
        rb"\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,200}\|\s*(iex|Invoke-Expression)\b")),
    R("lolbin_certutil", "Missbraucht certutil zum Herunterladen", "Downloader", 55,
      P(b"certutil", rb"certutil(\.exe)?\s[^\n]{0,40}-urlcache[^\n]{0,60}https?://")),
    R("lolbin_bitsadmin", "Missbraucht bitsadmin zum Herunterladen", "Downloader", 40,
      P(b"bitsadmin", rb"bitsadmin(\.exe)?\s+/transfer\s[^\n]{0,200}https?://")),
    R("lolbin_mshta", "Startet Code über mshta (HTML-Anwendung)", "Downloader", 60,
      P(b"mshta", rb"mshta(\.exe)?['\"]?\s+['\"]?(https?://|vbscript:|javascript:)")),
    R("lolbin_regsvr32", "Lädt Code über regsvr32 aus dem Internet", "Downloader", 70,
      P(b"regsvr32", rb"regsvr32(\.exe)?\s[^\n]{0,80}/i:\s*['\"]?https?://")),
    R("lolbin_rundll_js", "Führt JavaScript über rundll32 aus", "Downloader", 70,
      P(b"rundll32", rb"rundll32(\.exe)?\s[^\n]{0,60}javascript:")),
    R("vbs_dropper", "Skript lädt Dateien herunter und startet sie", "Downloader", 60,
      P(b"createobject", rb"CreateObject\s*\(\s*['\"](WScript\.Shell|Shell\.Application)['\"]"),
      P((b"xmlhttp", b"winhttp", b"urldownloadtofile"), rb"(XMLHTTP|WinHttpRequest|URLDownloadToFile)"),
      P((b"adodb", b".run", b"shellexecute", b"savetofile"), rb"(ADODB\.Stream|\.Run\b|ShellExecute|SaveToFile)"),
      need_all=True),
    R("wsh_js", "JavaScript, das Windows-Befehle ausführt", "Downloader", 55,
      P(b"activexobject",
        rb"new\s+ActiveXObject\s*\(\s*['\"](WScript\.Shell|Shell\.Application|MSXML2\.XMLHTTP|ADODB\.Stream)"),
      P((b".run", b"shellexecute", b".exec", b"savetofile"), rb"(\.Run\s*\(|ShellExecute|\.Exec\s*\(|SaveToFile)"),
      need_all=True),
    R("curl_sh", "Lädt ein Skript herunter und führt es sofort aus", "Downloader", 20,
      P((b"curl", b"wget"), rb"\b(curl|wget)\s[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b"), targets=SCRIPT_ONLY),

    # --- Versteckte / verschleierte Befehle --------------------------------
    R("ps_encoded", "Versteckter (kodierter) PowerShell-Befehl", "Verschleierung", 55,
      P((b"powershell", b"pwsh"),
        rb"(powershell|pwsh)(\.exe)?['\"]?\s[^\n]{0,120}\s[-/](e|ec|en|enc|enco|encod|encodedcommand)\s+['\"]?[A-Za-z0-9+/=]{40,}")),
    R("ps_hidden", "Startet PowerShell unsichtbar", "Verschleierung", 30,
      P((b"powershell", b"pwsh"),
        rb"(powershell|pwsh)(\.exe)?['\"]?\s[^\n]{0,80}[-/]w(in|indow|indowstyle)?\s+(h|hid|hidden|1)\b")),
    R("ps_bypass", "Schaltet PowerShell-Sicherheitsrichtlinie ab", "Verschleierung", 15,
      P(b"bypass", rb"[-/](ep|exec|executionpolicy)\s+bypass")),
    R("ps_b64_iex", "Entschlüsselt versteckten Code und führt ihn aus", "Verschleierung", 40,
      P(b"frombase64string", rb"FromBase64String"),
      P((b"iex", b"invoke-expression", b"invoke("), rb"(\biex\b|Invoke-Expression|\.Invoke\s*\()"),
      need_all=True),
    R("reflective_load", "Lädt Programmcode direkt in den Arbeitsspeicher", "Verschleierung", 30,
      P(b"assembly", rb"\[(System\.)?Reflection\.Assembly\]\s*::\s*Load\s*\(")),
    R("amsi_bypass", "Versucht den Virenschutz (AMSI) auszutricksen", "Verschleierung", 75,
      P(b"amsi", rb"Amsi(Utils|InitFailed|ScanBuffer|Context)")),
    R("php_obf", "Verschleierter PHP-Code (eval + Dekodierung)", "Verschleierung", 70,
      P(b"eval", rb"\beval\s*\(\s*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode)\s*\(")),
    R("js_obf", "Verschleierter JavaScript-Code", "Verschleierung", 40,
      P((b"eval", b"function"), rb"\b(eval|Function)\s*\(\s*(unescape|atob|String\.fromCharCode|decodeURIComponent)\s*\(")),
    R("b64_blob", "Riesiger verschlüsselter Textblock im Skript", "Verschleierung", 15,
      P((), rb"[A-Za-z0-9+/]{4000,}={0,2}"), targets=SCRIPT_ONLY, skip_ext=WEB_EXT),

    # --- Virenschutz & Firewall sabotieren --------------------------------
    R("defender_off", "Schaltet Windows Defender ab", "Sabotage", 75,
      P(b"mppreference",
        rb"Set-MpPreference\s[^\n]{0,80}-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|IntrusionPreventionSystem)\s+(\$true|1)")),
    R("defender_excl", "Versteckt sich vor Windows Defender (Ausnahme eingetragen)", "Sabotage", 50,
      P(b"mppreference", rb"Add-MpPreference\s[^\n]{0,60}-Exclusion(Path|Process|Extension)")),
    R("defender_svc", "Stoppt den Windows-Defender-Dienst", "Sabotage", 60,
      P(b"windefend", rb"\b(sc|net)(\.exe)?\s+(stop|config|delete)\s+WinDefend")),
    R("fw_off", "Schaltet die Firewall ab", "Sabotage", 55,
      P(b"netsh", rb"netsh(\.exe)?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable)")),
    R("clear_logs", "Löscht Windows-Protokolle (Spuren verwischen)", "Sabotage", 45,
      P((b"wevtutil", b"clear-eventlog"), rb"(wevtutil(\.exe)?\s+(cl|clear-log)\s|Clear-EventLog\s)")),
    R("history_wipe", "Verwischt Spuren im Befehlsverlauf", "Sabotage", 30,
      P((b"histfile", b"history"), rb"(history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null)"), targets=SCRIPT_ONLY),
    R("uac_bypass", "Umgeht die Benutzerkontensteuerung (UAC)", "Sabotage", 70,
      P(b"ms-settings", rb"ms-settings[\\/]+shell[\\/]+open[\\/]+command")),
    R("fork_bomb", "Fork-Bombe (legt den Computer lahm)", "Sabotage", 70,
      P(b":()", rb":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), targets=SCRIPT_ONLY),
    R("bat_bomb", "Batch-Bombe (startet sich endlos selbst)", "Sabotage", 60,
      P(b"%0", rb"%0\s*\|\s*%0"), targets=SCRIPT_ONLY),
    R("wipe", "Zerstört Daten oder die Festplatte", "Sabotage", 85,
      P((b"--no-preserve-root", b"of=/dev/", b"format", b"del ", b"rd ", b"rmdir"),
        rb"(rm\s+-[a-z]*\s+--no-preserve-root\s+/|dd\s+if=/dev/(zero|u?random)\s+of=/dev/(sd[a-z]|nvme\d|hd[a-z]|disk\d)"
        rb"|format(\.com)?\s+c:\s*/[qy]|del\s+(/[fsq]\s+){2,3}['\"]?c:\\(\*|windows)|(rd|rmdir)\s+/s\s+/q\s+['\"]?c:\\windows)")),

    # --- Erpressung (Ransomware) -------------------------------------------
    R("ransom_backup", "Löscht Sicherungskopien (typisch für Erpressungstrojaner)", "Ransomware", 80,
      P((b"vssadmin", b"shadowcopy", b"wbadmin", b"bcdedit"),
        rb"(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete"
        rb"|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)"
        rb"|bcdedit(\.exe)?\s+/set\s+\{?default\}?\s+(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"
        rb"|Win32_ShadowCopy[^\n]{0,80}Delete)")),
    R("ransom_note", "Erpresser-Nachricht („Deine Dateien wurden verschlüsselt“)", "Ransomware", 55,
      P((b"encrypted", b"verschl"),
        rb"((all\s+)?your\s+(important\s+)?files\s+(have\s+been|are|were)\s+encrypted|ihre\s+dateien\s+wurden\s+verschl)")),

    # --- Passwort- und Datendiebstahl --------------------------------------
    R("mimikatz", "Passwort-Diebstahl-Werkzeug (Mimikatz)", "Passwort-Diebstahl", 85,
      P((b"sekurlsa", b"lsadump", b"mimikatz"),
        rb"(sekurlsa\s*::\s*\w+|lsadump\s*::\s*\w+|Invoke-Mimikatz|mimikatz(\.exe)?\s)")),
    R("lsass_dump", "Liest Windows-Anmeldedaten aus dem Speicher (LSASS)", "Passwort-Diebstahl", 80,
      P((b"lsass", b"minidump"),
        rb"(procdump(64)?(\.exe)?\s[^\n]{0,60}lsass|comsvcs(\.dll)?[^\n]{0,20}MiniDump)")),
    R("stealer_browser", "Liest gespeicherte Browser-Passwörter aus", "Passwort-Diebstahl", 75,
      P((b"login data", b"local state", b"cookies"), rb"(Login Data|Local State|Network[\\/]+Cookies)"),
      P((b"cryptunprotectdata", b"win32crypt", b"encrypted_key"), rb"(CryptUnprotectData|win32crypt|encrypted_key)"),
      need_all=True, targets=SCRIPT_ONLY),
    R("stealer_discord", "Stiehlt Discord-Zugangsdaten (Token-Grabber)", "Passwort-Diebstahl", 70,
      P((b"leveldb", b"dqw4w9wgxcq"), rb"(discord(canary|ptb)?[\\/]+Local Storage[\\/]+leveldb|dQw4w9WgXcQ:)"),
      targets=SCRIPT_ONLY),
    R("keylogger", "Tastatur-Spion (Keylogger) mit Datenversand", "Spionage", 70,
      P((b"pynput", b"keyboard", b"getasynckeystate", b"setwindowshookex", b"pyhook"),
        rb"(pynput|keyboard\.(on_press|hook|add_hotkey)|GetAsyncKeyState|SetWindowsHookEx|pyHook)"),
      P((b"smtplib", b"webhooks", b"api.telegram", b"ftplib"),
        rb"(smtplib|ftplib|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot)"),
      need_all=True, targets=SCRIPT_ONLY),
    R("webhook_exfil", "Schickt Daten heimlich an einen Discord-Webhook", "Spionage", 25,
      P(b"webhooks", rb"discord(app)?\.com/api/webhooks/\d{6,}/[\w-]{20,}"), targets=SCRIPT_ONLY),
    R("telegram_exfil", "Schickt Daten heimlich an einen Telegram-Bot", "Spionage", 25,
      P(b"api.telegram.org", rb"api\.telegram\.org/bot\d+:[\w-]{20,}/send(Document|Message|Photo)"),
      targets=SCRIPT_ONLY),

    # --- Krypto-Miner --------------------------------------------------------
    R("miner_pool", "Verbindet sich mit einem Krypto-Mining-Pool", "Krypto-Miner", 60,
      P(b"stratum", rb"stratum\d?\+(tcp|ssl|tls)://")),
    R("miner_tool", "Enthält einen Krypto-Miner (XMRig o. ä.)", "Krypto-Miner", 45,
      P((b"xmrig", b"donate-level", b"cryptonight"), rb"(\bxmrig\b|--donate-level|cryptonight)")),

    # --- Autostart / Einnisten --------------------------------------------------
    R("persist_runkey", "Trägt sich heimlich in den Autostart ein", "Einnisten", 35,
      P(b"currentversion",
        rb"(reg(\.exe)?\s+add\s[^\n]{0,40}CurrentVersion[\\/]+Run|(New|Set)-ItemProperty[^\n]{0,120}CurrentVersion[\\/]+Run)")),
    R("persist_schtask", "Legt eine versteckte geplante Aufgabe an", "Einnisten", 35,
      P(b"schtasks", rb"schtasks(\.exe)?\s+/create\s[^\n]{0,250}(/sc\s+(onlogon|onstart|onidle|minute)|/ru\s+['\"]?system)")),
    R("persist_cron", "Startet sich bei jedem Hochfahren (Cron)", "Einnisten", 45,
      P(b"@reboot", rb"@reboot\s[^\n]{0,120}(curl|wget|\bnc\b|bash|python|/tmp/)"), targets=SCRIPT_ONLY),
    R("admin_add", "Legt heimlich ein Administrator-Konto an", "Einnisten", 60,
      P(b"localgroup", rb"net1?(\.exe)?\s+localgroup\s+(administrators|administratoren)\s+\S+\s+/add")),
    R("user_add", "Legt heimlich ein Benutzerkonto an", "Einnisten", 40,
      P(b"/add", rb"net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add")),
    R("sudoers", "Verschafft sich Root-Rechte ohne Passwort", "Einnisten", 55,
      P(b"sudoers", rb"(NOPASSWD\s*:\s*ALL[^\n]{0,40}>>?\s*/etc/sudoers|>>\s*/etc/sudoers)"), targets=SCRIPT_ONLY),
    R("ld_preload", "Rootkit-Technik (ld.so.preload)", "Einnisten", 45,
      P(b"ld.so.preload", rb"/etc/ld\.so\.preload"), targets=SCRIPT_ONLY),

    # --- Office-Makros & Verknüpfungen --------------------------------------
    R("macro_auto", "Makro startet beim Öffnen automatisch Befehle", "Makro-Virus", 55,
      P((b"autoopen", b"auto_open", b"document_open", b"workbook_open", b"autoexec"),
        rb"(Auto_?Open|Document_Open|Workbook_Open|AutoExec)"),
      P((b"shell", b"createobject", b"urldownloadtofile", b"powershell", b"kernel32"),
        rb"(\bShell\s*\(|WScript\.Shell|URLDownloadToFile|CreateObject|powershell|Lib\s+['\"]kernel32)"),
      need_all=True, targets={"office"}),
    R("office_dde", "Dokument startet Befehle über DDE", "Makro-Virus", 50,
      P(b"ddeauto", rb"DDEAUTO"), targets={"office"}),
    R("lnk_cmd", "Verknüpfung startet versteckt Befehle", "Tarnung", 50,
      P((b"powershell", b"cmd", b"mshta", b"wscript", b"cscript", b"regsvr32", b"bitsadmin", b"certutil"),
        rb"(powershell|pwsh|cmd\.exe|mshta|wscript|cscript|regsvr32|bitsadmin|certutil)"),
      P((b"-w", b"-e", b"/c", b"http", b"-nop", b"bypass"),
        rb"(-w(indowstyle)?\s+h|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|/c\s|https?://|-nop\b|bypass)"),
      need_all=True, targets={"lnk"}),
]


@dataclass
class RuleHit:
    rule: Rule
    snippet: str


def _clean_snippet(raw: bytes | None) -> str:
    if not raw:
        return ""
    text = raw[:160].decode("latin-1")
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:90] + ("…" if len(text) > 90 else "")


def match_rules(data: bytes, targets, ext: str = "") -> list[RuleHit]:
    """Prüft Daten gegen alle passenden Regeln."""
    if not data:
        return []
    low = data.lower()
    hits: list[RuleHit] = []
    for rule in RULES:
        if not (rule.targets & targets) or ext in rule.skip_ext:
            continue
        snippet = None
        all_ok = True
        for pat in rule.patterns:
            match = None
            if not pat.hints or any(h in low for h in pat.hints):
                match = pat.regex.search(data)
            if rule.need_all:
                if match is None:
                    all_ok = False
                    break
                if snippet is None:
                    snippet = match.group(0)
            elif match is not None:
                snippet = match.group(0)
                break
        if snippet is not None and (all_ok or not rule.need_all):
            hits.append(RuleHit(rule, _clean_snippet(snippet)))
    return hits


# --------------------------------------------------------------------------
# Prüfsummen-Datenbank
# --------------------------------------------------------------------------

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
ONLINE_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
ONLINE_NAME = "Bekannte Schadsoftware (MalwareBazaar)"


def _parse_line(line: str) -> list[tuple[str, str]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    if line.count(",") >= 3 and '"' in line:
        # CSV-Export von MalwareBazaar: zeit, sha256, md5, sha1, reporter, dateiname, typ, mime, signatur …
        try:
            row = next(csv.reader([line], skipinitialspace=True))
        except (csv.Error, StopIteration):
            return []
        name = row[8].strip() if len(row) > 8 and row[8].strip().lower() not in ("", "n/a") else ONLINE_NAME
        return [(c.strip().lower(), name) for c in row[1:3]
                if HEX64.match(c.strip().lower()) or HEX32.match(c.strip().lower())]
    parts = line.split(None, 1)
    digest = parts[0].strip(",;").lower()
    if not (HEX64.match(digest) or HEX32.match(digest)):
        return []
    name = parts[1].strip() if len(parts) > 1 else "Bekannte Schadsoftware"
    return [(digest, name[:120])]


class SignatureDB:
    def __init__(self):
        self._lock = threading.Lock()
        self.hashes: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        self.updated: str | None = None
        self.reload()

    def _sources(self):
        return [(config.SIGNATURE_DIR / "hashes.txt", "eingebaut", "Bekannte Schadsoftware"),
                (config.CUSTOM_SIG_FILE, "eigene", "Eigene Signatur"),
                (config.ONLINE_SIG_FILE, "online", ONLINE_NAME)]

    def reload(self) -> None:
        hashes: dict[str, str] = {}
        counts: dict[str, int] = {}
        for path, label, default_name in self._sources():
            n = 0
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        for digest, name in _parse_line(line):
                            hashes[digest] = name if name != "Bekannte Schadsoftware" else default_name
                            n += 1
            except OSError:
                pass
            counts[label] = n
        updated = None
        try:
            updated = datetime.fromtimestamp(config.ONLINE_SIG_FILE.stat().st_mtime).isoformat(timespec="minutes")
        except OSError:
            pass
        with self._lock:
            self.hashes, self.counts, self.updated = hashes, counts, updated

    def lookup(self, sha256: str | None, md5: str | None) -> str | None:
        with self._lock:
            for digest in (sha256, md5):
                if digest and digest in self.hashes:
                    return self.hashes[digest]
        return None

    def stats(self) -> dict:
        with self._lock:
            return {"total": len(self.hashes), "sources": dict(self.counts),
                    "rules": len(RULES), "online_updated": self.updated}

    def add_custom(self, digest: str, name: str) -> None:
        digest = digest.strip().lower()
        if not (HEX64.match(digest) or HEX32.match(digest)):
            raise ValueError("Bitte eine gültige SHA-256- (64 Zeichen) oder MD5-Prüfsumme (32 Zeichen) eingeben.")
        name = re.sub(r"[\r\n]+", " ", name.strip())[:120] or "Eigene Signatur"
        with config.CUSTOM_SIG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"{digest}  {name}\n")
        config.fix_owner(config.CUSTOM_SIG_FILE)
        self.reload()

    def update_online(self, timeout: int = 25) -> dict:
        """Lädt die neuesten Schadsoftware-Prüfsummen von MalwareBazaar (abuse.ch)."""
        request = urllib.request.Request(ONLINE_URL, headers={"User-Agent": "Schutzschild-Antivirus/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(60 * 1024 * 1024)
        if raw.startswith(b"PK"):
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                raw = b"\n".join(zf.read(n) for n in zf.namelist()[:3])
        fresh = {t for t in (line.strip().lower() for line in raw.decode("utf-8", "replace").splitlines())
                 if HEX64.match(t)}
        if not fresh:
            raise ValueError("Die Antwort enthielt keine Prüfsummen.")
        existing = set()
        try:
            existing = {t for t in (line.strip().lower() for line in
                                    config.ONLINE_SIG_FILE.read_text(encoding="utf-8").splitlines())
                        if HEX64.match(t)}
        except OSError:
            pass
        merged = sorted(existing | fresh)[-1_000_000:]
        header = f"# Quelle: MalwareBazaar (abuse.ch) – aktualisiert {datetime.now():%d.%m.%Y %H:%M}\n"
        config.ONLINE_SIG_FILE.write_text(header + "\n".join(merged) + "\n", encoding="utf-8")
        config.fix_owner(config.ONLINE_SIG_FILE)
        self.reload()
        return {"added": len(fresh - existing), "total": len(merged)}


class Allowlist:
    """Dateien (per SHA-256), denen der Benutzer ausdrücklich vertraut."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        data = config.read_json(path, [])
        self._items: set[str] = {d for d in data if isinstance(d, str)} if isinstance(data, list) else set()

    def contains(self, digest: str | None) -> bool:
        with self._lock:
            return bool(digest) and digest in self._items

    def add(self, digest: str | None) -> None:
        if not digest:
            return
        with self._lock:
            self._items.add(digest)
            config.write_json(self.path, sorted(self._items))

    def count(self) -> int:
        with self._lock:
            return len(self._items)
