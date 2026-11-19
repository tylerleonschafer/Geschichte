"""Kleiner lokaler Webserver für die Benutzeroberfläche.

Sicherheit: Der Server lauscht nur auf 127.0.0.1 (nicht aus dem Netzwerk
erreichbar). Jede API-Anfrage braucht ein geheimes Token, das nur das beim
Start geöffnete Browserfenster kennt. Fremde Webseiten können deshalb keine
Befehle an Schutzschild schicken.
"""
from __future__ import annotations

import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import config
from .firewall import FirewallError
from .processes import parse_pid
from .quarantine import QuarantineError
from .scanner import ScanError

STATIC = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/style.css": "style.css",
          "/icon.svg": "icon.svg"}
# Fest eingetragen, weil Windows sonst manchmal falsche Typen aus der Registry liefert
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml; charset=utf-8"}
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _str(body: dict, key: str, limit: int = 4096) -> str:
    value = body.get(key, "")
    if not isinstance(value, (str, int, float)):
        raise ApiError(f"Feld „{key}“ fehlt oder ist ungültig.")
    return str(value)[:limit]


class Api:
    """Alle Befehle, die die Oberfläche an den Schutz schicken kann."""

    def __init__(self, app):
        self.app = app
        self.routes = {
            ("GET", "/api/status"): self.status,
            ("GET", "/api/scan"): lambda q, b: self.app.scanner.snapshot(),
            ("POST", "/api/scan/start"): self.scan_start,
            ("POST", "/api/scan/stop"): self.scan_stop,
            ("GET", "/api/threats"): lambda q, b: {"threats": self.app.threats.all()},
            ("POST", "/api/threat"): self.threat,
            ("POST", "/api/threats/all"): self.threats_all,
            ("GET", "/api/quarantine"): lambda q, b: {"items": self.app.quarantine.list()},
            ("POST", "/api/quarantine/restore"): self.q_restore,
            ("POST", "/api/quarantine/delete"): self.q_delete,
            ("GET", "/api/network"): lambda q, b: self.app.net.snapshot(),
            ("POST", "/api/network/kick"): lambda q, b: self.app.net.kick(b),
            ("POST", "/api/network/kick_all"): lambda q, b: self.app.net.kick_all(),
            ("POST", "/api/firewall/block"): self.fw_block,
            ("POST", "/api/firewall/unblock"): self.fw_unblock,
            ("GET", "/api/processes"): lambda q, b: self.app.procs.snapshot(),
            ("POST", "/api/process/kill"): self.p_kill,
            ("POST", "/api/process/quarantine"): self.p_quarantine,
            ("GET", "/api/events"): lambda q, b: {"events": self.app.events.recent(400)},
            ("POST", "/api/events/clear"): self.events_clear,
            ("GET", "/api/settings"): self.settings_get,
            ("POST", "/api/settings"): self.settings_set,
            ("POST", "/api/signatures/add"): self.sig_add,
            ("POST", "/api/signatures/update"): self.sig_update,
            ("POST", "/api/eicar"): lambda q, b: self.app.create_eicar(),
            ("POST", "/api/elevate"): lambda q, b: self.app.elevate(),
            ("POST", "/api/shutdown"): self.shutdown,
        }

    def status(self, q, b):
        try:
            since = int(q.get("since", ["0"])[0])
        except ValueError:
            since = 0
        return self.app.status(since)

    def scan_start(self, q, b):
        try:
            return self.app.scanner.start(_str(b, "mode", 20), b.get("path") and _str(b, "path"))
        except ScanError as exc:
            raise ApiError(str(exc))

    def scan_stop(self, q, b):
        self.app.scanner.stop()
        return {"ok": True}

    def threat(self, q, b):
        return self.app.threat_action(_str(b, "id", 40), _str(b, "action", 20))

    def threats_all(self, q, b):
        action = _str(b, "action", 20)
        if action not in ("quarantine", "delete"):
            raise ApiError("Nur Quarantäne oder Löschen ist für alle möglich.")
        results = [self.app.threat_action(t["id"], action) for t in self.app.threats.all()
                   if t["status"] == "offen" and t.get("type") == "file"]
        ok = sum(1 for r in results if r["ok"])
        return {"ok": ok == len(results), "done": ok, "failed": len(results) - ok,
                "messages": [r["message"] for r in results if not r["ok"]][:5]}

    def q_restore(self, q, b):
        try:
            meta = self.app.quarantine.restore(_str(b, "id", 40))
        except QuarantineError as exc:
            raise ApiError(str(exc))
        except OSError as exc:
            raise ApiError(f"Wiederherstellen fehlgeschlagen: {exc.strerror or exc}")
        if meta.get("sha256"):
            self.app.allowlist.add(meta["sha256"])
        self.app.events.add("info", "Quarantäne", f"„{meta['name']}“ wiederhergestellt", meta["restored_to"])
        return {"ok": True, "message": f"Wiederhergestellt nach {meta['restored_to']}"}

    def q_delete(self, q, b):
        try:
            meta = self.app.quarantine.delete(_str(b, "id", 40))
        except QuarantineError as exc:
            raise ApiError(str(exc))
        self.app.events.add("ok", "Quarantäne", f"„{meta.get('name', 'Datei')}“ endgültig gelöscht")
        return {"ok": True}

    def fw_block(self, q, b):
        try:
            entry = self.app.firewall.block(_str(b, "ip", 64), _str(b, "reason", 200) if b.get("reason") else "")
        except FirewallError as exc:
            raise ApiError(str(exc))
        self.app.events.add("ok" if entry["applied"] else "warn", "Firewall",
                            f"IP {entry['ip']} gesperrt", entry["message"])
        return entry

    def fw_unblock(self, q, b):
        try:
            res = self.app.firewall.unblock(_str(b, "ip", 64))
        except FirewallError as exc:
            raise ApiError(str(exc))
        self.app.events.add("info", "Firewall", f"Sperre für {res['ip']} aufgehoben")
        return res

    def p_kill(self, q, b):
        try:
            pid = parse_pid(b.get("pid"))
        except ValueError as exc:
            raise ApiError(str(exc))
        res = self.app.procs.kill(pid, _str(b, "name", 200) or None)
        if res["ok"]:
            self.app.events.add("ok", "Prozesse", res["message"])
        return res

    def p_quarantine(self, q, b):
        try:
            pid = parse_pid(b.get("pid"))
        except ValueError as exc:
            raise ApiError(str(exc))
        return self.app.quarantine_process(pid, _str(b, "name", 200))

    def events_clear(self, q, b):
        self.app.events.clear()
        return {"ok": True}

    def settings_get(self, q, b):
        return {"settings": self.app.settings.all(), "signatures": self.app.sigdb.stats(),
                "defaults": {"downloads": str(config.downloads_dir()),
                             "desktop": [str(p) for p in config.desktop_dirs()]},
                "data_dir": str(config.DATA_DIR), "firewall": self.app.firewall.backend(),
                "trusted": self.app.allowlist.count()}

    def settings_set(self, q, b):
        try:
            settings = self.app.settings.update(b)
        except ValueError as exc:
            raise ApiError(str(exc))
        return {"settings": settings}

    def sig_add(self, q, b):
        try:
            self.app.sigdb.add_custom(_str(b, "hash", 100), _str(b, "name", 120) if b.get("name") else "")
        except ValueError as exc:
            raise ApiError(str(exc))
        self.app.events.add("ok", "Signaturen", "Eigene Signatur hinzugefügt")
        return {"ok": True, "signatures": self.app.sigdb.stats()}

    def sig_update(self, q, b):
        try:
            res = self.app.sigdb.update_online()
        except Exception as exc:
            msg = getattr(exc, "reason", None) or exc
            self.app.events.add("warn", "Signaturen", "Online-Aktualisierung fehlgeschlagen", str(msg))
            raise ApiError(f"Aktualisierung fehlgeschlagen: {msg}. Bist du mit dem Internet verbunden?", 502)
        self.app.events.add("ok", "Signaturen",
                            f"{res['added']} neue Signaturen geladen ({res['total']} online insgesamt)")
        return {"ok": True, **res, "signatures": self.app.sigdb.stats()}

    def shutdown(self, q, b):
        if self.app.shutdown_callback:
            self.app.shutdown_callback(delay=0.5)
        return {"ok": True}


class Server:
    def __init__(self, app, port: int = 8765):
        self.app = app
        self.api = Api(app)
        self.token = secrets.token_urlsafe(24)
        self.httpd = self._bind(port)
        self.port = self.httpd.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}
        app.shutdown_callback = self.shutdown_later

    def _bind(self, port: int) -> ThreadingHTTPServer:
        handler = self._handler()
        last_error = None
        for candidate in [port, *range(port + 1, port + 10), 0]:
            try:
                httpd = ThreadingHTTPServer(("127.0.0.1", candidate), handler)
                httpd.daemon_threads = True
                return httpd
            except OSError as exc:
                last_error = exc
        raise last_error  # type: ignore[misc]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/#t={self.token}"

    def serve_forever(self) -> None:
        self.httpd.serve_forever(poll_interval=0.3)

    def shutdown_later(self, delay: float = 0.5) -> None:
        def _stop():
            self.app.stop()
            self.httpd.shutdown()
        threading.Timer(delay, _stop).start()

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "Schutzschild"
            sys_version = ""

            def log_message(self, *args):  # Konsole sauber halten
                pass

            def _send(self, status: int, body: bytes, ctype: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", CSP)
                self.end_headers()
                self.wfile.write(body)

            def _json(self, status: int, data) -> None:
                self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")

            def _host_ok(self) -> bool:
                return self.headers.get("Host", "") in server.allowed_hosts

            def _handle(self, method: str) -> None:
                if not self._host_ok():
                    return self._send(403, b"Forbidden", "text/plain")
                parsed = urlparse(self.path)
                if method == "GET" and parsed.path in STATIC:
                    return self._static(STATIC[parsed.path])
                route = server.api.routes.get((method, parsed.path))
                if route is None:
                    return self._json(404, {"error": "Nicht gefunden"})
                token = self.headers.get("X-Schutzschild-Token", "")
                if not hmac.compare_digest(token.encode(), server.token.encode()):
                    return self._json(401, {"error": "Nicht angemeldet – bitte Schutzschild neu starten."})
                body = {}
                if method == "POST":
                    if "application/json" not in self.headers.get("Content-Type", ""):
                        return self._json(415, {"error": "JSON erwartet"})
                    length = int(self.headers.get("Content-Length") or 0)
                    if length > 1_000_000:
                        return self._json(413, {"error": "Anfrage zu groß"})
                    try:
                        body = json.loads(self.rfile.read(length) or b"{}")
                    except ValueError:
                        return self._json(400, {"error": "Ungültiges JSON"})
                    if not isinstance(body, dict):
                        return self._json(400, {"error": "Ungültige Anfrage"})
                try:
                    result = route(parse_qs(parsed.query), body)
                    self._json(200, result)
                except ApiError as exc:
                    self._json(exc.status, {"error": str(exc)})
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                except Exception as exc:  # pragma: no cover
                    server.app.events.add("warn", "System", "Interner Fehler", f"{parsed.path}: {exc!r}")
                    self._json(500, {"error": f"Interner Fehler: {exc}"})

            def _static(self, name: str) -> None:
                path = config.UI_DIR / name
                try:
                    data = path.read_bytes()
                except OSError:
                    return self._send(404, b"Not found", "text/plain")
                ctype = CONTENT_TYPES.get(path.suffix, "application/octet-stream")
                self._send(200, data, ctype)

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        return Handler
