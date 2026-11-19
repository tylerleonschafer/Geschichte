#!/usr/bin/env python3
"""Schutzschild – dein eigenes Antivirus-Programm.

Start:  python schutzschild.py
Optionen:
  --port 8765       Port der Oberfläche (nur auf diesem PC erreichbar)
  --kein-browser    Browser nicht automatisch öffnen
  --fenster         Als eigenes Fenster öffnen (braucht: pip install pywebview)
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import config  # noqa: E402
from core.app import App  # noqa: E402
from core.server import Server  # noqa: E402

BANNER = r"""
   ____       _           _                 _     _ _     _
  / ___|  ___| |__  _   _| |_ _______  ___| |__ (_) | __| |
  \___ \ / __| '_ \| | | | __|_  / __|/ __| '_ \| | |/ _` |
   ___) | (__| | | | |_| | |_ / /\__ \ (__| | | | | | (_| |
  |____/ \___|_| |_|\__,_|\__/___|___/\___|_| |_|_|_|\__,_|
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Schutzschild Antivirus")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--kein-browser", action="store_true", help="Browser nicht öffnen")
    parser.add_argument("--fenster", action="store_true", help="Eigenes Fenster (pywebview)")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

    app = App()
    server = Server(app, args.port)
    app.start()

    print(BANNER)
    print(f"  Version {config.VERSION} · {config.platform_name()} · "
          f"{'Administrator' if config.is_admin() else 'ohne Administratorrechte'}")
    print(f"\n  Oberfläche: {server.url}")
    print("  (Dieses Fenster offen lassen. Beenden mit Strg+C.)\n")

    if args.fenster:
        try:
            import webview  # type: ignore
        except ImportError:
            print("  pywebview ist nicht installiert – öffne stattdessen den Browser.")
        else:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            webview.create_window("Schutzschild", server.url, width=1320, height=860, min_size=(900, 600))
            webview.start()
            app.stop()
            return 0

    if not args.kein_browser:
        threading.Timer(0.6, lambda: webbrowser.open(server.url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Schutzschild wird beendet …")
    finally:
        app.stop()
    print("  Tschüss! Schutzschild wurde beendet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
