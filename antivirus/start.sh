#!/usr/bin/env sh
# Startet Schutzschild unter Linux oder macOS.
# Für Firewall-Sperren mit Root-Rechten starten:  sudo ./start.sh
cd "$(dirname "$0")" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 wurde nicht gefunden. Bitte installieren (z. B. sudo apt install python3)."
  exit 1
fi

if ! python3 -c "import psutil" >/dev/null 2>&1; then
  echo "Installiere das benötigte Modul psutil ..."
  python3 -m pip install --user --quiet psutil 2>/dev/null \
    || echo "Hinweis: Bitte psutil installieren, z. B. mit: sudo apt install python3-psutil"
fi

exec python3 schutzschild.py "$@"
