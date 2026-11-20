@echo off
rem Startet Schutzschild mit Administratorrechten (Windows fragt nach Erlaubnis).
rem Nur so kann die Firewall Angreifer sperren und Verbindungen kappen.
powershell -NoProfile -Command "Start-Process -FilePath '%~dp0start.bat' -Verb RunAs"
