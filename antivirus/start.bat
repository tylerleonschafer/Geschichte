@echo off
chcp 65001 >nul
title Schutzschild Antivirus
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo.
  echo   Python wurde nicht gefunden.
  echo   Bitte installiere Python von https://www.python.org/downloads/
  echo   WICHTIG: Beim Installieren den Haken bei "Add python.exe to PATH" setzen.
  echo.
  pause
  exit /b 1
)

%PY% -c "import psutil" >nul 2>nul
if errorlevel 1 (
  echo   Installiere das benoetigte Modul psutil ...
  %PY% -m pip install --user --quiet psutil
)

%PY% schutzschild.py %*
if errorlevel 1 pause
