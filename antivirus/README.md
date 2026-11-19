# 🛡️ Schutzschild – dein eigenes Antivirus-Programm

Ein selbst gebautes Antivirus mit Virenscanner, Echtzeitschutz, Quarantäne,
Prozess-Wächter und **Hacker-Abwehr mit Rauswurf** – bedienbar über eine
moderne Oberfläche (hell & dunkel, funktioniert auch auf schmalen Bildschirmen).

## Starten

| System | So geht's |
| --- | --- |
| **Windows** | Doppelklick auf `start.bat` – oder `start_als_admin.bat` für den vollen Schutz |
| **Linux / macOS** | `./start.sh` – oder `sudo ./start.sh` für den vollen Schutz |

Voraussetzung ist [Python 3.10+](https://www.python.org/downloads/) (unter Windows beim
Installieren **„Add python.exe to PATH“** anhaken). Das Modul `psutil` installiert das
Startskript automatisch. Danach öffnet sich die Oberfläche im Browser.
Das schwarze Konsolenfenster muss offen bleiben – es *ist* das Programm.

Optional als eigenes Fenster statt Browser-Tab: `pip install pywebview` und dann
`python schutzschild.py --fenster`.

> **Warum Administrator?** Ohne Adminrechte kann Schutzschild scannen, warnen und
> Programme beenden. Zum **Sperren von IP-Adressen in der Firewall** und zum
> **Kappen von Verbindungen** braucht es Adminrechte. Über den Knopf
> „Eingeschränkt“ oben rechts kannst du unter Windows direkt neu starten.

## Was es kann

### 🔍 Virenscan
- **Schnellscan** (Downloads, Desktop, Temp-Ordner, Autostart-Ordner und Windows-Autostart-Einträge in der Registry),
  **vollständiger Scan** (ganzer Benutzerordner) oder **eigener Ordner** (z. B. ein USB-Stick)
- Drei Erkennungsmethoden:
  1. **Signaturen** – SHA-256/MD5-Prüfsummen bekannter Schadsoftware (online aktualisierbar über MalwareBazaar)
  2. **58 Verhaltensregeln** – z. B. Reverse-Shells, Erpressungstrojaner (löscht Sicherungskopien),
     Passwort-Diebe, Keylogger, Krypto-Miner, Downloader, Makro-Viren, Webshells, Defender-Abschalter
  3. **Heuristik** – getarnte Endungen (`Rechnung.pdf.exe`), Umkehr-Zeichen-Trick, Programme
     getarnt als Bild, Köder-Namen (Crack, Cheat, Robux-Generator …), gepackte Programme, ZIP-Inhalte
- Jeder Fund zeigt **warum** er verdächtig ist – inklusive der gefundenen Stelle

### ⚡ Echtzeitschutz
Neue Dateien in Downloads und auf dem Desktop werden sofort geprüft; gefährliche
Funde landen automatisch in der Quarantäne.

### 🚨 Hacker-Abwehr (Rauswurf)
Der Netzwerk-Wächter prüft alle paar Sekunden jede Verbindung und erkennt u. a.:
- fremde Fernzugriffe von außen (Remotedesktop, VNC, SSH, Telnet …)
- aktive **Fernwartungs-Software** wie AnyDesk oder TeamViewer – die Lieblingswerkzeuge von Telefonbetrügern
- offene **Hintertür-Ports** typischer Trojaner (Metasploit, njRAT, AsyncRAT, Quasar, Remcos …)
- Konsolen mit direkter Internetverbindung (**Reverse-Shell**)
- Windows-Hilfsprogramme, die ins Internet funken, Programme aus Temp-Ordnern, Mining-Pools

**Rauswerfen** passiert in drei Schritten: IP in der Firewall sperren → Verbindung
kappen → Programm dahinter beenden. Mit dem **Panik-Knopf** fliegen alle gefährlichen
Verbindungen auf einmal raus, und der **automatische Rauswurf** erledigt das ohne Rückfrage.

### 🧠 Prozesse, 📦 Quarantäne, 📜 Protokoll
- Prozessliste mit Risiko-Bewertung (z. B. falscher `svchost.exe`, `svch0st.exe`, Miner, Hacker-Tools)
- Quarantäne verschlüsselt Dateien, sodass sie nichts mehr anrichten können – Wiederherstellen jederzeit möglich
- Protokoll aller Ereignisse, Desktop-Benachrichtigungen bei Gefahr

## Testen – ganz ohne echten Virus
Klicke auf **Virenscan → „Testvirus erzeugen“**. Dabei entsteht die offizielle, völlig harmlose
[EICAR-Testdatei](https://www.eicar.org/download-anti-malware-testfile/), die jedes
Antivirus-Programm erkennt. Der Echtzeitschutz sollte sie nach ein paar Sekunden wegsperren.
(Ist Windows Defender schneller, ist die Datei schon weg – dann funktioniert eben auch der.)

## Wichtig zu wissen
Schutzschild ist ein Lern- und Hobbyprojekt. Es erkennt viele typische Tricks, ersetzt aber
**keinen** professionellen Virenschutz mit Millionen Signaturen. Lass Windows Defender
deshalb einfach mit eingeschaltet – beide vertragen sich.

## Aufbau

```
antivirus/
├── schutzschild.py        Startprogramm
├── core/
│   ├── signatures.py      Prüfsummen-Datenbank + Verhaltensregeln
│   ├── scanner.py         Scanner, Heuristiken, ZIP-/Office-Analyse
│   ├── realtime.py        Echtzeitschutz + Wächter im Hintergrund
│   ├── netguard.py        Hacker-Abwehr: Verbindungen bewerten & rauswerfen
│   ├── firewall.py        IP-Sperren (Windows-Firewall, iptables, Blackhole-Route)
│   ├── processes.py       Prozess-Wächter
│   ├── quarantine.py      Quarantäne
│   ├── server.py          Lokaler Webserver (nur 127.0.0.1, mit geheimem Token)
│   └── app.py             Verbindet alles
├── ui/                    Oberfläche (HTML, CSS, JavaScript – ohne Internet-Abhängigkeiten)
└── signaturen/hashes.txt  Eingebaute Prüfsummen
```

Einstellungen, Protokoll, Quarantäne und Sperrliste liegen in `~/.schutzschild/`
(unter Windows `C:\Users\<Name>\.schutzschild\`).

**Eigene Regeln** schreibst du in `core/signatures.py` (Liste `RULES`), **eigene Prüfsummen**
trägst du in den Einstellungen ein.
