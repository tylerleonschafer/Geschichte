"""Quarantäne: gefährliche Dateien werden unschädlich gemacht und weggesperrt.

Die Datei wird beim Wegsperren mit XOR "verschlüsselt". So kann sie weder
gestartet noch von einem anderen Programm versehentlich geöffnet werden –
lässt sich aber jederzeit wiederherstellen.
"""
from __future__ import annotations

import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path

from . import config

MAGIC = b"SCHUTZSCHILD-QUARANTAENE-1\n"
XOR_TABLE = bytes(i ^ 0x5A for i in range(256))
ID_RE = re.compile(r"^[0-9a-f]{16}$")


class QuarantineError(Exception):
    pass


class Quarantine:
    def __init__(self, directory: Path):
        self.dir = directory
        self._lock = threading.Lock()

    def _meta_path(self, qid: str) -> Path:
        if not ID_RE.match(qid or ""):
            raise QuarantineError("Ungültige Quarantäne-ID.")
        return self.dir / f"{qid}.json"

    def add(self, path, reason: str, sha256: str | None = None) -> dict:
        src = Path(path)
        if not src.is_file():
            raise QuarantineError("Die Datei existiert nicht mehr.")
        qid = uuid.uuid4().hex[:16]
        blob = self.dir / f"{qid}.qtn"
        size = src.stat().st_size
        with self._lock:
            try:
                with open(src, "rb") as fin, open(blob, "wb") as fout:
                    fout.write(MAGIC)
                    while True:
                        chunk = fin.read(1024 * 1024)
                        if not chunk:
                            break
                        fout.write(chunk.translate(XOR_TABLE))
            except OSError as exc:
                blob.unlink(missing_ok=True)
                raise QuarantineError(f"Datei konnte nicht gelesen werden: {exc.strerror or exc}")
            try:
                try:
                    os.remove(src)
                except PermissionError:
                    os.chmod(src, stat.S_IWRITE | stat.S_IREAD)
                    os.remove(src)
            except OSError:
                blob.unlink(missing_ok=True)
                raise QuarantineError("Die Datei wird gerade benutzt oder ist geschützt. Beende zuerst das "
                                      "Programm (Seite „Prozesse“) oder starte Schutzschild als Administrator.")
            meta = {"id": qid, "original_path": str(src), "name": src.name, "size": size,
                    "sha256": sha256, "reason": reason, "date": time.time()}
            config.write_json(self._meta_path(qid), meta)
            config.fix_owner(blob)
        return meta

    def list(self) -> list[dict]:
        items = []
        for meta_file in self.dir.glob("*.json"):
            meta = config.read_json(meta_file, None)
            if isinstance(meta, dict) and ID_RE.match(str(meta.get("id", ""))):
                items.append(meta)
        return sorted(items, key=lambda m: -m.get("date", 0))

    def count(self) -> int:
        return sum(1 for _ in self.dir.glob("*.qtn"))

    def restore(self, qid: str) -> dict:
        meta_file = self._meta_path(qid)
        meta = config.read_json(meta_file, None)
        blob = self.dir / f"{qid}.qtn"
        if not isinstance(meta, dict) or not blob.is_file():
            raise QuarantineError("Eintrag nicht gefunden.")
        target = Path(meta["original_path"])
        if target.exists():
            target = target.with_name(f"{target.stem} (wiederhergestellt){target.suffix}")
        with self._lock:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(blob, "rb") as fin, open(target, "wb") as fout:
                if fin.read(len(MAGIC)) != MAGIC:
                    raise QuarantineError("Quarantäne-Datei ist beschädigt.")
                while True:
                    chunk = fin.read(1024 * 1024)
                    if not chunk:
                        break
                    fout.write(chunk.translate(XOR_TABLE))
            config.fix_owner(target)
            blob.unlink(missing_ok=True)
            meta_file.unlink(missing_ok=True)
        meta["restored_to"] = str(target)
        return meta

    def delete(self, qid: str) -> dict:
        meta_file = self._meta_path(qid)
        meta = config.read_json(meta_file, {}) or {}
        with self._lock:
            (self.dir / f"{qid}.qtn").unlink(missing_ok=True)
            meta_file.unlink(missing_ok=True)
        return meta
