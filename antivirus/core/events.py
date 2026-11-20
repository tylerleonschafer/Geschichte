"""Ereignis-Protokoll: alles, was der Schutz tut, landet hier."""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from . import config

LEVELS = ("info", "ok", "warn", "danger")


class EventLog:
    def __init__(self, path: Path, maxlen: int = 800):
        self.path = path
        self.maxlen = maxlen
        self._lock = threading.Lock()
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._next_id = 1
        self._writes = 0
        self._load()

    def _load(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines[-self.maxlen:]:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict) or "message" not in event:
                continue
            event["id"] = self._next_id
            self._next_id += 1
            self._events.append(event)

    def add(self, level: str, category: str, message: str, detail: str = "") -> dict:
        if level not in LEVELS:
            level = "info"
        with self._lock:
            event = {
                "id": self._next_id,
                "ts": time.time(),
                "time": datetime.now().astimezone().isoformat(timespec="seconds"),
                "level": level,
                "category": category,
                "message": message,
                "detail": detail,
            }
            self._next_id += 1
            self._events.append(event)
            self._persist(event)
            return event

    def _persist(self, event: dict) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._writes += 1
            if self._writes % 200 == 0 and self.path.stat().st_size > 1_500_000:
                self._rewrite()
            elif self._writes == 1:
                config.fix_owner(self.path)
        except OSError:
            pass

    def _rewrite(self) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for event in self._events:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        tmp.replace(self.path)

    def since(self, last_id: int, limit: int = 50) -> list[dict]:
        with self._lock:
            return [e for e in self._events if e["id"] > last_id][-limit:]

    def recent(self, limit: int = 300) -> list[dict]:
        with self._lock:
            return list(self._events)[-limit:][::-1]

    @property
    def last_id(self) -> int:
        return self._next_id - 1

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            try:
                self.path.write_text("", encoding="utf-8")
            except OSError:
                pass
