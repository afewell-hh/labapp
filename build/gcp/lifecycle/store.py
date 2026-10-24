"""Durable slot storage abstraction with generation-matched writes (CAS).

Mirrors the Cloud Storage object contract that a later live adapter must
provide: ``write`` succeeds only when the object's current generation equals
``if_generation_match`` (0 means "must not exist"). There is deliberately no
delete operation: the slot object is persistent and reused.
"""
from __future__ import annotations

import copy
import json
import threading
from typing import Callable, Optional, Protocol


class PreconditionFailed(Exception):
    """The object's generation did not match; someone else wrote first."""


class SlotStore(Protocol):
    def read(self, key: str) -> tuple[Optional[dict], int]:
        """Return (record, generation); (None, 0) when the object is absent."""

    def write(self, key: str, record: dict, *, if_generation_match: int) -> int:
        """Store record; return the new generation or raise PreconditionFailed."""


class MemoryStore:
    """In-memory store with Cloud Storage generation semantics (for tests)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._objects: dict[str, tuple[str, int]] = {}
        self._next_generation = 1000
        # Test hook: called as hook(key, record) just before the next write is
        # evaluated, so tests can interleave a competing writer.
        self.before_write: Optional[Callable[[str, dict], None]] = None
        self.writes: list[tuple[str, int, int]] = []

    def read(self, key: str) -> tuple[Optional[dict], int]:
        with self._lock:
            if key not in self._objects:
                return None, 0
            body, generation = self._objects[key]
            return json.loads(body), generation

    def write(self, key: str, record: dict, *, if_generation_match: int) -> int:
        hook = self.before_write
        if hook is not None:
            self.before_write = None  # one-shot; the hook may itself write
            hook(key, copy.deepcopy(record))
        with self._lock:
            current = self._objects[key][1] if key in self._objects else 0
            if current != if_generation_match:
                raise PreconditionFailed(
                    f"{key}: generation {current} != {if_generation_match}")
            self._next_generation += 1
            self._objects[key] = (json.dumps(record, sort_keys=True),
                                  self._next_generation)
            self.writes.append((key, if_generation_match, self._next_generation))
            return self._next_generation
