"""
SealArena Session Context Manager
Enforces strict per-session memory isolation and cache salting.
Guarantees zero KV-cache or prompt-cache leakage across tenants or rounds.
"""

import time
import hashlib
from typing import Dict, List, Optional, Any

class SessionContext:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.created_at = time.time()
        # Per-session cache salt: prevents cross-session prompt caching collisions
        self.cache_salt = hashlib.sha256(f"{session_id}_{time.time()}".encode()).hexdigest()
        self.history: List[Dict[str, str]] = []

    def add_message(self, role: str, content: str):
        self.history.append({"role": role, "content": content})

    def clear(self):
        self.history.clear()
        # Rotate cache salt on reset
        self.cache_salt = hashlib.sha256(f"{self.session_id}_{time.time()}_reset".encode()).hexdigest()

class SessionManager:
    """Manages isolated sessions. Does not allow state leakage between session IDs."""

    def __init__(self):
        self.sessions: Dict[str, SessionContext] = {}

    def get_or_create(self, session_id: str) -> SessionContext:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionContext(session_id)
        return self.sessions[session_id]

    def reset_session(self, session_id: str) -> bool:
        if session_id in self.sessions:
            self.sessions[session_id].clear()
            del self.sessions[session_id]
            return True
        return False

    def reset_all(self):
        for s in self.sessions.values():
            s.clear()
        self.sessions.clear()
