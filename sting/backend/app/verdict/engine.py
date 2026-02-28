"""
Verdict Engine - Real-time session scoring
"""
from typing import Dict, Optional
from dataclasses import dataclass

SCORE_WEIGHTS = {
    "AUTH_SUCCESS": -30,
    "NORMAL_FILE_READ": -5,
    "NORMAL_COMMAND": -2,
    "NO_RECON_30S": -20,
    "CLEAN_60S": -20,
    "AUTH_ATTEMPT": +15,
    "CANARY_HIT": +50,
    "WGET_EXECUTABLE": +80,
    "RECON_SEQUENCE": +40,
    "KNOWN_BAD_IP": +100,
    "BINARY_FROM_TMP": +60,
    "RESOURCE_LIMIT_HIT": +40,
}

@dataclass
class Verdict:
    session_id: str
    score: int
    state: str

class VerdictEngine:
    def __init__(self):
        self._scores: Dict[str, int] = {}
        self._states: Dict[str, str] = {}
        
    def create_session(self, session_id: str, ip: str, protocol: str):
        from verdict.session_layer import create_session
        self._scores[session_id] = 100
        self._states[session_id] = "HOSTILE"
        return create_session(session_id, protocol)
    
    def score_event(self, session_id: str, event_type: str, payload: dict = None) -> int:
        if session_id not in self._scores:
            return 100
        delta = SCORE_WEIGHTS.get(event_type, 0)
        self._scores[session_id] = max(0, min(100, self._scores[session_id] + delta))
        self._update_state(session_id)
        return self._scores[session_id]
    
    def _update_state(self, session_id: str):
        score = self._scores.get(session_id, 100)
        if score >= 50:
            self._states[session_id] = "HOSTILE"
        elif score >= 30:
            self._states[session_id] = "PENDING"
        else:
            self._states[session_id] = "CLEARED"
    
    def get_verdict(self, session_id: str) -> Verdict:
        score = self._scores.get(session_id, 100)
        state = self._states.get(session_id, "HOSTILE")
        return Verdict(session_id=session_id, score=score, state=state)
    
    def should_passthrough(self, session_id: str) -> bool:
        verdict = self.get_verdict(session_id)
        return verdict.state == "CLEARED"
    
    def nuke_session(self, session_id: str) -> bool:
        from verdict.session_layer import get_session, delete_session
        session = get_session(session_id)
        if session:
            session.nuke()
        self._scores[session_id] = 100
        self._states[session_id] = "HOSTILE"
        return True
    
    def commit_session(self, session_id: str):
        from verdict.session_layer import get_session
        session = get_session(session_id)
        if not session:
            return []
        writes = session.commit()
        self._scores[session_id] = 0
        self._states[session_id] = "CLEARED"
        return writes

_engine = VerdictEngine()

def get_engine() -> VerdictEngine:
    return _engine
