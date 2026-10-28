"""
SealArena Protocol Models
Defines Pydantic schemas for cross-service requests, audit records, and telemetry.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

# --- Commit-Reveal Protocol ---

class CommitRequest(BaseModel):
    tenant_id: str
    session_id: str
    commitment_hash: str = Field(description="SHA-256 hash of (concatenated payloads + salt)")
    payload_count: int
    token_str: str = Field(description="Serialized capability token")

class CommitResponse(BaseModel):
    status: str
    commitment_hash: str
    round_id: str
    timestamp: float
    message: str

class EvaluationRequest(BaseModel):
    tenant_id: str
    session_id: str
    round_id: str
    prompt_index: int
    prompt: str
    token_str: str

class EvaluationResponse(BaseModel):
    session_id: str
    prompt_index: int
    verdict: str  # "ALLOWED" or "BLOCKED"
    status_code: int
    response_text: Optional[str] = None
    response_hash: str
    latency_ms: float
    message: str

class RevealRequest(BaseModel):
    tenant_id: str
    session_id: str
    round_id: str
    salt: str
    payloads: List[str]
    token_str: str

class RevealResponse(BaseModel):
    status: str
    commitment_verified: bool
    computed_hash: str
    expected_hash: str
    message: str

# --- Blue Defense Rule Bundle ---

class EncryptedRuleBundle(BaseModel):
    tenant_id: str
    version: str
    nonce_hex: str
    ciphertext_hex: str
    signature: str

class RuleUploadResponse(BaseModel):
    status: str
    version: str
    rules_loaded: int
    message: str

# --- Audit & Forensic Records ---

class AuditRecord(BaseModel):
    index: int
    timestamp: float
    tenant_id: str
    session_id: str
    action: str
    payload_hash: str
    verdict: str
    response_hash: str
    prev_hash: str
    entry_hash: str
    signature: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

# --- Monitor Telemetry (Metadata Only, Content-Free) ---

class MonitorEvent(BaseModel):
    event_id: str
    timestamp: float
    tenant_id: str
    boundary: str
    action: str
    verdict: str
    bytes_in: int
    bytes_out: int
    latency_ms: float
    anomalous: bool = False
    alert_type: Optional[str] = None
    alert_details: Optional[str] = None
