"""
SealArena Capability Token System
Implements short-lived, scoped, cryptographically-signed capability tokens for tenants.
"""

import time
import uuid
from typing import List, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field
from src.common.crypto import (
    canonical_json_bytes,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    export_ed25519_public_hex,
    import_ed25519_public_hex
)

class CapabilityTokenPayload(BaseModel):
    token_id: str = Field(default_factory=lambda: f"tok_{uuid.uuid4().hex[:12]}")
    tenant_id: str
    session_id: str
    issued_at: float = Field(default_factory=time.time)
    expires_at: float
    capabilities: List[str]
    forbidden: List[str] = Field(default_factory=list)

class CapabilityToken(BaseModel):
    payload: CapabilityTokenPayload
    signature: str

class TokenAuthority:
    """Arbiter Token Authority that issues and verifies tenant capability tokens."""

    def __init__(self, private_key=None, public_key=None):
        if private_key is None or public_key is None:
            self.priv_key, self.pub_key = generate_ed25519_keypair()
        else:
            self.priv_key = private_key
            self.pub_key = public_key

    def get_public_key_hex(self) -> str:
        return export_ed25519_public_hex(self.pub_key)

    def issue_token(
        self,
        tenant_id: str,
        session_id: str,
        capabilities: List[str],
        forbidden: Optional[List[str]] = None,
        ttl_seconds: float = 60.0
    ) -> CapabilityToken:
        now = time.time()
        payload = CapabilityTokenPayload(
            tenant_id=tenant_id,
            session_id=session_id,
            issued_at=now,
            expires_at=now + ttl_seconds,
            capabilities=capabilities,
            forbidden=forbidden or []
        )
        data_to_sign = canonical_json_bytes(payload.model_dump())
        sig = ed25519_sign(self.priv_key, data_to_sign)
        return CapabilityToken(payload=payload, signature=sig)

    def verify_token(self, token: CapabilityToken, required_action: str) -> Tuple[bool, str]:
        """
        Validates token signature, expiration, and capability claims.
        Returns (is_valid, reason).
        """
        now = time.time()
        payload_data = canonical_json_bytes(token.payload.model_dump())

        # 1. Verify cryptographic signature
        if not ed25519_verify(self.pub_key, payload_data, token.signature):
            return False, "INVALID_CRYPTOGRAPHIC_SIGNATURE"

        # 2. Check expiration
        if now > token.payload.expires_at:
            return False, f"TOKEN_EXPIRED: expired {now - token.payload.expires_at:.1f}s ago"

        # 3. Check forbidden actions
        if required_action in token.payload.forbidden:
            return False, f"ACTION_EXPLICITLY_FORBIDDEN: {required_action}"

        # 4. Check permitted capabilities
        if required_action not in token.payload.capabilities and "*" not in token.payload.capabilities:
            return False, f"CAPABILITY_NOT_GRANTED: requires {required_action}"

        return True, "AUTHORIZED"
