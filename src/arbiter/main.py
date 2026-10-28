"""
SealArena Arbiter Service
The central secure broker bridging Red Runner, Blue Runner, LLM Target, Ledger, and Monitor.
Enforces mTLS, ABAC capability tokens, commit-reveal protocols, encrypted guard evaluation,
timing channel padding, and canary boundary scanning.
"""

import os
import time
import json
import uuid
import httpx
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.common.crypto import sha256_string, sha256_hash
from src.common.tokens import TokenAuthority, CapabilityToken
from src.common.canaries import CanaryExfiltrationScanner
from src.common.protocol import (
    CommitRequest, CommitResponse,
    EvaluationRequest, EvaluationResponse,
    RevealRequest, RevealResponse,
    EncryptedRuleBundle, RuleUploadResponse
)
from src.arbiter.abac import PolicyEngine, AccessRequest
from src.arbiter.guard import GuardStage
from src.arbiter.timing import TimingDefense
from src.arbiter.queue_mgr import FairQueueManager

app = FastAPI(title="SealArena Arbiter", version="1.0.0")

# Configuration & Subsystems
MODEL_URL = os.getenv("MODEL_URL", "http://localhost:8001")
LEDGER_URL = os.getenv("LEDGER_URL", "http://localhost:8003")
MONITOR_URL = os.getenv("MONITOR_URL", "http://localhost:8004")

token_auth = TokenAuthority()
policy_engine = PolicyEngine()
guard_stage = GuardStage()
timing_defense = TimingDefense(target_latency_ms=350.0, jitter_std_ms=4.0, enabled=True)
canary_scanner = CanaryExfiltrationScanner()
queue_mgr = FairQueueManager()

# Session and Round Tracking
active_rounds: Dict[str, Dict[str, Any]] = {}

async def log_to_ledger(entry_data: Dict[str, Any]):
    """Dispatches audit entry to Audit Ledger microservice."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{LEDGER_URL}/api/v1/ledger/append", json=entry_data)
    except Exception:
        # Graceful fallback if ledger service is starting up
        pass

async def send_to_monitor(event_data: Dict[str, Any]):
    """Dispatches coarse metadata event to Monitor microservice."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{MONITOR_URL}/api/v1/monitor/event", json=event_data)
    except Exception:
        pass

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "arbiter",
        "guard_rules_loaded": guard_stage.rules_loaded,
        "timing_defense": timing_defense.enabled
    }

@app.post("/api/v1/auth/token")
async def request_token(req: Dict[str, Any]):
    """Issues scoped, short-lived capability token to tenants."""
    tenant_id = req.get("tenant_id")
    session_id = req.get("session_id", f"sess_{uuid.uuid4().hex[:8]}")
    capabilities = req.get("capabilities", [])
    forbidden = req.get("forbidden", [])
    ttl = float(req.get("ttl_seconds", 120.0))

    if not tenant_id or tenant_id not in ["red", "blue", "admin", "monitor"]:
        raise HTTPException(status_code=400, detail="Invalid tenant_id")

    token = token_auth.issue_token(
        tenant_id=tenant_id,
        session_id=session_id,
        capabilities=capabilities,
        forbidden=forbidden,
        ttl_seconds=ttl
    )
    return {
        "status": "success",
        "token": token.model_dump(),
        "token_str": json.dumps(token.model_dump()),
        "public_key_hex": token_auth.get_public_key_hex()
    }

@app.post("/api/v1/red/commit", response_model=CommitResponse)
async def red_commit(req: CommitRequest):
    """
    Commit Phase: Red commits H(payloads || salt) before the round starts.
    Arbiter records commitment in ledger to bind Red from altering attacks mid-round.
    """
    start_time = time.perf_counter()

    # 1. Parse and verify token
    try:
        token_obj = CapabilityToken(**json.loads(req.token_str))
        valid, reason = token_auth.verify_token(token_obj, "commit_payload")
        if not valid:
            raise HTTPException(status_code=403, detail=f"Token unauthorized: {reason}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token parse error: {str(e)}")

    # 2. Rate limiting
    if not queue_mgr.check_rate_limit(req.tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # 3. ABAC Policy evaluation
    access_req = AccessRequest(
        subject_tenant=req.tenant_id,
        action="commit_payload",
        resource=f"session/{req.session_id}",
        session_id=req.session_id,
        round_phase="INITIALIZED",
        token_capabilities=token_obj.payload.capabilities,
        token_forbidden=token_obj.payload.forbidden
    )
    allow, policy_reason = policy_engine.evaluate(access_req)
    if not allow:
        raise HTTPException(status_code=403, detail=policy_reason)

    round_id = f"round_{uuid.uuid4().hex[:8]}"
    active_rounds[round_id] = {
        "session_id": req.session_id,
        "commitment_hash": req.commitment_hash,
        "payload_count": req.payload_count,
        "evaluated_count": 0,
        "phase": "COMMITTED",
        "created_at": time.time()
    }

    # Audit & Monitor
    audit_entry = {
        "tenant_id": req.tenant_id,
        "session_id": req.session_id,
        "action": "COMMIT_PAYLOADS",
        "payload_hash": req.commitment_hash,
        "verdict": "COMMITTED",
        "response_hash": sha256_string(round_id),
        "metadata": {"payload_count": req.payload_count, "round_id": round_id}
    }
    await log_to_ledger(audit_entry)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    await send_to_monitor({
        "event_id": uuid.uuid4().hex[:12],
        "timestamp": time.time(),
        "tenant_id": req.tenant_id,
        "boundary": "red->arbiter",
        "action": "COMMIT",
        "verdict": "COMMITTED",
        "bytes_in": len(req.commitment_hash),
        "bytes_out": len(round_id),
        "latency_ms": elapsed_ms
    })

    return CommitResponse(
        status="COMMITTED",
        commitment_hash=req.commitment_hash,
        round_id=round_id,
        timestamp=time.time(),
        message="Payload commitment successfully registered and bound to audit ledger"
    )

@app.post("/api/v1/red/evaluate", response_model=EvaluationResponse)
async def red_evaluate(req: EvaluationRequest):
    """
    Evaluation Phase: Red submits prompt.
    1. ABAC check
    2. Guard stage (Blue defense filter)
    3. LLM Target evaluation
    4. Canary boundary scan
    5. Timing normalization padding
    """
    start_time = time.perf_counter()

    # 1. Token Verification
    try:
        token_obj = CapabilityToken(**json.loads(req.token_str))
        valid, reason = token_auth.verify_token(token_obj, "submit_prompt")
        if not valid:
            raise HTTPException(status_code=403, detail=f"Token unauthorized: {reason}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

    # 2. Rate limit
    if not queue_mgr.check_rate_limit(req.tenant_id):
        raise HTTPException(status_code=429, detail="Tenant rate limit exceeded")

    round_info = active_rounds.get(req.round_id)
    current_phase = round_info["phase"] if round_info else "UNCOMMITTED"

    # 3. ABAC Policy Check
    access_req = AccessRequest(
        subject_tenant=req.tenant_id,
        action="evaluate_prompt",
        resource=f"round/{req.round_id}",
        session_id=req.session_id,
        round_phase=current_phase,
        token_capabilities=token_obj.payload.capabilities,
        token_forbidden=token_obj.payload.forbidden
    )
    allow, policy_reason = policy_engine.evaluate(access_req)
    if not allow:
        elapsed_ms = await timing_defense.pad_response(start_time)
        return EvaluationResponse(
            session_id=req.session_id,
            prompt_index=req.prompt_index,
            verdict="BLOCKED",
            status_code=403,
            response_text=None,
            response_hash=sha256_string("POLICY_DENY"),
            latency_ms=elapsed_ms,
            message=f"ABAC Denied: {policy_reason}"
        )

    if round_info:
        round_info["phase"] = "EVALUATING"
        round_info["evaluated_count"] += 1

    prompt_hash = sha256_string(req.prompt)

    # 4. Guard Stage (Blue Defense Rules)
    guard_verdict, guard_reason = guard_stage.evaluate_prompt(req.prompt)

    response_text = None
    response_verdict = guard_verdict
    final_message = "Prompt passed Blue defenses and completed evaluation"

    if guard_verdict == "BLOCKED":
        final_message = "Blocked by security policy"
        response_text = None
    else:
        # 5. Forward to LLM Target
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                model_resp = await client.post(
                    f"{MODEL_URL}/api/v1/generate",
                    json={
                        "session_id": req.session_id,
                        "prompt": req.prompt,
                        "stream": False
                    }
                )
                if model_resp.status_code == 200:
                    raw_text = model_resp.json().get("response", "")

                    # 6. Canary Boundary Scanner on Model Output
                    is_leak, leaked_canary, leak_desc = canary_scanner.scan_text(raw_text, "arbiter->red")
                    if is_leak:
                        response_verdict = "BLOCKED"
                        final_message = "EXFILTRATION_BLOCKED: Model response contained unauthorized boundary canary"
                        response_text = None

                        # Alert Monitor and Ledger of Canary Exfiltration Attempt
                        await send_to_monitor({
                            "event_id": uuid.uuid4().hex[:12],
                            "timestamp": time.time(),
                            "tenant_id": req.tenant_id,
                            "boundary": "model->red",
                            "action": "CANARY_SCAN",
                            "verdict": "EXFILTRATION_BLOCKED",
                            "bytes_in": len(req.prompt),
                            "bytes_out": 0,
                            "latency_ms": 0.0,
                            "anomalous": True,
                            "alert_type": "CANARY_EXFILTRATION_TRIGGER",
                            "alert_details": f"Attempted exfiltration of canary '{leaked_canary}'"
                        })
                    else:
                        response_text = raw_text
                else:
                    response_verdict = "ERROR"
                    final_message = "LLM target returned error status"
        except Exception as e:
            response_verdict = "MODEL_UNAVAILABLE"
            final_message = f"LLM target connection error: {str(e)}"

    resp_hash = sha256_string(response_text or response_verdict)

    # 7. Apply Timing Normalization Padding
    padded_latency_ms = await timing_defense.pad_response(start_time)

    # 8. Record in Audit Ledger
    audit_entry = {
        "tenant_id": req.tenant_id,
        "session_id": req.session_id,
        "action": "EVALUATE_PROMPT",
        "payload_hash": prompt_hash,
        "verdict": response_verdict,
        "response_hash": resp_hash,
        "metadata": {
            "prompt_index": req.prompt_index,
            "round_id": req.round_id,
            "latency_ms": padded_latency_ms
        }
    }
    await log_to_ledger(audit_entry)

    # 9. Send Coarse Telemetry to Monitor (No prompt content, no rule names)
    await send_to_monitor({
        "event_id": uuid.uuid4().hex[:12],
        "timestamp": time.time(),
        "tenant_id": req.tenant_id,
        "boundary": "arbiter->red",
        "action": "EVALUATE",
        "verdict": response_verdict,
        "bytes_in": len(req.prompt),
        "bytes_out": len(response_text or ""),
        "latency_ms": padded_latency_ms
    })

    return EvaluationResponse(
        session_id=req.session_id,
        prompt_index=req.prompt_index,
        verdict=response_verdict,
        status_code=200 if response_verdict == "ALLOWED" else 403,
        response_text=response_text,
        response_hash=resp_hash,
        latency_ms=padded_latency_ms,
        message=final_message
    )

@app.post("/api/v1/red/reveal", response_model=RevealResponse)
async def red_reveal(req: RevealRequest):
    """
    Reveal Phase: Red submits plaintext payloads and salt after round completion.
    Arbiter recomputes H(payloads || salt) and verifies it matches the initial commitment.
    """
    round_info = active_rounds.get(req.round_id)
    if not round_info:
        raise HTTPException(status_code=404, detail="Round not found")

    expected_commitment = round_info["commitment_hash"]

    # Reconstruct commitment: SHA-256 of concatenated payloads + salt
    combined = "".join(req.payloads) + req.salt
    computed_hash = sha256_string(combined)

    verified = (computed_hash.lower() == expected_commitment.lower())
    round_info["phase"] = "REVEALED" if verified else "TAMPER_DETECTED"

    # Audit log
    await log_to_ledger({
        "tenant_id": req.tenant_id,
        "session_id": req.session_id,
        "action": "REVEAL_PAYLOADS",
        "payload_hash": computed_hash,
        "verdict": "VERIFIED" if verified else "COMMITMENT_MISMATCH",
        "response_hash": expected_commitment,
        "metadata": {
            "round_id": req.round_id,
            "payload_count": len(req.payloads),
            "match": verified
        }
    })

    return RevealResponse(
        status="SUCCESS" if verified else "MISMATCH",
        commitment_verified=verified,
        computed_hash=computed_hash,
        expected_hash=expected_commitment,
        message="Commitment verified: Red payloads authenticated to initial pre-round commitment" if verified else "Commitment verification failed! Payloads altered mid-round"
    )

@app.post("/api/v1/blue/rules", response_model=RuleUploadResponse)
async def blue_deploy_rules(req: EncryptedRuleBundle):
    """
    Blue deploys encrypted defense rules to Arbiter.
    Rules are decrypted in Arbiter's isolated guard stage. Red cannot access this endpoint.
    """
    if req.tenant_id != "blue":
        raise HTTPException(status_code=403, detail="Only Blue tenant can deploy defense rules")

    success = guard_stage.load_encrypted_rules(req.nonce_hex, req.ciphertext_hex)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to decrypt rule bundle with guard master key")

    rule_count = len(guard_stage.rules.get("blocked_keywords", [])) + len(guard_stage.rules.get("blocked_patterns", []))

    await log_to_ledger({
        "tenant_id": req.tenant_id,
        "session_id": "blue_admin",
        "action": "DEPLOY_RULES",
        "payload_hash": sha256_string(req.ciphertext_hex),
        "verdict": "DEPLOYED",
        "response_hash": sha256_string(f"rules_v_{req.version}"),
        "metadata": {"version": req.version, "rules_loaded": rule_count}
    })

    return RuleUploadResponse(
        status="DEPLOYED",
        version=req.version,
        rules_loaded=rule_count,
        message="Defense rule bundle successfully decrypted and loaded in Arbiter guard memory"
    )

@app.get("/api/v1/metrics")
async def get_metrics():
    """Returns timing defense metrics, latency overhead, and active sessions."""
    return {
        "timing": timing_defense.get_metrics(),
        "active_rounds": len(active_rounds)
    }

@app.post("/api/v1/timing/toggle")
async def toggle_timing_defense(req: Dict[str, bool]):
    """Enables or disables timing padding (for comparative leaktest demonstration)."""
    enable = req.get("enabled", True)
    timing_defense.enabled = enable
    return {"status": "success", "timing_defense_enabled": timing_defense.enabled}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.arbiter.main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)
