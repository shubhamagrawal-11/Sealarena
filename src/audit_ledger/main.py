"""
SealArena Audit Ledger Microservice
Maintains the append-only, Ed25519-signed, hash-chained log with Merkle checkpoints.
"""

import os
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.audit_ledger.signer import LedgerSigner
from src.audit_ledger.chain import HashChain
from src.audit_ledger.merkle import MerkleCheckpointManager

app = FastAPI(title="SealArena Audit Ledger", version="1.0.0")

signer = LedgerSigner()
hash_chain = HashChain(signer=signer)
merkle_mgr = MerkleCheckpointManager(signer=signer, batch_size=5)

class AppendRequest(BaseModel):
    tenant_id: str
    session_id: str
    action: str
    payload_hash: str
    verdict: str
    response_hash: str
    metadata: Optional[Dict[str, Any]] = None

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "audit-ledger",
        "block_count": len(hash_chain.entries),
        "latest_hash": hash_chain.latest_hash
    }

@app.get("/api/v1/ledger/public_key")
async def get_public_key():
    return {
        "algorithm": "Ed25519",
        "public_key_hex": signer.get_public_key_hex()
    }

@app.post("/api/v1/ledger/append")
async def append_record(req: AppendRequest):
    record = hash_chain.append_entry(
        tenant_id=req.tenant_id,
        session_id=req.session_id,
        action=req.action,
        payload_hash=req.payload_hash,
        verdict=req.verdict,
        response_hash=req.response_hash,
        metadata=req.metadata
    )
    # Check if a new Merkle checkpoint should be created
    ckpt = merkle_mgr.maybe_create_checkpoint(hash_chain.entries)
    return {
        "status": "appended",
        "record": record,
        "checkpoint_created": bool(ckpt)
    }

@app.get("/api/v1/ledger/records")
async def get_records(limit: int = 100):
    return {
        "count": len(hash_chain.entries),
        "records": hash_chain.entries[-limit:]
    }

@app.get("/api/v1/ledger/checkpoints")
async def get_checkpoints():
    return {
        "count": len(merkle_mgr.checkpoints),
        "checkpoints": merkle_mgr.checkpoints
    }

@app.get("/api/v1/ledger/verify")
async def verify_chain():
    result = hash_chain.verify_integrity()
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.audit_ledger.main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8003)), reload=False)
