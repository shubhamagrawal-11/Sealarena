"""
SealArena LLM Target Microservice
Executes isolated model inferences within internal model-net.
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

from src.llm_target.session_ctx import SessionManager
from src.llm_target.mock_engine import LLMEngine

app = FastAPI(title="SealArena LLM Target", version="1.0.0")

session_mgr = SessionManager()
engine = LLMEngine()

class GenerateRequest(BaseModel):
    session_id: str
    prompt: str
    stream: Optional[bool] = False

class ResetRequest(BaseModel):
    session_id: str

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "llm-target",
        "active_sessions": len(session_mgr.sessions),
        "use_mock": engine.use_mock
    }

@app.post("/api/v1/generate")
async def generate(req: GenerateRequest):
    session = session_mgr.get_or_create(req.session_id)
    response_text = await engine.generate(req.prompt, session)
    return {
        "session_id": req.session_id,
        "response": response_text,
        "cache_salt": session.cache_salt
    }

@app.post("/api/v1/session/reset")
async def reset_session(req: ResetRequest):
    success = session_mgr.reset_session(req.session_id)
    return {"status": "reset", "session_id": req.session_id, "found": success}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.llm_target.main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8001)), reload=False)
