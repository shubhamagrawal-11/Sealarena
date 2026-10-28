"""
SealArena Monitor Microservice
Collects coarse metadata telemetry, enforces content-blind observability,
and generates rate-limited security alerts.
"""

import os
from typing import Dict, Any, List
from fastapi import FastAPI
from pydantic import BaseModel

from src.monitor.coarse_filter import CoarseFilter
from src.monitor.anomaly import AnomalyDetector

app = FastAPI(title="SealArena Observability Monitor", version="1.0.0")

coarse_filter = CoarseFilter(add_size_noise=True)
anomaly_detector = AnomalyDetector(alert_cooldown_seconds=2.0)

stored_events: List[Dict[str, Any]] = []

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "monitor",
        "events_recorded": len(stored_events),
        "alerts_count": len(anomaly_detector.active_alerts)
    }

@app.post("/api/v1/monitor/event")
async def record_event(raw_event: Dict[str, Any]):
    # 1. Sanitize to coarse metadata (content-free)
    sanitized = coarse_filter.sanitize_event(raw_event)
    stored_events.append(sanitized)

    # Keep memory bounded
    if len(stored_events) > 500:
        stored_events.pop(0)

    # 2. Check for security anomalies
    alert = anomaly_detector.process_event(raw_event)

    return {
        "status": "recorded",
        "event_id": sanitized["event_id"],
        "alert_triggered": bool(alert)
    }

@app.get("/api/v1/monitor/events")
async def get_events(limit: int = 50):
    return {
        "count": len(stored_events),
        "events": stored_events[-limit:]
    }

@app.get("/api/v1/monitor/alerts")
async def get_alerts():
    return {
        "count": len(anomaly_detector.active_alerts),
        "alerts": anomaly_detector.active_alerts
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.monitor.main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8004)), reload=False)
