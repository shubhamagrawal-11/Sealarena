"""
SealArena Coarse Telemetry Filter
Enforces strict content-blind observability.
Removes all prompts, responses, rule names, and payloads before telemetry is stored or surfaced.
"""

import time
import math
import random
from typing import Dict, Any

class CoarseFilter:
    """Strips all payload content and applies differential noise to metric sizes."""

    def __init__(self, add_size_noise: bool = True):
        self.add_size_noise = add_size_noise

    def sanitize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts only content-free metadata.
        Explicitly drops: 'prompt', 'response', 'rules', 'rule_name', 'payload', 'keyword'.
        """
        bytes_in = int(raw_event.get("bytes_in", 0))
        bytes_out = int(raw_event.get("bytes_out", 0))

        # Add small rounding or quantization noise to prevent packet-size covert channels
        if self.add_size_noise:
            # Quantize sizes to nearest 16-byte boundary with +- 8 byte jitter
            bytes_in = max(0, int(math.ceil(bytes_in / 16.0) * 16 + random.randint(-4, 4)))
            bytes_out = max(0, int(math.ceil(bytes_out / 16.0) * 16 + random.randint(-4, 4)))

        sanitized = {
            "event_id": str(raw_event.get("event_id", "")),
            "timestamp": float(raw_event.get("timestamp", time.time())),
            "tenant_id": str(raw_event.get("tenant_id", "unknown")),
            "boundary": str(raw_event.get("boundary", "internal")),
            "action": str(raw_event.get("action", "EVALUATE")),
            "verdict": str(raw_event.get("verdict", "UNKNOWN")),
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "latency_ms": round(float(raw_event.get("latency_ms", 0.0)), 2),
            "anomalous": bool(raw_event.get("anomalous", False)),
            "alert_type": raw_event.get("alert_type"),
            "alert_details": raw_event.get("alert_details")
        }

        return sanitized
