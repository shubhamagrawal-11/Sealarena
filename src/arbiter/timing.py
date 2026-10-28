"""
SealArena Timing Channel Defense & Latency Normalizer
Implements fixed-time padding and batched release to eliminate timing side-channels
that leak Blue defense rule complexity or model processing states.
"""

import time
import random
import asyncio
from typing import List, Dict, Optional
import numpy as np

class TimingDefense:
    """
    Normalizes response latency across all evaluation requests.
    Prevents Red from inferring whether a prompt was blocked early (e.g. keyword hit in 2ms)
    or processed through the entire LLM pipeline (e.g. 350ms).
    """

    def __init__(self, target_latency_ms: float = 350.0, jitter_std_ms: float = 5.0, enabled: bool = True):
        self.target_latency_ms = target_latency_ms
        self.jitter_std_ms = jitter_std_ms
        self.enabled = enabled

        # Telemetry metrics
        self.raw_latencies: List[float] = []
        self.padded_latencies: List[float] = []
        self.overheads: List[float] = []

    async def pad_response(self, start_time: float) -> float:
        """
        Calculates and awaits required delay to reach target latency window.
        Returns final measured latency in ms.
        """
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        self.raw_latencies.append(elapsed_ms)

        if not self.enabled:
            self.padded_latencies.append(elapsed_ms)
            self.overheads.append(0.0)
            return elapsed_ms

        # Compute randomized target with Gaussian jitter
        jitter = random.gauss(0.0, self.jitter_std_ms)
        effective_target = max(self.target_latency_ms + jitter, elapsed_ms)

        pad_delay_ms = effective_target - elapsed_ms
        if pad_delay_ms > 0:
            await asyncio.sleep(pad_delay_ms / 1000.0)

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0
        self.padded_latencies.append(total_latency_ms)
        self.overheads.append(total_latency_ms - elapsed_ms)
        return total_latency_ms

    def get_metrics(self) -> Dict[str, float]:
        """Calculates p50 and p95 latency and overhead stats."""
        if not self.padded_latencies:
            return {
                "count": 0,
                "raw_p50_ms": 0.0,
                "raw_p95_ms": 0.0,
                "padded_p50_ms": 0.0,
                "padded_p95_ms": 0.0,
                "overhead_p50_ms": 0.0,
                "overhead_p95_ms": 0.0,
                "timing_defense_active": self.enabled
            }

        raw_arr = np.array(self.raw_latencies)
        pad_arr = np.array(self.padded_latencies)
        ovh_arr = np.array(self.overheads)

        return {
            "count": len(pad_arr),
            "raw_p50_ms": float(np.percentile(raw_arr, 50)),
            "raw_p95_ms": float(np.percentile(raw_arr, 95)),
            "padded_p50_ms": float(np.percentile(pad_arr, 50)),
            "padded_p95_ms": float(np.percentile(pad_arr, 95)),
            "overhead_p50_ms": float(np.percentile(ovh_arr, 50)),
            "overhead_p95_ms": float(np.percentile(ovh_arr, 95)),
            "timing_defense_active": self.enabled
        }
