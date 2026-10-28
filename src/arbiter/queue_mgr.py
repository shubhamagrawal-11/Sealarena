"""
SealArena Rate Limiting & Fair Queueing Engine
Enforces tenant quotas, burst limits, and fair request distribution to prevent DoS.
"""

import time
import asyncio
from typing import Dict
from collections import defaultdict

class TokenBucket:
    def __init__(self, capacity: float = 20.0, fill_rate: float = 10.0):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, amount: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.last_update = now

        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

class FairQueueManager:
    """Manages per-tenant rate limits and concurrency locks."""

    def __init__(self):
        self.buckets: Dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(capacity=20.0, fill_rate=10.0))
        self.locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def check_rate_limit(self, tenant_id: str) -> bool:
        return self.buckets[tenant_id].consume(1.0)

    def get_tenant_lock(self, tenant_id: str) -> asyncio.Lock:
        return self.locks[tenant_id]
