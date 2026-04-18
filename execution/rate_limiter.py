"""
execution/rate_limiter.py
--------------------------
Async rate limiter used by both the attacker and target connectors.

Combines two controls:
  1. max_concurrent  — asyncio.Semaphore: caps simultaneous in-flight calls.
  2. min_interval_s  — minimum wall-clock seconds between acquisitions.
     Converts to an effective RPS ceiling: rps = 1 / min_interval_s.

Usage (async context manager):
    limiter = RateLimiter(max_concurrent=3, min_interval_s=0.5)  # ≤ 2 rps

    async with limiter:
        response = await connector.chat(prompt)

The interval enforcement is serialised under a separate asyncio.Lock so that
concurrent acquirers don't race on `_last_call_time`.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """
    Async context-manager rate limiter.

    Args:
        max_concurrent: Maximum number of in-flight calls at any moment.
        min_interval_s: Minimum seconds between successive acquisitions
                        (0.0 = no interval constraint, just the semaphore).
    """

    def __init__(self, max_concurrent: int = 5, min_interval_s: float = 0.0) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self._sem = asyncio.Semaphore(max_concurrent)
        self._min_interval = min_interval_s
        self._last_call: float = 0.0
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> "RateLimiter":
        await self._sem.acquire()
        if self._min_interval > 0.0:
            async with self._lock:
                now = time.monotonic()
                gap = self._min_interval - (now - self._last_call)
                if gap > 0:
                    await asyncio.sleep(gap)
                self._last_call = time.monotonic()
        return self

    async def __aexit__(self, *_) -> None:
        self._sem.release()

    @classmethod
    def from_rps(cls, rps: float, max_concurrent: int = 5) -> "RateLimiter":
        """Convenience constructor: specify calls-per-second instead of interval."""
        if rps <= 0:
            raise ValueError("rps must be positive")
        return cls(max_concurrent=max_concurrent, min_interval_s=1.0 / rps)
