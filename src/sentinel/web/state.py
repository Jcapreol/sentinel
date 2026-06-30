from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.config import Config

VT_FREE_TIER_LIMIT: int = 500

# Set by web/main.py lifespan; read by routes.py handlers.
_config: Config | None = None

_vt_calls_used: int = 0
_quota_lock: asyncio.Lock = asyncio.Lock()


async def get_remaining_quota() -> int:
    return VT_FREE_TIER_LIMIT - _vt_calls_used


async def increment_vt_calls() -> None:
    global _vt_calls_used
    async with _quota_lock:
        _vt_calls_used += 1
