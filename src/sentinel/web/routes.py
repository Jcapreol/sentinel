from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncGenerator
from functools import partial

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from sentinel.main import run_analysis
from sentinel.web import state
from sentinel.web.demo import UnknownSlugError, load_fixture

router = APIRouter()

_PROGRESS_STEPS: list[str] = [
    "Parsing alert and extracting indicators...",
    "Watchman: behavioral pattern analysis via Claude...",
    "Cipher: querying VirusTotal reputation database...",
    "Cipher: querying AbuseIPDB community reports...",
    "Cipher: querying URLhaus malware distribution database...",
    "Assembling evidence chain and calculating confidence tier...",
]


def _sse(event: dict) -> str:  # type: ignore[type-arg]
    return f"data: {json.dumps(event)}\n\n"


def _error_event(source: str, reason: str, next_step: str | None = None) -> str:
    return _sse(
        {
            "type": "error",
            "blind_spot": {"source": source, "reason": reason, "next_step": next_step},
        }
    )


class AnalyzeRequest(BaseModel):
    alert_text: str = ""
    scenario_slug: str | None = None


@router.post("/analyze/stream")
async def analyze_stream(request: AnalyzeRequest) -> StreamingResponse:
    async def event_generator() -> AsyncGenerator[str, None]:
        if request.scenario_slug is not None:
            # ── Demo mode: load fixture, animate progress ──────────────
            try:
                result = load_fixture(request.scenario_slug)
            except UnknownSlugError:
                yield _error_event(
                    source="demo",
                    reason=(
                        f"Unknown scenario {request.scenario_slug!r}. "
                        "Choose one of the five pre-loaded scenarios from the dropdown."
                    ),
                    next_step="Select a valid scenario from the dropdown.",
                )
                return
            except Exception as exc:
                print(
                    f"[sentinel-web] Fixture load error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                yield _error_event(
                    source="demo",
                    reason="Failed to load demo fixture — check server logs for details.",
                    next_step=None,
                )
                return

            for step in _PROGRESS_STEPS:
                yield _sse({"type": "progress", "step": step})
                await asyncio.sleep(0.5)

            yield _sse({"type": "result", "data": result})

        else:
            # ── Live mode: bridge to run_analysis() via thread executor ─
            config = state._config
            if config is None:
                yield _error_event(
                    source="sentinel-engine",
                    reason=(
                        "API keys not configured — server cannot perform live analysis."
                    ),
                    next_step=(
                        "Set ANTHROPIC_API_KEY, VIRUSTOTAL_API_KEY, "
                        "ABUSEIPDB_API_KEY, URLHAUS_API_KEY and restart the server."
                    ),
                )
                return

            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(
                None, partial(run_analysis, request.alert_text, config)
            )

            for step in _PROGRESS_STEPS:
                if future.done():
                    break
                yield _sse({"type": "progress", "step": step})
                await asyncio.sleep(3)

            try:
                result = await future
            except Exception as exc:
                print(
                    f"[sentinel-web] Analysis error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                yield _error_event(
                    source="sentinel-engine",
                    reason=(
                        "Analysis engine encountered an error — "
                        "check server logs for details."
                    ),
                    next_step=(
                        "Verify API keys are configured and restart the server."
                    ),
                )
                return

            await state.increment_vt_calls()
            yield _sse({"type": "result", "data": result})

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/quota")
async def quota() -> dict[str, int]:
    return {
        "remaining": await state.get_remaining_quota(),
        "limit": state.VT_FREE_TIER_LIMIT,
    }
