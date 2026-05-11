import json

import anthropic

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot

_MODEL = "claude-haiku-4-5-20251001"

_PROMPT_TEMPLATE = """\
You are a security analyst. Analyze the following security alert for behavioral indicators of compromise.

Respond ONLY with valid JSON in this exact format:
{{
    "findings": ["<specific behavioral finding>", "<another finding>"],
    "confidence": "<Investigating|Probable|Confirmed>"
}}

Alert: {alert}"""


class WatchmanAgent:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._client = anthropic.Anthropic(
            api_key=config.anthropic_api_key,
            timeout=config.timeout_seconds,
        )

    def analyze(self, input_data: str) -> AgentResult:
        try:
            response = self._client.messages.create(
                model=_MODEL,
                max_tokens=1024,
                messages=[
                    {
                        "role": "user",
                        "content": _PROMPT_TEMPLATE.format(alert=input_data),
                    }
                ],
            )
            raw_text: str = response.content[0].text  # type: ignore[union-attr]
            parsed = json.loads(raw_text)
            findings: list[str] = parsed.get("findings") or []
            confidence: str | None = parsed.get("confidence")
            if not isinstance(findings, list):
                raise ValueError("findings must be a list")
            return AgentResult(
                source_name="watchman",
                findings=findings,
                blind_spots=[],
                raw_confidence=confidence,
                error=None,
            )
        except anthropic.APITimeoutError:
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason="Watchman timed out — behavioral analysis unavailable",
                        next_step="Retry when Anthropic API is available or increase SENTINEL_TIMEOUT",
                    )
                ],
                raw_confidence=None,
                error="timeout",
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason="Watchman output malformed — behavioral analysis unavailable",
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="malformed_output",
            )
        except Exception:
            return AgentResult(
                source_name="watchman",
                findings=[],
                blind_spots=[
                    BlindSpot(
                        source="watchman",
                        reason="Watchman analysis failed — behavioral analysis unavailable",
                        next_step=None,
                    )
                ],
                raw_confidence=None,
                error="analysis_failed",
            )
