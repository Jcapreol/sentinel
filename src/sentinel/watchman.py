import json
import re

import anthropic

from sentinel.config import Config
from sentinel.verdict import AgentResult, BlindSpot

_MODEL = "claude-haiku-4-5-20251001"

_SYSTEM = (
    "You are a security analysis tool. "
    "You MUST respond with raw JSON only — no markdown, no code fences, no explanatory text. "
    "Your entire response must be a single JSON object parseable by json.loads()."
)

_PROMPT_TEMPLATE = """\
Analyze the following security alert for behavioral indicators of compromise.

Respond with this exact JSON structure and nothing else — no markdown, no code fences:
{{"findings": ["<specific behavioral finding>", "<another finding>"], "confidence": "<Investigating|Probable|Confirmed>"}}

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
                system=_SYSTEM,
                messages=[
                    {
                        "role": "user",
                        "content": _PROMPT_TEMPLATE.format(alert=input_data),
                    }
                ],
            )
            raw_text: str = response.content[0].text  # type: ignore[union-attr]
            # Strip markdown code fences Claude sometimes adds despite instructions
            cleaned = re.sub(r"```(?:json)?\s*\n?", "", raw_text.strip())
            cleaned = re.sub(r"```\s*", "", cleaned).strip()
            parsed = json.loads(cleaned)
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
