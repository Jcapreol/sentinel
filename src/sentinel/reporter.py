from pathlib import Path
from typing import Any, TypedDict

from sentinel.cipher import extract_ioc
from sentinel.verdict import AgentResult, VerdictSchema


class IncidentReport(TypedDict):
    executive_summary: str
    indicator_details: dict[str, str]
    evidence_chain: list[dict[str, Any]]
    verdict_and_confidence: dict[str, Any]
    mitre_attack_mapping: list[str]
    recommended_next_steps: list[str]


_TIER_MEANINGS = {
    "Confirmed": (
        "Two independent sources agree on malicious activity. High-confidence threat."
    ),
    "Probable": "Strong signal from one or more sources. Likely malicious.",
    "Investigating": "Insufficient corroborating evidence. Requires further analysis.",
    "Benign": "No malicious indicators detected. Activity appears safe.",
}

_NEXT_STEPS: dict[str, list[str]] = {
    "Confirmed": [
        "Escalate immediately to the incident response team",
        "Isolate the affected host from the network",
        "Preserve forensic evidence (memory, disk, logs)",
        "Open a P1 incident ticket and notify management",
    ],
    "Probable": [
        "Investigate further: pull additional logs and network captures",
        "Escalate to a senior analyst for review",
        "Escalate to incident response if additional context confirms malicious activity",
        "Check for lateral movement from the affected host",
    ],
    "Investigating": [
        "Flag for analyst review within 24 hours",
        "Gather additional context: process trees, parent processes, user activity",
        "Monitor the indicator for increased frequency or pattern changes",
        "Document findings and close if no further evidence emerges",
    ],
    "Benign": [
        "Close the alert with notes explaining the benign determination",
        "Update allow-list if the indicator is known-good infrastructure",
        "No immediate action required",
    ],
}

_MITRE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1041": "Exfiltration Over C2 Channel",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1486": "Data Encrypted for Impact",
    "T1571": "Non-Standard Port",
}

_ACTION_PHRASE: dict[str, str] = {
    "Confirmed": "Immediate escalation and host isolation are recommended.",
    "Probable": "Further investigation is recommended; escalate if confirmed.",
    "Investigating": "Flag for analyst review and gather additional context.",
    "Benign": "No immediate action required; close with notes.",
}


def generate_report(
    input_data: str,
    watchman_result: AgentResult,
    cipher_result: AgentResult,
    verdict: VerdictSchema,
) -> IncidentReport:
    tier = verdict["verdict"]
    timestamp = verdict["timestamp"]
    ioc = extract_ioc(input_data)
    mitre_tags: list[str] = list(watchman_result.get("mitre_tags") or [])

    # Executive Summary
    ioc_desc = f"{ioc[1]} ({ioc[0]})" if ioc else "the submitted alert"
    action_phrase = _ACTION_PHRASE.get(tier, "Review the findings below.")
    first_finding = watchman_result["findings"][:1]
    finding_note = f" {first_finding[0]}." if first_finding else ""
    executive_summary = (
        f"Sentinel analyzed {ioc_desc} and returned a verdict of {tier}.{finding_note}"
        f" {action_phrase}"
    )

    # Indicator Details
    indicator_details: dict[str, str] = {"timestamp": timestamp}
    if ioc:
        indicator_details["type"] = ioc[0]
        indicator_details["value"] = ioc[1]
    else:
        indicator_details["type"] = "unknown"
        indicator_details["value"] = "no extractable IOC"

    # Evidence Chain
    evidence_chain: list[dict[str, Any]] = [
        {
            "source": "watchman",
            "type": "behavioral_analysis",
            "findings": watchman_result["findings"],
            "status": "error" if watchman_result["error"] else "success",
        },
        {
            "source": "cipher",
            "type": "threat_intelligence",
            "findings": cipher_result["findings"],
            "status": "error" if cipher_result["error"] else "success",
        },
    ]

    # Verdict and Confidence
    verdict_and_confidence: dict[str, Any] = {
        "tier": tier,
        "confidence_tier": verdict["confidence_tier"],
        "meaning": _TIER_MEANINGS.get(tier, tier),
        "blind_spots": verdict["blind_spots"],
    }

    return IncidentReport(
        executive_summary=executive_summary,
        indicator_details=indicator_details,
        evidence_chain=evidence_chain,
        verdict_and_confidence=verdict_and_confidence,
        mitre_attack_mapping=mitre_tags,
        recommended_next_steps=_NEXT_STEPS.get(
            tier, ["Review the findings and consult a security analyst."]
        ),
    )


def render_markdown(report: IncidentReport, timestamp: str) -> str:
    lines: list[str] = []
    lines.append("# Sentinel Incident Report")
    lines.append(f"\n**Generated:** {timestamp}\n")
    lines.append("---\n")

    lines.append("## Executive Summary\n")
    lines.append(report["executive_summary"])
    lines.append("")

    lines.append("## Indicator Details\n")
    for key, val in report["indicator_details"].items():
        lines.append(f"- **{key.replace('_', ' ').title()}:** {val}")
    lines.append("")

    lines.append("## Evidence Chain\n")
    for entry in report["evidence_chain"]:
        src = entry["source"].title()
        kind = str(entry["type"]).replace("_", " ").title()
        lines.append(f"### {src} ({kind})\n")
        lines.append(f"**Status:** {entry['status']}")
        findings: list[str] = entry["findings"]
        if findings:
            for finding in findings:
                lines.append(f"- {finding}")
        else:
            lines.append("- No findings")
        lines.append("")

    lines.append("## Verdict and Confidence\n")
    vc = report["verdict_and_confidence"]
    lines.append(f"**Verdict:** {vc['tier']} (tier {vc['confidence_tier']})\n")
    lines.append(f"**Meaning:** {vc['meaning']}\n")
    blind_spots: list[dict[str, Any]] = vc["blind_spots"]
    if blind_spots:
        lines.append("**Blind Spots:**")
        for bs in blind_spots:
            lines.append(f"- {bs['source']}: {bs['reason']}")
    lines.append("")

    lines.append("## MITRE ATT&CK Mapping\n")
    tags: list[str] = report["mitre_attack_mapping"]
    if tags:
        for tag in tags:
            name = _MITRE_NAMES.get(tag)
            lines.append(f"- {tag} — {name}" if name else f"- {tag}")
    else:
        lines.append("- No ATT&CK techniques identified")
    lines.append("")

    lines.append("## Recommended Next Steps\n")
    for step in report["recommended_next_steps"]:
        lines.append(f"- {step}")

    return "\n".join(lines)


def write_report_markdown(
    report: IncidentReport,
    timestamp: str,
    reports_dir: Path = Path("reports"),
) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_ts = timestamp.replace(":", "-").replace("+", "Z")
    filepath = reports_dir / f"{safe_ts}-incident.md"
    filepath.write_text(render_markdown(report, timestamp), encoding="utf-8")
    return filepath
