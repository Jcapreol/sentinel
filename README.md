# SENTINEL

[![CI](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Jcapreol/sentinel/actions/workflows/ci.yml)

SENTINEL is an open-source, MIT-licensed multi-agent AI SOC analyst for the terminal that accepts a raw security alert, log line, or IOC and produces a corroborated, structured verdict in under 30 seconds.
It runs two independent analysis agents — Watchman (Claude behavioral analysis) and Cipher (VirusTotal + AbuseIPDB threat intelligence) — and maps independent source count to human-readable confidence tiers (Investigating / Probable / Confirmed).
Full documentation, usage instructions, and setup guide are completed in v1.0.
