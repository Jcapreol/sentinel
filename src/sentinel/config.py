from dotenv import load_dotenv
load_dotenv()

import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    anthropic_api_key: str
    virustotal_api_key: str
    abuseipdb_api_key: str
    timeout_seconds: int = 10


def load() -> Config:
    missing = [
        var
        for var in ("ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")
        if not os.environ.get(var)
    ]
    if missing:
        raise ConfigError(f"Missing required environment variable: {missing[0]}")

    timeout_raw = os.environ.get("SENTINEL_TIMEOUT")
    timeout = int(timeout_raw) if timeout_raw else 10

    return Config(
        anthropic_api_key=os.environ["ANTHROPIC_API_KEY"],
        virustotal_api_key=os.environ["VIRUSTOTAL_API_KEY"],
        abuseipdb_api_key=os.environ["ABUSEIPDB_API_KEY"],
        timeout_seconds=timeout,
    )
