import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sentinel.config import Config, ConfigError
from sentinel.config import load as load_config

_STATIC_DIR = Path(__file__).parent.parent.parent.parent / "static"

_config: Config | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _config
    try:
        _config = load_config()
    except ConfigError as exc:
        print(f"[sentinel-web] {exc}", file=sys.stderr)
        print(
            "[sentinel-web] Set ANTHROPIC_API_KEY, VIRUSTOTAL_API_KEY,"
            " ABUSEIPDB_API_KEY, URLHAUS_API_KEY",
            file=sys.stderr,
        )
    yield


app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(str(_STATIC_DIR / "index.html"))
