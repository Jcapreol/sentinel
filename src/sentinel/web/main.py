import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sentinel.config import ConfigError
from sentinel.config import load as load_config
from sentinel.web import state
from sentinel.web.routes import router
from sentinel.web.verdicts import router as verdicts_router

_STATIC_DIR = Path(__file__).parent.parent.parent.parent / "static"

# [Story 10.1, AC4/D3] This is the first Sentinel component that listens on
# a network; everything before it was outbound-only. Binding beyond
# loopback is a real change in threat model (docs/dashboard-design.md, D3)
# and per D4/Notes for dev, adding a config option for this comes bundled
# with authentication, in whatever future story actually needs it -- not
# before. A plain module constant, not an env var or Config field, so
# there is nothing here to accidentally widen without touching this line.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    try:
        state._config = load_config()
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
app.include_router(router)
app.include_router(verdicts_router)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(str(_STATIC_DIR / "index.html"))


if __name__ == "__main__":
    # [Story 10.1, AC4] The canonical, enforced way to start the server for
    # real use (the Pi deployment) -- binds to DEFAULT_HOST unconditionally.
    # `uvicorn sentinel.web.main:app --reload` (README, dev-only) still
    # works and happens to default to loopback too, but only this entrypoint
    # makes that an actual property of the codebase rather than an accident
    # of how someone invokes uvicorn's own CLI.
    import uvicorn

    uvicorn.run(app, host=DEFAULT_HOST, port=DEFAULT_PORT)
