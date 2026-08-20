"""Heartbeat / liveness self-monitoring for the poll pipeline (Story 8.1).

The 2026-08-17 incident: a Gmail OAuth refresh token expired; cron kept
invoking `sentinel-triage --once` every 5 minutes for ~2 days; every
invocation failed with the same ConfigError; nothing alerted; the outage was
discovered only when a human noticed `--view` timestamps were stale.

AC1's Q1 answer: prior to this story, a successful poll with no new mail
produces ZERO log output and recorded no positive success signal anywhere --
`run_poll_cycle` returning without raising is observable only by its
ABSENCE of failure, not by any explicit signal. Confirmed by tracing the
code directly (not assumed): the per-message loop body never executes when
there is no new mail, so no print statement fires, and `poll_checkpoint`
(store.py) has no timestamp column at all -- there was nothing a monitoring
mechanism could check. This module creates that signal; it does not persist
one that already existed.

"Success" is defined narrowly (per this story's own Notes for dev: "Do not
build a general health framework. This story is one signal: is the poll
working."): `run_poll_cycle` returning without raising. This deliberately
does NOT count a per-message failure (an isolated, already-self-healing
situation -- Story 1.7's own design, retried automatically next cycle) as
"unhealthy" -- only a failure that stops the poll cycle itself (auth
failure, Gmail unreachable, etc.) does. AC1's incident -- an OAuth
ConfigError raised out of `build_gmail_service`, which happens before any
per-message work begins -- is exactly this kind of failure.

State lives in a small plain-text JSON file, a SIBLING of evidence.db, not
inside it (Q2): the timestamp "must survive process exit and should not
require the evidence store to be readable, since a future failure mode may
involve the store itself" (this story's own spec). evidence.db is a
Fernet-encrypted SQLite file (store.py) -- a corrupted DB, a lost encryption
key, or a locked file would make health state unreadable at exactly the
moment it matters most if it lived there. This file needs no encryption (it
holds only a timestamp and a boolean, nothing about email content) and no
SQL (two fields, checked once per poll cycle) -- a JSON file is the simplest
correct choice for this story's narrow scope, not an under-engineered one.
"""

import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import TypedDict

from sentinel.alerter import send_health_alert
from sentinel.config import Config


class HealthState(TypedDict):
    last_success_utc: str | None
    alert_active: bool


def _health_state_path(db_path: str) -> Path:
    """Sibling of evidence.db -- e.g. data/evidence.db -> data/health_state.json
    -- same directory as this deployment's other runtime state, without
    being inside evidence.db itself (see module docstring, Q2)."""
    return Path(db_path).with_name("health_state.json")


def try_load_health_state(db_path: str) -> HealthState | None:
    """[Story 10.3] The one parse+validate implementation for the health
    state file. Returns None specifically when the file is missing,
    unreadable, corrupt JSON, or shaped wrong -- distinct from a
    successfully-read file that happens to hold the same values a failed
    read would produce (a genuinely fresh deployment's
    {"last_success_utc": None, "alert_active": False}). That distinction
    doesn't matter to this module's own callers (record_poll_success/
    record_poll_failure, via load_health_state below, which collapses
    both cases to the same safe default -- see its own docstring for why).
    It does matter to a caller that needs to tell a human "we don't know
    the status" apart from "the status is healthy" -- the web dashboard's
    AC6 ("missing or unreadable" must show as unknown, not silently
    healthy), which is why this is a separate, public function rather
    than an inline private helper."""
    path = _health_state_path(db_path)
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    last_success_utc = raw.get("last_success_utc")
    alert_active = raw.get("alert_active")
    if last_success_utc is not None and not isinstance(last_success_utc, str):
        return None
    if not isinstance(alert_active, bool):
        return None
    return {"last_success_utc": last_success_utc, "alert_active": alert_active}


def load_health_state(db_path: str) -> HealthState:
    """Never raises. A missing, corrupt, or unreadable state file degrades
    to the default (never-succeeded, no active alert) rather than crashing
    the poll cycle this function exists to monitor -- that default is the
    same one a genuinely fresh deployment starts with, so a transient read
    glitch is at worst indistinguishable from "first run ever," not a new
    failure mode of its own."""
    state = try_load_health_state(db_path)
    if state is None:
        return HealthState(last_success_utc=None, alert_active=False)
    return state


def save_health_state(db_path: str, state: HealthState) -> None:
    """Never raises. A failed write (disk full, permissions) degrades the
    NEXT read back to the default state rather than crashing the poll cycle
    that just ran (whether it succeeded or already failed for its own,
    unrelated reason).

    [Review] Writes to a temp file in the same directory, then atomically
    renames it into place via Path.replace() -- matching this project's
    existing atomic-write precedent (triage/eval.py's save_calibration_model,
    itself citing triage/store.py's persist_evidence_record). Without this,
    a hard process kill (SIGKILL, Pi power loss) mid-write -- or, more
    realistically for this specific file, two overlapping `--once`
    invocations if a cron-fired run ever hangs past the 5-minute interval --
    could leave a truncated, syntactically-invalid JSON fragment on disk.
    load_health_state already degrades a corrupt file safely to the default
    state (confirmed empirically during review: truncated at every byte
    offset, never crashes), so this isn't closing a crash risk -- it's
    closing the narrower, rarer case where a genuinely torn write happens to
    land as valid-but-wrong JSON that silently reads back as a healthier (or
    unhealthier) state than reality."""
    path = _health_state_path(db_path)
    try:
        parent = path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f"{path.name}.tmp-{uuid.uuid4().hex}")
        tmp_path.write_text(json.dumps(state))
        tmp_path.replace(path)
    except OSError as e:
        print(
            f"[worker] WARNING: failed to write health state to {path}: "
            f"{type(e).__name__}: {e}",
            file=sys.stderr,
        )


def _elapsed_minutes(last_success_utc: str | None, now: datetime) -> float | None:
    if last_success_utc is None:
        return None
    # [Review] load_health_state only validates last_success_utc is None-or-
    # str, never that it's a genuinely parseable ISO datetime -- a
    # corrupted/hand-edited/future-format-changed value previously crashed
    # this with an uncaught ValueError, which propagated out of
    # record_poll_failure/record_poll_success and MASKED the real poll
    # failure this whole module exists to surface (the exception from here
    # replaced the original exception in run_poll_cycle_with_heartbeat's
    # except block, before send_health_alert was ever reached). Treated the
    # same as a missing timestamp -- "never succeeded" is the honest,
    # self-consistent interpretation of "we don't actually know when it
    # last succeeded," not a reason to crash the monitoring code itself.
    try:
        last_success = datetime.fromisoformat(last_success_utc)
    except ValueError:
        return None
    return (now - last_success).total_seconds() / 60.0


def _elapsed_display(last_success_utc: str | None, now: datetime) -> str:
    elapsed = _elapsed_minutes(last_success_utc, now)
    if elapsed is None:
        return "an unknown period (no successful poll has ever been recorded)"
    return f"{elapsed:.0f} minutes"


def _threshold_exceeded(
    last_success_utc: str | None, now: datetime, threshold_minutes: float
) -> bool:
    elapsed = _elapsed_minutes(last_success_utc, now)
    if elapsed is None:
        # Never succeeded even once -- a broken-from-the-start deployment
        # should not have to wait out its own threshold window before
        # surfacing that fact.
        return True
    return elapsed > threshold_minutes


def _maybe_send_health_alert(config: Config, status: str, detail: str) -> None:
    # AC7: heartbeat alerts use their OWN enable flag, independent of and
    # defaulting the opposite way from SENTINEL_ALERT_ENABLED (verdict
    # alerts, off by default) -- see config.py's alert_heartbeat_enabled
    # docstring and this story's AC7 answer for the full reasoning.
    if not config.alert_heartbeat_enabled:
        print(
            "[worker] Health check: SENTINEL_ALERT_HEARTBEAT_ENABLED is false -- "
            f"not sending {status} alert",
            file=sys.stderr,
        )
        return
    send_health_alert(config, status=status, detail=detail)


def record_poll_success(db_path: str, config: Config, now: datetime) -> None:
    """Call after a poll cycle completes without raising (this module's
    definition of success -- see module docstring). If an "Unhealthy" alert
    was outstanding, sends the matching recovery alert (AC4: exactly one
    alert per transition, not one per cycle) before clearing it."""
    state = load_health_state(db_path)
    if state["alert_active"]:
        elapsed = _elapsed_display(state["last_success_utc"], now)
        print(
            "[worker] Health check: poll succeeded again after an outage -- "
            "sending recovery alert",
            file=sys.stderr,
        )
        _maybe_send_health_alert(
            config,
            status="Recovered",
            detail=f"The poll succeeded again after being unhealthy for {elapsed}.",
        )
    save_health_state(db_path, {"last_success_utc": now.isoformat(), "alert_active": False})


def record_poll_failure(db_path: str, config: Config, error: BaseException, now: datetime) -> None:
    """Call after a poll cycle raises (this module's definition of failure).
    Sends an "Unhealthy" alert exactly once per outage (AC4): only on the
    first recorded cycle that crosses the configured threshold, never again
    while one is already outstanding -- a 637-failure outage produces one
    email, not 637."""
    state = load_health_state(db_path)
    if _threshold_exceeded(
        state["last_success_utc"], now, config.alert_heartbeat_threshold_minutes
    ) and not state["alert_active"]:
        elapsed = _elapsed_display(state["last_success_utc"], now)
        print(
            f"[worker] Health check: no successful poll for {elapsed} "
            f"(threshold {config.alert_heartbeat_threshold_minutes:g} min) -- "
            "sending unhealthy alert",
            file=sys.stderr,
        )
        _maybe_send_health_alert(
            config,
            status="Unhealthy",
            detail=(
                f"No successful poll for {elapsed} (threshold "
                f"{config.alert_heartbeat_threshold_minutes:g} min). Last failure: "
                f"{type(error).__name__}: {error}"
            ),
        )
        save_health_state(
            db_path, {"last_success_utc": state["last_success_utc"], "alert_active": True}
        )
    # Threshold not yet exceeded, or an alert is already active: last_success_utc
    # is deliberately left untouched -- only a genuine success (record_poll_
    # success) may advance it -- and if alert_active didn't change, there is
    # nothing new to persist.
