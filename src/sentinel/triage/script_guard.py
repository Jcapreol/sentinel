"""Shared operational-safety infrastructure for the real-corpus scripts
(fit_real_calibration_model.py, run_evaluation_harness.py): a duplicate-run
lock, a persistent Cipher lookup cache, and a persistent external-API-call
budget. Added in response to the 2026-07-30 calibration saturation incident
and two items deferred from Story 3.3's code review -- see
_bmad-output/implementation-artifacts/triage-4-2-rate-limiting-and-cost-controls.md.

Deliberately NOT used by the live triage path (worker.py) -- WatchmanAgent/
CipherAgent accept these as optional constructor parameters that only the
two real-corpus scripts ever pass, so live triage behavior is provably
unaffected (AC5).

The lock is keyed by a resource path (e.g. calibration_model_v1.json's
absolute path), not by script name, so two DIFFERENT scripts racing on the
same resource are also blocked -- and it must be acquired before ANY work
touching that resource, read or write, since run_evaluation_harness.py only
ever reads calibration_model_v1.json and the 2026-07-30 incident was two
concurrent invocations of that read-only script.

The cache and budget both persist across process runs (a real SQLite file on
disk, not an in-memory dict) -- a configurable TTL/window is meaningless
otherwise, since nothing would ever survive long enough to expire or roll
over.
"""

from __future__ import annotations

import multiprocessing
import sqlite3
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal, TypedDict

# Deliberately no `import os`/`subprocess`/`smtplib` anywhere in this file --
# every triage/*.py module is covered by the permanent structural guard
# test_triage_imports_no_remediation_capable_library (AC3/FR32: no raw
# OS-level file/process control anywhere in the triage pipeline). This
# module's lock/PID needs are met entirely via pathlib (Path.open("x") for
# atomic exclusive creation, Path.unlink() to remove) and
# multiprocessing.current_process().pid (the same real OS PID os.getpid()
# would return, via the higher-level stdlib API for process identity) --
# not a loophole, the actually-appropriate tool for each job.


# [Review][Patch] Single source of truth for both real-corpus scripts' CLI
# defaults -- previously duplicated verbatim in fit_real_calibration_model.py
# and run_evaluation_harness.py (code review 2026-08-03).
DEFAULT_CACHE_TTL_SECONDS = 86400.0  # 24h -- reputation data doesn't change minute to minute
DEFAULT_API_CEILING_WINDOW_HOURS = 1.0


def print_sample_size_cost_warning(
    sample_size_per_class: int | None,
    default_sample_size_per_class: int,
    pool_sizes: dict[str, int],
) -> None:
    """Story 4.1: prints an unmissable stderr warning when a real-corpus
    script's --sample-size-per-class will make substantially more real
    Watchman/Cipher API calls than the default would -- same precedent as
    run_evaluation_harness.py's own _IDENTITY_PLACEHOLDER_WARNING (Story
    3.4): a prominent, printed-once warning, not a blocking/interactive
    confirmation prompt (no script in this codebase blocks on stdin).

    `pool_sizes` maps each class-bucket name (e.g. "benign_tuning",
    "malicious_tuning") to its RAW file count -- this function does its own
    min(sample_size_per_class, pool_size) capping per bucket, matching
    sample_corpus_files's own "return everything if sample_size >= len(files)"
    behavior, so a pool smaller than the requested N is never misreported as
    though N files from it will really be processed.
    """
    if sample_size_per_class is None or sample_size_per_class <= default_sample_size_per_class:
        return
    actual_counts = {
        name: min(sample_size_per_class, pool_size) for name, pool_size in pool_sizes.items()
    }
    actual_total = sum(actual_counts.values())
    default_total = default_sample_size_per_class * len(pool_sizes)
    if actual_total <= default_total:
        return
    ratio = actual_total / default_total
    breakdown = ", ".join(f"{name}={count}" for name, count in actual_counts.items())
    print(
        f"WARNING: --sample-size-per-class {sample_size_per_class} exceeds the default "
        f"({default_sample_size_per_class}) -- this run will make real Watchman/Cipher "
        f"API calls for {actual_total} files total ({breakdown}), ~{ratio:.1f}x the "
        f"default run's {default_total}. Confirm this was intentional.",
        file=sys.stderr,
    )


class LockAlreadyHeldError(Exception):
    """Raised when acquire_run_lock finds an existing lock file -- another
    process is already running against the same resource."""


class ApiCallBudgetExceededError(Exception):
    """Raised by ApiCallBudget.check_and_record before making a real
    external API call that would exceed the configured ceiling. A dedicated
    type, deliberately not a bare RuntimeError -- callers must re-raise this
    past every generic `except Exception:` handler in cipher.py/watchman.py
    and both real-corpus scripts' _score_one_file, or it is silently
    swallowed into a normal-looking coverage-gap result / skipped file,
    exactly what AC3 forbids ("not silently truncating results or
    continuing past the configured budget")."""


class CachedLookup(TypedDict):
    weight: float
    direction: Literal["malicious", "benign", "neutral"]
    finding: str


def _read_stale_pid(lock_path: str) -> str | None:
    try:
        content = Path(lock_path).read_text().strip()
        return content or None
    except OSError:
        return None


@contextmanager
def acquire_run_lock(resource_path: str) -> Iterator[None]:
    """Atomic exclusive-create lock file at f"{resource_path}.lock" (via
    Path.open("x"), the same underlying atomicity as os.O_CREAT|O_EXCL).
    Raises LockAlreadyHeldError immediately if already held -- never blocks
    or waits. Known, accepted limitation (same shape as this codebase's
    existing "hard process kill" limitations elsewhere): a hard kill
    (SIGKILL, Windows TerminateProcess) leaves the lock file orphaned --
    __exit__ never runs. Recovery is manual: confirm the PID named in the
    error is no longer running, then delete the lock file."""
    lock_path = f"{resource_path}.lock"
    # [Review][Patch] Proactively create a missing parent directory, mirroring
    # _connect's existing precedent for the SQLite state path below --
    # without this, a resource_path in a not-yet-created directory raised an
    # uncaught FileNotFoundError instead of the clean, actionable error every
    # caller's `except (ValueError, LockAlreadyHeldError,
    # ApiCallBudgetExceededError)` clause is built around (code review
    # 2026-08-03).
    parent = Path(lock_path).parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    try:
        with Path(lock_path).open("x") as f:
            f.write(str(multiprocessing.current_process().pid))
    except FileExistsError:
        stale_pid = _read_stale_pid(lock_path)
        pid_detail = f"held by PID {stale_pid}" if stale_pid else "PID unreadable"
        raise LockAlreadyHeldError(
            f"Another process appears to already be running against {resource_path} "
            f"({pid_detail}, lock file: {lock_path}). If that process crashed without "
            "cleaning up, confirm it is no longer running, then delete the lock file manually."
        ) from None
    try:
        yield
    finally:
        # [Review][Patch] Verify this process still owns the lock before
        # deleting it (code review 2026-08-03). Without this check: an
        # operator manually deleting a lock file believing its holder
        # crashed, while it was in fact still alive and running, could let a
        # THIRD invocation acquire the lock slot; when the original
        # (still-alive) process eventually reaches this finally block, it
        # would delete the THIRD process's lock file out from under it,
        # silently defeating mutual exclusion. missing_ok=True: another
        # process's own equivalent check may have already left this file
        # absent.
        if _read_stale_pid(lock_path) == str(multiprocessing.current_process().pid):
            Path(lock_path).unlink(missing_ok=True)


def _connect(db_path: str) -> sqlite3.Connection:
    parent = Path(db_path).parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS lookup_cache (
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            source TEXT NOT NULL,
            weight REAL NOT NULL,
            direction TEXT NOT NULL,
            finding TEXT NOT NULL,
            cached_at REAL NOT NULL,
            PRIMARY KEY (indicator_type, indicator_value, source)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_call_log (
            source TEXT NOT NULL,
            called_at REAL NOT NULL
        )
        """
    )
    return conn


class LookupCache:
    """Not Fernet-encrypted, unlike store.py's evidence records -- this
    holds public threat-intel lookups (domain/IP reputation), not customer
    email content.

    `ttl_seconds` is fixed at construction time, not passed per call -- same
    rationale as ApiCallBudget's `ceiling`/`window_seconds`: the script's
    `main()` owns `--cache-ttl-seconds` and constructs one `LookupCache` per
    run; `CipherAgent` only ever needs to report "here's what I found for
    this indicator/source," never the configured TTL itself."""

    def __init__(
        self, db_path: str, ttl_seconds: float, now_fn: Callable[[], float] = time.time
    ) -> None:
        self._db_path = db_path
        self._ttl_seconds = ttl_seconds
        self._now_fn = now_fn

    def get(self, indicator_type: str, indicator_value: str, source: str) -> CachedLookup | None:
        conn = _connect(self._db_path)
        try:
            row = conn.execute(
                "SELECT weight, direction, finding, cached_at FROM lookup_cache "
                "WHERE indicator_type = ? AND indicator_value = ? AND source = ?",
                (indicator_type, indicator_value, source),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        weight, direction, finding, cached_at = row
        if self._now_fn() - cached_at > self._ttl_seconds:
            return None
        return CachedLookup(weight=weight, direction=direction, finding=finding)

    def put(
        self, indicator_type: str, indicator_value: str, source: str, result: CachedLookup
    ) -> None:
        conn = _connect(self._db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO lookup_cache "
                "(indicator_type, indicator_value, source, weight, direction, finding, cached_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    indicator_type,
                    indicator_value,
                    source,
                    result["weight"],
                    result["direction"],
                    result["finding"],
                    self._now_fn(),
                ),
            )
            conn.commit()
        finally:
            conn.close()


class ApiCallBudget:
    """Combined ceiling across every source (AC3: "Watchman + Cipher
    combined") -- one shared budget, not a separate ceiling per source.

    `ceiling`/`window_seconds` are fixed at construction time, not passed
    per call -- the script's `main()` owns the `--api-call-ceiling`/
    `--api-ceiling-window-hours` CLI flags and constructs one `ApiCallBudget`
    per run; `WatchmanAgent`/`CipherAgent` only ever need to report "I'm
    about to make a call for source X," never the configured limits
    themselves."""

    def __init__(
        self,
        db_path: str,
        ceiling: int | None,
        window_seconds: float,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        # [Review][Patch] A zero/negative window with a ceiling set would
        # silently disable the ceiling: WHERE called_at > (now - window_seconds)
        # becomes a future timestamp, so the count is always 0 and every call
        # is allowed through, exactly what AC3 forbids (code review
        # 2026-08-03). ceiling=None already means "no ceiling" explicitly, so
        # only a set ceiling with a non-positive window is an error.
        if ceiling is not None and window_seconds <= 0:
            raise ValueError(
                f"window_seconds must be > 0 when ceiling is set, got {window_seconds!r}"
            )
        self._db_path = db_path
        self._ceiling = ceiling
        self._window_seconds = window_seconds
        self._now_fn = now_fn

    def check_and_record(self, source: str) -> None:
        if self._ceiling is None:
            return
        now = self._now_fn()
        conn = _connect(self._db_path)
        # [Review][Patch] Autocommit mode so the BEGIN IMMEDIATE below is the
        # only transaction control in play -- Python's sqlite3 module's own
        # implicit transaction handling (the default isolation_level="")
        # would not otherwise make the SELECT-then-INSERT below atomic.
        conn.isolation_level = None
        try:
            # BEGIN IMMEDIATE acquires SQLite's RESERVED lock immediately,
            # before the SELECT even runs -- a concurrent caller's own BEGIN
            # IMMEDIATE blocks (via sqlite3's default busy-timeout retry)
            # until this transaction commits or rolls back. Closes the TOCTOU
            # race the Acceptance Auditor empirically reproduced in code
            # review (2026-08-03): two callers could previously both SELECT
            # the same pre-increment count and both proceed, silently
            # exceeding the combined ceiling AC3 requires.
            conn.execute("BEGIN IMMEDIATE")
            (count,) = conn.execute(
                "SELECT COUNT(*) FROM api_call_log WHERE called_at > ?",
                (now - self._window_seconds,),
            ).fetchone()
            if count >= self._ceiling:
                raise ApiCallBudgetExceededError(
                    f"API call ceiling of {self._ceiling} within {self._window_seconds:.0f}s "
                    f"reached ({count} calls already recorded in this window) -- refusing the "
                    f"{source!r} call that would exceed it. Increase --api-call-ceiling or "
                    "wait for the window to roll over."
                )
            conn.execute(
                "INSERT INTO api_call_log (source, called_at) VALUES (?, ?)", (source, now)
            )
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            conn.close()
