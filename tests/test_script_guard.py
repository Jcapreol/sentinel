"""Tests for src/sentinel/triage/script_guard.py (Story 4.2): the
duplicate-run lock, the persistent Cipher lookup cache, and the persistent
API call budget shared by both real-corpus scripts.

Real filesystem lock files and real (tempfile-backed) SQLite throughout --
no mocking of os.open/sqlite3 themselves, matching tests/triage/test_store.py's
existing precedent of testing real SQLite behavior directly. Time-based logic
(TTL, budget window) uses an injectable now_fn rather than real time.sleep.
"""

from pathlib import Path

import pytest

from sentinel.triage.script_guard import (
    ApiCallBudget,
    ApiCallBudgetExceededError,
    CachedLookup,
    LockAlreadyHeldError,
    LookupCache,
    acquire_run_lock,
)

# --- acquire_run_lock -------------------------------------------------------


def test_acquire_run_lock_round_trip_creates_and_removes_lock_file(tmp_path: Path) -> None:
    resource_path = str(tmp_path / "calibration_model_v1.json")
    lock_path = Path(f"{resource_path}.lock")

    with acquire_run_lock(resource_path):
        assert lock_path.exists()

    assert not lock_path.exists()


def test_acquire_run_lock_writes_pid_into_lock_file(tmp_path: Path) -> None:
    import os

    resource_path = str(tmp_path / "calibration_model_v1.json")
    lock_path = Path(f"{resource_path}.lock")

    with acquire_run_lock(resource_path):
        assert lock_path.read_text().strip() == str(os.getpid())


def test_acquire_run_lock_raises_on_second_concurrent_acquire(tmp_path: Path) -> None:
    resource_path = str(tmp_path / "calibration_model_v1.json")

    with acquire_run_lock(resource_path):
        with pytest.raises(LockAlreadyHeldError):
            with acquire_run_lock(resource_path):
                pass  # pragma: no cover -- must not be reached


def test_acquire_run_lock_error_names_the_lock_path_and_pid(tmp_path: Path) -> None:
    import os

    resource_path = str(tmp_path / "calibration_model_v1.json")

    with acquire_run_lock(resource_path):
        with pytest.raises(LockAlreadyHeldError) as exc:
            with acquire_run_lock(resource_path):
                pass  # pragma: no cover
    message = str(exc.value)
    assert f"{resource_path}.lock" in message
    assert str(os.getpid()) in message


def test_acquire_run_lock_releases_on_exception_inside_the_with_block(tmp_path: Path) -> None:
    resource_path = str(tmp_path / "calibration_model_v1.json")
    lock_path = Path(f"{resource_path}.lock")

    with pytest.raises(RuntimeError, match="simulated failure"):
        with acquire_run_lock(resource_path):
            raise RuntimeError("simulated failure")

    assert not lock_path.exists()

    # A fresh acquire must succeed now that the lock was released.
    with acquire_run_lock(resource_path):
        assert lock_path.exists()


def test_acquire_run_lock_is_independent_per_resource_path(tmp_path: Path) -> None:
    resource_a = str(tmp_path / "a.json")
    resource_b = str(tmp_path / "b.json")

    with acquire_run_lock(resource_a):
        with acquire_run_lock(resource_b):  # different resource -- must not raise
            pass


def test_acquire_run_lock_does_not_delete_a_lock_file_it_no_longer_owns(tmp_path: Path) -> None:
    """Regression test for code review finding 2026-08-03: without a PID
    check before unlink, a scenario where the lock slot has been taken over
    by a DIFFERENT process (e.g. after an operator manually deleted a
    believed-stale lock and a new process acquired it) would have this
    process's own finally block delete that other process's lock file out
    from under it, defeating mutual exclusion."""
    resource_path = str(tmp_path / "calibration_model_v1.json")
    lock_path = Path(f"{resource_path}.lock")

    with acquire_run_lock(resource_path):
        # Simulate another process having taken over this lock slot in the
        # interim.
        lock_path.write_text("999999999")

    assert lock_path.exists()
    assert lock_path.read_text() == "999999999"


def test_acquire_run_lock_creates_missing_parent_directory(tmp_path: Path) -> None:
    """Regression test for code review finding 2026-08-03: without a
    proactive mkdir (mirroring _connect's existing precedent for the SQLite
    state path), a resource path in a not-yet-created directory raised an
    uncaught FileNotFoundError instead of the clean, actionable error every
    caller's `except (ValueError, LockAlreadyHeldError,
    ApiCallBudgetExceededError)` clause is built around."""
    resource_path = str(
        tmp_path / "nested" / "does" / "not" / "exist" / "calibration_model_v1.json"
    )
    lock_path = Path(f"{resource_path}.lock")

    with acquire_run_lock(resource_path):
        assert lock_path.exists()

    assert not lock_path.exists()


# --- LookupCache -------------------------------------------------------------


def _db_path(tmp_path: Path) -> str:
    return str(tmp_path / ".sentinel_script_state.db")


def test_lookup_cache_miss_returns_none(tmp_path: Path) -> None:
    cache = LookupCache(_db_path(tmp_path), ttl_seconds=3600)

    assert cache.get("domain", "evil.example.com", "virustotal") is None


def test_lookup_cache_hit_within_ttl_returns_stored_result(tmp_path: Path) -> None:
    clock = {"t": 1000.0}
    cache = LookupCache(_db_path(tmp_path), ttl_seconds=3600, now_fn=lambda: clock["t"])
    stored = CachedLookup(weight=0.7, direction="malicious", finding="VirusTotal: 5 engines flagged")

    cache.put("domain", "evil.example.com", "virustotal", stored)
    clock["t"] += 10  # well within any reasonable TTL

    result = cache.get("domain", "evil.example.com", "virustotal")

    assert result == stored


def test_lookup_cache_miss_after_ttl_expiry_returns_none(tmp_path: Path) -> None:
    clock = {"t": 1000.0}
    cache = LookupCache(_db_path(tmp_path), ttl_seconds=3600, now_fn=lambda: clock["t"])
    stored = CachedLookup(weight=0.7, direction="malicious", finding="VirusTotal: 5 engines flagged")
    cache.put("domain", "evil.example.com", "virustotal", stored)

    clock["t"] += 7200  # past the 3600s TTL

    assert cache.get("domain", "evil.example.com", "virustotal") is None


def test_lookup_cache_fresh_put_overwrites_expired_entry(tmp_path: Path) -> None:
    clock = {"t": 1000.0}
    cache = LookupCache(_db_path(tmp_path), ttl_seconds=3600, now_fn=lambda: clock["t"])
    stale = CachedLookup(weight=0.7, direction="malicious", finding="stale finding")
    cache.put("domain", "evil.example.com", "virustotal", stale)
    clock["t"] += 7200

    fresh = CachedLookup(weight=0.1, direction="neutral", finding="fresh finding")
    cache.put("domain", "evil.example.com", "virustotal", fresh)

    assert cache.get("domain", "evil.example.com", "virustotal") == fresh


def test_lookup_cache_keys_by_source_independently(tmp_path: Path) -> None:
    """A cache hit on one source must not suppress a genuinely-uncached
    lookup on another source for the same indicator."""
    cache = LookupCache(_db_path(tmp_path), ttl_seconds=3600)
    cache.put(
        "domain", "evil.example.com", "virustotal",
        CachedLookup(weight=0.7, direction="malicious", finding="vt hit"),
    )

    assert cache.get("domain", "evil.example.com", "abuseipdb") is None


def test_lookup_cache_keys_by_indicator_type_independently(tmp_path: Path) -> None:
    cache = LookupCache(_db_path(tmp_path), ttl_seconds=3600)
    cache.put(
        "domain", "1.2.3.4", "virustotal",
        CachedLookup(weight=0.7, direction="malicious", finding="domain-typed hit"),
    )

    # Same value string, different indicator_type -- must be a separate entry.
    assert cache.get("ip", "1.2.3.4", "virustotal") is None


def test_lookup_cache_persists_across_separate_instances(tmp_path: Path) -> None:
    db_path = _db_path(tmp_path)
    writer = LookupCache(db_path, ttl_seconds=3600)
    writer.put(
        "ip", "1.2.3.4", "abuseipdb",
        CachedLookup(weight=0.4, direction="malicious", finding="abuse hit"),
    )

    reader = LookupCache(db_path, ttl_seconds=3600)  # separate instance, same file
    result = reader.get("ip", "1.2.3.4", "abuseipdb")

    assert result == CachedLookup(weight=0.4, direction="malicious", finding="abuse hit")


# --- ApiCallBudget -------------------------------------------------------------


def test_api_call_budget_allows_calls_under_the_ceiling(tmp_path: Path) -> None:
    budget = ApiCallBudget(_db_path(tmp_path), ceiling=5, window_seconds=3600)

    budget.check_and_record("watchman")
    budget.check_and_record("cipher")  # must not raise


def test_api_call_budget_raises_before_recording_the_call_that_would_exceed(tmp_path: Path) -> None:
    budget = ApiCallBudget(_db_path(tmp_path), ceiling=3, window_seconds=3600)
    for _ in range(3):
        budget.check_and_record("watchman")

    with pytest.raises(ApiCallBudgetExceededError):
        budget.check_and_record("watchman")

    # The rejected call must NOT have been recorded -- confirm no further
    # growth by making the exact same call again and getting the exact same
    # rejection, not a different state.
    with pytest.raises(ApiCallBudgetExceededError):
        budget.check_and_record("watchman")


def test_api_call_budget_combines_watchman_and_cipher_counts(tmp_path: Path) -> None:
    """AC3: 'Watchman + Cipher combined' -- one shared ceiling, not a
    separate ceiling per source."""
    budget = ApiCallBudget(_db_path(tmp_path), ceiling=2, window_seconds=3600)
    budget.check_and_record("watchman")
    budget.check_and_record("virustotal")

    with pytest.raises(ApiCallBudgetExceededError):
        budget.check_and_record("abuseipdb")


def test_api_call_budget_with_none_ceiling_never_raises(tmp_path: Path) -> None:
    budget = ApiCallBudget(_db_path(tmp_path), ceiling=None, window_seconds=3600)

    for _ in range(50):
        budget.check_and_record("watchman")


def test_api_call_budget_window_is_time_based(tmp_path: Path) -> None:
    clock = {"t": 1000.0}
    budget = ApiCallBudget(_db_path(tmp_path), ceiling=1, window_seconds=60, now_fn=lambda: clock["t"])
    budget.check_and_record("watchman")

    clock["t"] += 120  # past the 60s window -- the earlier call must no longer count

    budget.check_and_record("watchman")  # must not raise


def test_api_call_budget_persists_across_separate_instances(tmp_path: Path) -> None:
    db_path = _db_path(tmp_path)
    first = ApiCallBudget(db_path, ceiling=1, window_seconds=3600)
    first.check_and_record("watchman")

    # Separate instance, same file and same configured ceiling -- must see the prior call.
    second = ApiCallBudget(db_path, ceiling=1, window_seconds=3600)
    with pytest.raises(ApiCallBudgetExceededError):
        second.check_and_record("watchman")


def test_api_call_budget_rejects_non_positive_window_when_ceiling_is_set(tmp_path: Path) -> None:
    """Regression test for code review finding 2026-08-03: a zero/negative
    window_seconds with a ceiling set made the ceiling a silent no-op --
    `WHERE called_at > (now - window_seconds)` becomes a future timestamp, so
    the count is always 0 and every call is allowed through, exactly what
    AC3 forbids. Must now fail loudly at construction instead."""
    with pytest.raises(ValueError, match="window_seconds"):
        ApiCallBudget(_db_path(tmp_path), ceiling=5, window_seconds=0)

    with pytest.raises(ValueError, match="window_seconds"):
        ApiCallBudget(_db_path(tmp_path), ceiling=5, window_seconds=-60)


def test_api_call_budget_allows_non_positive_window_when_ceiling_is_none(tmp_path: Path) -> None:
    """ceiling=None already means "no ceiling" explicitly -- window_seconds
    is irrelevant in that case and must not be rejected."""
    budget = ApiCallBudget(_db_path(tmp_path), ceiling=None, window_seconds=0)
    budget.check_and_record("watchman")  # must not raise


def test_api_call_budget_check_and_record_is_atomic_under_concurrent_threads(
    tmp_path: Path,
) -> None:
    """Regression test for a real race found in code review (2026-08-03):
    the original SELECT-then-INSERT was not atomic, letting two concurrent
    callers both read the same pre-increment count and both proceed,
    silently exceeding the ceiling -- exactly what AC3 forbids. Uses a real
    threading.Barrier to force both threads into the check-then-act window
    at the same moment, rather than just asserting the code looks atomic."""
    import threading

    budget = ApiCallBudget(_db_path(tmp_path), ceiling=1, window_seconds=3600)
    barrier = threading.Barrier(2)
    results: list[str] = []
    results_lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            budget.check_and_record("watchman")
            with results_lock:
                results.append("ok")
        except ApiCallBudgetExceededError:
            with results_lock:
                results.append("rejected")

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Deterministic, not flaky: the fix serializes the two callers via
    # SQLite's own locking, so exactly one succeeds and one is rejected
    # every single run -- a race would show up as ["ok", "ok"] (both slipped
    # through) at least occasionally.
    assert sorted(results) == ["ok", "rejected"]
