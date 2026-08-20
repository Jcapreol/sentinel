from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.config import Config, ConfigError
from sentinel.triage.health import (
    HealthState,
    load_health_state,
    record_poll_failure,
    record_poll_success,
    save_health_state,
    try_load_health_state,
)

# [Story 8.1, AC6] Verbatim from the story spec's live data -- use as-is,
# not paraphrased, so the fixture actually proves the real incident's
# failure cause survives into the alert detail.
_VERBATIM_INVALID_GRANT_ERROR = ConfigError(
    "Failed to load Gmail OAuth credentials from PosixPath('secrets/oauth-token.json'): "
    "('invalid_grant: Token has been expired or revoked.', {'error': 'invalid_grant', "
    "'error_description': 'Token has been expired or revoked.'})"
)

_NOW = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)


def _health_state_path(db_path: str) -> Path:
    return Path(db_path).with_name("health_state.json")


# --- load_health_state / save_health_state ---------------------------------------


def test_load_health_state_missing_file_returns_default(store_db_path: str) -> None:
    state = load_health_state(store_db_path)

    assert state == {"last_success_utc": None, "alert_active": False}


def test_load_health_state_corrupt_json_returns_default(store_db_path: str) -> None:
    _health_state_path(store_db_path).parent.mkdir(parents=True, exist_ok=True)
    _health_state_path(store_db_path).write_text("{not valid json")

    state = load_health_state(store_db_path)

    assert state == {"last_success_utc": None, "alert_active": False}


@pytest.mark.parametrize(
    "raw",
    [
        '{"last_success_utc": 12345, "alert_active": false}',  # wrong type for timestamp
        '{"last_success_utc": null, "alert_active": "yes"}',  # wrong type for bool
        "[]",  # not even an object
        '"just a string"',
    ],
)
def test_load_health_state_malformed_shape_returns_default(store_db_path: str, raw: str) -> None:
    _health_state_path(store_db_path).parent.mkdir(parents=True, exist_ok=True)
    _health_state_path(store_db_path).write_text(raw)

    state = load_health_state(store_db_path)

    assert state == {"last_success_utc": None, "alert_active": False}


# --- try_load_health_state (Story 10.3): distinguishes read failure from ----
# --- a genuine, successfully-read default -----------------------------------


def test_try_load_health_state_missing_file_returns_none(store_db_path: str) -> None:
    assert try_load_health_state(store_db_path) is None


def test_try_load_health_state_corrupt_json_returns_none(store_db_path: str) -> None:
    _health_state_path(store_db_path).parent.mkdir(parents=True, exist_ok=True)
    _health_state_path(store_db_path).write_text("{not valid json")

    assert try_load_health_state(store_db_path) is None


@pytest.mark.parametrize(
    "raw",
    [
        '{"last_success_utc": 12345, "alert_active": false}',
        '{"last_success_utc": null, "alert_active": "yes"}',
        "[]",
        '"just a string"',
    ],
)
def test_try_load_health_state_malformed_shape_returns_none(store_db_path: str, raw: str) -> None:
    _health_state_path(store_db_path).parent.mkdir(parents=True, exist_ok=True)
    _health_state_path(store_db_path).write_text(raw)

    assert try_load_health_state(store_db_path) is None


def test_try_load_health_state_genuine_fresh_default_is_not_none(store_db_path: str) -> None:
    """The key property try_load_health_state exists for: a genuinely
    successful read of a file that happens to hold the exact same values
    load_health_state's failure path also returns must NOT be
    indistinguishable from a read failure -- that's the whole point."""
    save_health_state(store_db_path, {"last_success_utc": None, "alert_active": False})

    state = try_load_health_state(store_db_path)

    assert state is not None
    assert state == {"last_success_utc": None, "alert_active": False}


def test_try_load_health_state_successful_read_matches_load_health_state(
    store_db_path: str,
) -> None:
    save_health_state(
        store_db_path, {"last_success_utc": "2026-08-20T12:00:00+00:00", "alert_active": True}
    )

    assert try_load_health_state(store_db_path) == load_health_state(store_db_path)


def test_record_poll_failure_never_crashes_on_unparseable_last_success_utc(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Review] load_health_state only validates last_success_utc is
    None-or-str, never that it's genuinely parseable -- a corrupted (or
    otherwise malformed-but-str-typed) value previously raised an uncaught
    ValueError from record_poll_failure, which would MASK the real poll
    failure being reported (the ValueError replaces the original exception
    in run_poll_cycle_with_heartbeat's except block, and the alert-sending
    logic is never reached). Must degrade to "never succeeded" instead,
    the same way a missing timestamp already does."""
    save_health_state(
        store_db_path, {"last_success_utc": "not-a-valid-timestamp", "alert_active": False}
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(  # must not raise
        store_db_path, store_config, RuntimeError("the real failure"), _NOW
    )

    alert_spy.assert_called_once()
    assert "unknown period" in alert_spy.call_args.kwargs["detail"]


def test_record_poll_success_never_crashes_on_unparseable_last_success_utc(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    save_health_state(
        store_db_path, {"last_success_utc": "not-a-valid-timestamp", "alert_active": True}
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_success(store_db_path, store_config, _NOW)  # must not raise

    alert_spy.assert_called_once()
    assert alert_spy.call_args.kwargs["status"] == "Recovered"


def test_save_then_load_health_state_round_trips(store_db_path: str) -> None:
    state: HealthState = {"last_success_utc": "2026-08-20T12:00:00+00:00", "alert_active": True}

    save_health_state(store_db_path, state)

    assert load_health_state(store_db_path) == state


def test_save_health_state_is_atomic_leaves_no_temp_file_behind(store_db_path: str) -> None:
    """[Review] Writes via a temp file + Path.replace(), matching
    eval.py's save_calibration_model precedent -- confirms the directory
    ends up with exactly the final file, no leftover .tmp-<uuid> artifact,
    after a normal successful save."""
    save_health_state(store_db_path, {"last_success_utc": None, "alert_active": False})

    entries = list(_health_state_path(store_db_path).parent.iterdir())
    assert entries == [_health_state_path(store_db_path)]


def test_health_state_path_is_sibling_of_evidence_db(tmp_path: Path) -> None:
    # [Story 8.1, Q2] Must not live inside evidence.db -- a corrupted DB or
    # lost encryption key must not also take out the heartbeat signal.
    db_path = str(tmp_path / "data" / "evidence.db")
    save_health_state(db_path, {"last_success_utc": None, "alert_active": False})

    assert (tmp_path / "data" / "health_state.json").exists()
    assert not (tmp_path / "data" / "evidence.db").exists()


def test_save_health_state_creates_parent_directory_if_missing(tmp_path: Path) -> None:
    db_path = str(tmp_path / "not-yet-created" / "evidence.db")

    save_health_state(db_path, {"last_success_utc": None, "alert_active": False})

    assert (tmp_path / "not-yet-created" / "health_state.json").exists()


def test_save_health_state_failure_never_raises(mocker, store_db_path: str) -> None:  # type: ignore[no-untyped-def]
    mocker.patch("pathlib.Path.write_text", side_effect=OSError("disk full"))

    save_health_state(store_db_path, {"last_success_utc": None, "alert_active": False})  # must not raise


# --- record_poll_success -----------------------------------------------------------


def test_record_poll_success_first_ever_updates_timestamp_no_alert(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 8.1, AC6] Healthy run fixture: a fresh deployment's first
    successful poll must record the timestamp and must NOT fire any alert
    (there was never an outage to recover from)."""
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_success(store_db_path, store_config, _NOW)

    alert_spy.assert_not_called()
    assert load_health_state(store_db_path) == {
        "last_success_utc": _NOW.isoformat(),
        "alert_active": False,
    }


def test_record_poll_success_after_active_alert_sends_recovery_and_clears_it(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 8.1, AC4/AC6] Recovery-after-an-outage fixture: exactly one
    recovery alert, and alert_active must be cleared so a later outage can
    alert again."""
    save_health_state(
        store_db_path,
        {"last_success_utc": (_NOW - timedelta(hours=2)).isoformat(), "alert_active": True},
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_success(store_db_path, store_config, _NOW)

    alert_spy.assert_called_once()
    call = alert_spy.call_args
    assert call.kwargs["status"] == "Recovered"
    assert "120 minutes" in call.kwargs["detail"]
    assert load_health_state(store_db_path) == {
        "last_success_utc": _NOW.isoformat(),
        "alert_active": False,
    }


def test_record_poll_success_when_no_alert_was_active_does_not_send_recovery(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    save_health_state(
        store_db_path,
        {"last_success_utc": (_NOW - timedelta(minutes=5)).isoformat(), "alert_active": False},
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_success(store_db_path, store_config, _NOW)

    alert_spy.assert_not_called()


def test_record_poll_failure_exactly_at_threshold_does_not_alert(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Review] The boundary is strict ">", not ">=" -- mutation-tested
    during adversarial review and found genuinely unverified by the two
    nearest existing tests (5 min under, 35 min over, neither of which
    distinguishes the two operators). Elapsed exactly equal to the
    threshold must NOT alert."""
    save_health_state(
        store_db_path,
        {
            "last_success_utc": (_NOW - timedelta(minutes=30)).isoformat(),
            "alert_active": False,
        },
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, store_config, RuntimeError("boom"), _NOW)

    alert_spy.assert_not_called()


def test_record_poll_failure_one_second_past_threshold_alerts(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    save_health_state(
        store_db_path,
        {
            "last_success_utc": (_NOW - timedelta(minutes=30, seconds=1)).isoformat(),
            "alert_active": False,
        },
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, store_config, RuntimeError("boom"), _NOW)

    alert_spy.assert_called_once()


# --- record_poll_failure ------------------------------------------------------------


def test_record_poll_failure_verbatim_invalid_grant_configerror_names_cause(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 8.1, AC5/AC6] The exact 2026-08-17 incident, verbatim: the
    alert must name the real failure cause, not a generic message."""
    save_health_state(
        store_db_path,
        {"last_success_utc": (_NOW - timedelta(minutes=45)).isoformat(), "alert_active": False},
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, store_config, _VERBATIM_INVALID_GRANT_ERROR, _NOW)

    alert_spy.assert_called_once()
    detail = alert_spy.call_args.kwargs["detail"]
    assert "invalid_grant" in detail
    assert "Token has been expired or revoked" in detail
    assert alert_spy.call_args.kwargs["status"] == "Unhealthy"


def test_record_poll_failure_threshold_not_yet_exceeded_does_not_alert(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 8.1, AC6] Threshold-not-yet-exceeded fixture: a single recent
    failure, well under the default 30-minute threshold, must not alert."""
    save_health_state(
        store_db_path,
        {"last_success_utc": (_NOW - timedelta(minutes=5)).isoformat(), "alert_active": False},
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, store_config, RuntimeError("transient"), _NOW)

    alert_spy.assert_not_called()
    assert load_health_state(store_db_path)["alert_active"] is False


def test_record_poll_failure_first_ever_failure_alerts_immediately(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """A deployment that has NEVER once succeeded should not have to wait
    out its own threshold window before surfacing that fact."""
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, store_config, RuntimeError("broken from the start"), _NOW)

    alert_spy.assert_called_once()
    assert load_health_state(store_db_path)["alert_active"] is True


def test_record_poll_failure_past_threshold_sends_alert_and_sets_active(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    save_health_state(
        store_db_path,
        {"last_success_utc": (_NOW - timedelta(minutes=35)).isoformat(), "alert_active": False},
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, store_config, RuntimeError("boom"), _NOW)

    alert_spy.assert_called_once()
    assert alert_spy.call_args.kwargs["status"] == "Unhealthy"
    assert load_health_state(store_db_path) == {
        "last_success_utc": (_NOW - timedelta(minutes=35)).isoformat(),
        "alert_active": True,
    }


def test_record_poll_failure_repeated_after_alert_already_active_does_not_duplicate(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 8.1, AC4/AC6] The 637-failure fixture: once an alert has
    already fired for the current outage, every subsequent failed cycle
    must NOT fire another one."""
    save_health_state(
        store_db_path,
        {"last_success_utc": (_NOW - timedelta(days=2)).isoformat(), "alert_active": True},
    )
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    for _ in range(5):
        record_poll_failure(store_db_path, store_config, RuntimeError("boom"), _NOW)

    alert_spy.assert_not_called()
    assert load_health_state(store_db_path)["alert_active"] is True


def test_record_poll_failure_respects_alert_heartbeat_enabled_false(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 8.1, AC7] The independent heartbeat flag, not alert_enabled,
    gates this -- confirmed here by leaving alert_enabled at its own
    default (False) and only disabling the heartbeat-specific flag."""
    config = replace(store_config, alert_heartbeat_enabled=False)
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, config, RuntimeError("boom"), _NOW)

    alert_spy.assert_not_called()
    # State still tracks the transition even though no email was sent -- a
    # later recovery, if heartbeat alerting is re-enabled by then, must not
    # be confused by stale alert_active bookkeeping.
    assert load_health_state(store_db_path)["alert_active"] is True


def test_record_poll_failure_heartbeat_enabled_independent_of_alert_enabled(
    mocker,  # type: ignore[no-untyped-def]
    store_db_path: str,
    store_config: Config,
) -> None:
    """[Story 8.1, AC7] The inverse: alert_enabled left at its default
    (False, verdict alerts off) must NOT suppress a heartbeat alert, since
    alert_heartbeat_enabled defaults to True independently."""
    assert store_config.alert_enabled is False
    assert store_config.alert_heartbeat_enabled is True
    alert_spy = mocker.patch("sentinel.triage.health.send_health_alert")

    record_poll_failure(store_db_path, store_config, RuntimeError("boom"), _NOW)

    alert_spy.assert_called_once()
