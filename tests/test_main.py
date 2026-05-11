from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING

import pytest

from conftest import make_agent_result
from sentinel.config import ConfigError
from sentinel.main import main

if TYPE_CHECKING:
    from sentinel.config import Config


def test_positional_arg_is_used_as_input(
    mocker: pytest.MockerFixture, fake_config: "Config"
) -> None:
    mocker.patch("sys.argv", ["sentinel", "test alert content"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result("watchman")
    cipher_mock.return_value.analyze.return_value = make_agent_result("cipher")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    watchman_mock.return_value.analyze.assert_called_once_with("test alert content")


def test_stdin_read_when_no_positional_arg(
    mocker: pytest.MockerFixture, fake_config: "Config"
) -> None:
    mocker.patch("sys.argv", ["sentinel"])
    mocker.patch("sys.stdin", io.StringIO("alert from stdin"))
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result("watchman")
    cipher_mock.return_value.analyze.return_value = make_agent_result("cipher")

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    watchman_mock.return_value.analyze.assert_called_once_with("alert from stdin")


def test_no_input_exits_2_with_usage_to_stderr(
    mocker: pytest.MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch("sys.argv", ["sentinel"])
    mock_stdin = mocker.MagicMock()
    mock_stdin.isatty.return_value = True
    mocker.patch("sys.stdin", mock_stdin)

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err != ""


def test_empty_input_exits_2(
    mocker: pytest.MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch("sys.argv", ["sentinel"])
    mocker.patch("sys.stdin", io.StringIO("   "))

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""


def test_config_error_exits_2(
    mocker: pytest.MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch("sys.argv", ["sentinel", "some alert"])
    mocker.patch(
        "sentinel.main.load_config",
        side_effect=ConfigError("Missing required environment variable: ANTHROPIC_API_KEY"),
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ANTHROPIC_API_KEY" in captured.err


def test_success_exits_0_with_json_to_stdout(
    mocker: pytest.MockerFixture,
    fake_config: "Config",
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel", "suspicious outbound traffic to 1.2.3.4"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result(
        "watchman", findings=["Suspicious outbound connection pattern"]
    )
    cipher_mock.return_value.analyze.return_value = make_agent_result(
        "cipher", findings=["VirusTotal: 1.2.3.4 flagged by 5 engines"]
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out != ""
    result = json.loads(captured.out)
    assert result["confidence_tier"] == 2
    assert result["source_independence_confirmed"] is True
    assert result["verdict"] == "Probable"


def test_unhandled_exception_exits_1(
    mocker: pytest.MockerFixture,
    fake_config: "Config",
    capsys: pytest.CaptureFixture[str],
) -> None:
    mocker.patch("sys.argv", ["sentinel", "some alert"])
    mocker.patch("sentinel.main.load_config", return_value=fake_config)
    watchman_mock = mocker.patch("sentinel.main.WatchmanAgent")
    cipher_mock = mocker.patch("sentinel.main.CipherAgent")
    watchman_mock.return_value.analyze.return_value = make_agent_result("watchman")
    cipher_mock.return_value.analyze.return_value = make_agent_result("cipher")
    mocker.patch(
        "sentinel.main.assemble_verdict",
        side_effect=RuntimeError("unexpected failure"),
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unexpected error" in captured.err
