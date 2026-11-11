"""Перевірки аргументів, stdout/stderr та локального режиму CLI."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from labs.lab04 import main

CVE = "CVE-2099-10001"
SAMPLE = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


def test_local_cli_prints_one_json_and_no_network(monkeypatch, capsys):
    """Локальний режим не викликає навіть підмінену мережеву функцію."""
    fake_fetch = Mock(side_effect=AssertionError("Unexpected NVD request"))
    monkeypatch.setattr(main.api_client, "fetch_response", fake_fetch)
    assert main.main(["--cve", CVE, "--input", str(SAMPLE)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["variant"] == 12
    assert report["decision"] == "other"
    assert report["rule"]["field"] == "confidentialityImpact"
    assert captured.out.count("\n") == 1
    fake_fetch.assert_not_called()


def test_missing_file_is_error(tmp_path, capsys):
    """Відсутній файл повертає код 1 і пояснення лише в stderr."""
    missing = tmp_path / "missing.json"
    assert main.main(["--cve", CVE, "--input", str(missing)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "читання" in out.err


def test_invalid_json_is_error(tmp_path, capsys):
    """Зламаний JSON не створює частковий звіт."""
    file = tmp_path / "bad.json"
    file.write_text("{invalid", encoding="utf-8")
    assert main.main(["--cve", CVE, "--input", str(file)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "JSON" in out.err


def test_invalid_structure_is_error(tmp_path, capsys):
    """Неправильна структура даних дає код 1."""
    file = tmp_path / "broken.json"
    file.write_text('{"vulnerabilities": null}', encoding="utf-8")
    assert main.main(["--cve", CVE, "--input", str(file)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "дані" in out.err


@pytest.mark.parametrize(
    "bad",
    ["cve-2099-10001", "CVE-2-1000", "CVE-2099-123", "CVE-2099-1000a"],
)
def test_cve_format_errors(bad, capsys):
    """argparse відхиляє CVE без повного збігу з шаблоном."""
    with pytest.raises(SystemExit) as error:
        main.main(["--cve", bad, "--input", str(SAMPLE)])
    assert error.value.code == 2
    assert capsys.readouterr().out == ""


def test_missing_cve_is_arg_error():
    """Параметр --cve обов'язковий навіть у локальному режимі."""
    with pytest.raises(SystemExit) as error:
        main.main(["--input", str(SAMPLE)])
    assert error.value.code == 2


@pytest.mark.parametrize("bad", [True, 0, 16, 1.5, "12"])
def test_invalid_variant_is_cli_error(monkeypatch, capsys, bad):
    """Неправильний номер варіанта обробляється кодом 2."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", bad)
    assert main.main(["--cve", CVE, "--input", str(SAMPLE)]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert "варіанта" in out.err


def test_live_mode_uses_client_and_handles_not_found(monkeypatch, capsys):
    """CLI тестує виклик клієнта без справжньої мережі."""
    fake_fetch = Mock(return_value={"vulnerabilities": []})
    monkeypatch.setattr(main.api_client, "fetch_response", fake_fetch)
    assert main.main(["--cve", CVE]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"
    fake_fetch.assert_called_once_with(CVE)


def test_client_error_is_cli_error(monkeypatch, capsys):
    """Мережева помилка повертає 1 без traceback і JSON."""
    fake = Mock(
        side_effect=main.api_client.NVDClientError("HTTP-помилка NVD: 429")
    )
    monkeypatch.setattr(main.api_client, "fetch_response", fake)
    assert main.main(["--cve", CVE]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "429" in captured.err
    assert "Traceback" not in captured.err
