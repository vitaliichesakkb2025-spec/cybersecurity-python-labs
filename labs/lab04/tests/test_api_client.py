"""Тести HTTP-клієнта без зовнішніх запитів до NVD."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE = "CVE-2099-10001"


def response_with(payload: object, status: int = 200) -> Mock:
    """Створити контрольовану відповідь Requests без мережі."""
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.json.return_value = payload
    return response


def test_build_headers_with_and_without_key(monkeypatch):
    """Ключ зчитується під час виклику, очищується й не витікає."""
    assert api_client.build_headers() == {"Accept": "application/json"}
    monkeypatch.setenv("NVD_API_KEY", "  ")
    assert api_client.build_headers() == {"Accept": "application/json"}
    monkeypatch.setenv("NVD_API_KEY", "  example-key  ")
    assert api_client.build_headers() == {
        "Accept": "application/json", "apiKey": "example-key"
    }


def test_fetch_uses_expected_request(monkeypatch):
    """Задати один GET з cveId, таймаутом і без редиректів."""
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    fake_response = response_with(payload)
    fake_get = Mock(return_value=fake_response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert api_client.fetch_response(CVE) == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    fake_response.raise_for_status.assert_called_once_with()


def test_fetch_passes_key_as_header(monkeypatch):
    """API-ключ не повинен бути параметром URL."""
    monkeypatch.setenv("NVD_API_KEY", "  fake-secret  ")
    fake_get = Mock(return_value=response_with({"vulnerabilities": []}))
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    api_client.fetch_response(CVE)
    assert fake_get.call_args.kwargs["headers"]["apiKey"] == "fake-secret"
    assert fake_get.call_args.kwargs["params"] == {"cveId": CVE}


@pytest.mark.parametrize(
    "exception",
    [requests.exceptions.Timeout(), requests.exceptions.ConnectionError()],
)
def test_timeout_and_connection_error(monkeypatch, exception):
    """Мережевий виняток не розкривається користувачу."""
    monkeypatch.setattr(
        api_client.requests, "get", Mock(side_effect=exception)
    )
    with pytest.raises(api_client.NVDClientError):
        api_client.fetch_response(CVE)


def test_http_error(monkeypatch):
    """Реальний raise_for_status імітується через side_effect."""
    bad = response_with({}, status=429)
    bad.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "private details", response=bad
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=bad))
    with pytest.raises(api_client.NVDClientError, match="429") as error:
        api_client.fetch_response(CVE)
    assert "private" not in str(error.value)


@pytest.mark.parametrize("status", [201, 302, 304])
def test_unexpected_status_is_error(monkeypatch, status):
    """Навіть без HTTPError не приймається код, відмінний від 200."""
    fake = response_with({}, status=status)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=fake))
    with pytest.raises(api_client.NVDClientError):
        api_client.fetch_response(CVE)


def test_json_decode_error(monkeypatch):
    """200 із некоректним JSON має завершитися контрольованою помилкою."""
    fake = response_with({})
    fake.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=fake))
    with pytest.raises(api_client.NVDClientError, match="JSON"):
        api_client.fetch_response(CVE)
