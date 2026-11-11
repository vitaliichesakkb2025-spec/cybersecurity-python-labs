"""Автоматичне ізолювання тестів від мережі та справжніх ключів."""

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Видалити ключ і заборонити справжні Requests-запити."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")
