"""Автоматичне ізолювання тестів від мережі та справжніх ключів."""

import pytest

from labs.lab04 import api_client


@pytest.fixture(autouse=True)
def isolated_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Видалити ключ і заборонити справжні Requests-запити."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(api_client, "ENV_FILE", tmp_path / ".env")
    monkeypatch.delattr("requests.sessions.Session.request")
