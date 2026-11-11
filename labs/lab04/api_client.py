"""Безпечне отримання однієї відповіді NVD CVE API 2.0."""

import os

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = (3.05, 10)


class NVDClientError(RuntimeError):
    """Помилка отримання або декодування відповіді NVD."""


def build_headers() -> dict[str, str]:
    """Додати ключ із середовища лише за непорожнього значення."""
    headers = {"Accept": "application/json"}
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    return headers


def fetch_response(cve_id: str) -> object:
    """Виконати один GET-запит із TLS, таймаутами та без редиректів."""
    try:
        response = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except requests.exceptions.Timeout as exc:
        raise NVDClientError("Таймаут запиту до NVD") from exc
    except requests.exceptions.ConnectionError as exc:
        raise NVDClientError("Немає з'єднання з NVD") from exc
    except requests.exceptions.RequestException as exc:
        raise NVDClientError("Мережева помилка NVD") from exc

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        raise NVDClientError(
            f"HTTP-помилка NVD: {response.status_code}"
        ) from exc

    if response.status_code != 200:
        raise NVDClientError(
            f"Неочікуваний HTTP-статус: {response.status_code}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise NVDClientError("NVD повернула некоректний JSON") from exc
