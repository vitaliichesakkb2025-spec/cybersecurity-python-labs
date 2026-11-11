"""Чиста перевірка відповіді NVD і правила всіх 15 варіантів."""

import math
from typing import Any

RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}
ALLOWED: dict[str, frozenset[str]] = {
    "attackVector": frozenset(
        {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}
    ),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}


def _optional_text(mapping: dict[str, Any], key: str) -> str | None:
    """Прийняти відсутнє поле, але відхилити наявний хибний тип."""
    if key not in mapping:
        return None
    value = mapping[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Некоректне текстове поле: {key}")
    return value


def _description(cve: dict[str, Any]) -> str | None:
    """Взяти перший непорожній англомовний опис із валідного списку."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise ValueError("descriptions має бути списком")
    english = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise ValueError("Елемент descriptions має бути об'єктом")
        if not isinstance(item.get("lang"), str):
            raise ValueError("Некоректний descriptions.lang")
        if not isinstance(item.get("value"), str):
            raise ValueError("Некоректний descriptions.value")
        if item["lang"] == "en" and item["value"].strip() and english is None:
            english = item["value"]
    return english


def _chosen_score(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибрати першу Primary-оцінку CVSS v3.1, інакше першу."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    scores = metrics["cvssMetricV31"]
    if not isinstance(scores, list):
        raise ValueError("cvssMetricV31 має бути списком")
    if not scores:
        return None
    if any(not isinstance(item, dict) for item in scores):
        raise ValueError("Кожна оцінка CVSS має бути об'єктом")
    chosen = next(
        (item for item in scores if item.get("type") == "Primary"),
        scores[0],
    )
    data = chosen.get("cvssData")
    if not isinstance(data, dict):
        raise ValueError("cvssData має бути об'єктом")
    score = data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise ValueError("baseScore має бути числом від 0 до 10")
    version = _optional_text(data, "version")
    if version is not None and version != "3.1":
        raise ValueError("Очікується CVSS версії 3.1")
    return {
        "score": score,
        "source": _optional_text(chosen, "source"),
        "version": version,
        "vector": _optional_text(data, "vectorString"),
        "data": data,
    }


def extract_record(payload: object, cve_id: str) -> dict[str, Any] | None:
    """Перевірити відповідь, не змінюючи її; повернути нормалізований запис.

    Формат: dict із vuln_status, description і cvss (словник чи None).
    Якщо vulnerabilities порожній, результатом буде None.
    """
    if not isinstance(payload, dict):
        raise ValueError("Відповідь NVD має бути об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 1:
        raise ValueError("vulnerabilities має містити 0 або 1 елемент")
    if not vulnerabilities:
        return None
    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("Відсутній об'єкт cve")
    cve = item["cve"]
    if not isinstance(cve.get("id"), str) or cve["id"] != cve_id:
        raise ValueError("Невідповідний cve.id")
    status = _optional_text(cve, "vulnStatus")
    description = _description(cve)
    cvss = None
    if status is not None and status != "Rejected":
        cvss = _chosen_score(cve)
    return {
        "vuln_status": status,
        "description": description,
        "cvss": cvss,
    }


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Сформувати звіт за правилом variant без читання чи запису даних."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in RULES
    ):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15")
    threshold, field, expected = RULES[variant]
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {
            "threshold": threshold,
            "field": field,
            "expected": expected,
        },
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    report["decision"] = "insufficient_data"
    if record["vuln_status"] is None or record["cvss"] is None:
        return report
    selected = record["cvss"]
    report["cvss_version"] = selected["version"]
    report["score"] = selected["score"]
    report["score_source"] = selected["source"]
    report["vector"] = selected["vector"]
    data = selected["data"]
    if field not in data:
        return report
    observed = data[field]
    if not isinstance(observed, str) or observed not in ALLOWED[field]:
        raise ValueError(f"Некоректне значення поля: {field}")
    report["observed"] = observed
    report["decision"] = (
        "review"
        if selected["score"] >= threshold and observed == expected
        else "other"
    )
    return report
