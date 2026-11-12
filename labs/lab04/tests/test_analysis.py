"""Перевірки структури NVD, оцінок CVSS і правила варіанта 12."""

import copy
import json
from pathlib import Path

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE = "CVE-2099-10001"
SAMPLE = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture
def payload() -> dict:
    """Повертати незалежну копію синтетичної відповіді."""
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def cve_data(payload: dict) -> dict:
    """Знайти словник єдиного CVE."""
    return payload["vulnerabilities"][0]["cve"]


def cvss_data(payload: dict) -> dict:
    """Знайти навчальну оцінку CVSS v3.1."""
    return cve_data(payload)["metrics"]["cvssMetricV31"][0]["cvssData"]


def report(payload: dict) -> dict:
    """Виконати справжній аналіз варіанта 12."""
    return build_report(extract_record(payload, CVE), CVE, 12)


def test_original_fixture_is_other(payload):
    """9.8 з HIGH не відповідає правилу LOW попри високий бал."""
    result = report(payload)
    assert result["decision"] == "other"
    assert result["score"] == 9.8
    assert result["observed"] == "HIGH"
    assert result["rule"] == {
        "threshold": 6.0,
        "field": "confidentialityImpact",
        "expected": "LOW",
    }
    assert list(result) == [
        "cve_id",
        "variant",
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "rule",
        "observed",
        "decision",
    ]


@pytest.mark.parametrize(
    "score, impact, decision",
    [
        (5.9, "LOW", "other"),
        (6.0, "LOW", "review"),
        (6.1, "LOW", "review"),
        (9.8, "HIGH", "other"),
    ],
)
def test_threshold_and_feature(payload, score, impact, decision):
    """Випадки до, на та після порога, з правильною і хибною ознакою."""
    cvss_data(payload)["baseScore"] = score
    cvss_data(payload)["confidentialityImpact"] = impact
    assert report(payload)["decision"] == decision


def test_missing_cve_has_null_fields(payload):
    """Порожній результат пошуку не дорівнює HTTP-помилці."""
    payload["vulnerabilities"] = []
    result = report(payload)
    assert result["decision"] == "not_found"
    assert result["rule"]["expected"] == "LOW"
    assert all(
        result[field] is None
        for field in ("description", "vuln_status", "score", "observed")
    )


def test_rejected_takes_priority(payload):
    """Rejected не використовує навіть наявну оцінку CVSS."""
    cve_data(payload)["vulnStatus"] = "Rejected"
    result = report(payload)
    assert result["decision"] == "rejected"
    assert result["score"] is None
    assert result["observed"] is None
    assert result["description"] is not None


def test_missing_status_ignores_metrics(payload):
    """За відсутнього статусу рішення insufficient_data."""
    del cve_data(payload)["vulnStatus"]
    assert report(payload)["decision"] == "insufficient_data"
    assert report(payload)["score"] is None


@pytest.mark.parametrize(
    "location", ["metrics", "cvssMetricV31", "score_field"]
)
def test_absent_scoring_data(payload, location):
    """Відсутній блок оцінки або поле варіанта дає брак даних."""
    if location == "metrics":
        del cve_data(payload)["metrics"]
    elif location == "cvssMetricV31":
        del cve_data(payload)["metrics"]["cvssMetricV31"]
    else:
        del cvss_data(payload)["confidentialityImpact"]
    assert report(payload)["decision"] == "insufficient_data"


@pytest.mark.parametrize("bad", [None, 3, True, "", "INVALID", "low"])
def test_bad_variant_field_is_error(payload, bad):
    """Присутнє хибне поле конфіденційності не можна ігнорувати."""
    cvss_data(payload)["confidentialityImpact"] = bad
    with pytest.raises(ValueError):
        report(payload)


@pytest.mark.parametrize(
    "bad", [True, False, "9.8", -0.1, 10.1, float("nan"), float("inf")]
)
def test_bad_score_is_error(payload, bad):
    """Заборонені bool, текст, NaN, нескінченність і вихід за межі."""
    cvss_data(payload)["baseScore"] = bad
    with pytest.raises(ValueError):
        report(payload)


@pytest.mark.parametrize(
    "bad", [None, [], "not a mapping", {"vulnerabilities": None}]
)
def test_bad_payload_structure(bad):
    """Зовнішня відповідь має містити коректний список vulnerabilities."""
    with pytest.raises(ValueError):
        extract_record(bad, CVE)


def test_multiple_records_are_error(payload):
    """Точний CVE-пошук не має повертати два записи."""
    payload["vulnerabilities"].append(
        copy.deepcopy(payload["vulnerabilities"][0])
    )
    with pytest.raises(ValueError):
        report(payload)


def test_different_record_id_is_error(payload):
    """Ідентифікатор знайденого CVE повинен точно збігатися."""
    cve_data(payload)["id"] = "CVE-2000-0000"
    with pytest.raises(ValueError):
        report(payload)


@pytest.mark.parametrize("bad", [None, "bad", []])
def test_present_bad_metrics_is_error(payload, bad):
    """Відсутність metrics та некоректний тип — різні ситуації."""
    cve_data(payload)["metrics"] = bad
    with pytest.raises(ValueError):
        report(payload)


@pytest.mark.parametrize("bad", [None, "bad", {}])
def test_present_bad_v31_list_is_error(payload, bad):
    """Наявний cvssMetricV31 мусить бути списком."""
    cve_data(payload)["metrics"]["cvssMetricV31"] = bad
    with pytest.raises(ValueError):
        report(payload)


def test_empty_v31_list_is_insufficient(payload):
    """Порожній список оцінок — брак даних."""
    cve_data(payload)["metrics"]["cvssMetricV31"] = []
    assert report(payload)["decision"] == "insufficient_data"


def test_primary_beats_earlier_secondary(payload):
    """Primary обирається навіть якщо Secondary стоїть раніше."""
    scores = cve_data(payload)["metrics"]["cvssMetricV31"]
    primary = scores[0]
    primary["cvssData"]["confidentialityImpact"] = "LOW"
    secondary = copy.deepcopy(primary)
    secondary["type"] = "Secondary"
    secondary["cvssData"]["baseScore"] = 1.0
    scores.insert(0, secondary)
    result = report(payload)
    assert result["score"] == 9.8
    assert result["decision"] == "review"


def test_first_score_used_without_primary(payload):
    """За відсутності Primary вибирається перша оцінка."""
    scores = cve_data(payload)["metrics"]["cvssMetricV31"]
    scores[0]["type"] = "Secondary"
    scores[0]["cvssData"]["baseScore"] = 5.9
    scores[0]["cvssData"]["confidentialityImpact"] = "LOW"
    second = copy.deepcopy(scores[0])
    second["cvssData"]["baseScore"] = 9.8
    scores.append(second)
    assert report(payload)["score"] == 5.9
    assert report(payload)["decision"] == "other"


def test_analysis_does_not_mutate_input(payload):
    """Аналіз не змінює вихідний словник."""
    original = copy.deepcopy(payload)
    report(payload)
    assert payload == original


def test_first_english_description_is_chosen(payload):
    """Обирається перший непорожній опис англійською."""
    cve_data(payload)["descriptions"] = [
        {"lang": "uk", "value": "Тест"},
        {"lang": "en", "value": ""},
        {"lang": "en", "value": "English description"},
        {"lang": "en", "value": "Another"},
    ]
    assert report(payload)["description"] == "English description"


@pytest.mark.parametrize(
    "field, value", [("version", "3.0"), ("vectorString", None)]
)
def test_bad_optional_scoring_metadata(payload, field, value):
    """Присутнє неправильне поле версії або вектора є помилкою."""
    cvss_data(payload)[field] = value
    with pytest.raises(ValueError):
        report(payload)


@pytest.mark.parametrize("variant", [True, 0, 16, 1.5, "12"])
def test_invalid_variant_is_error(variant):
    """Приймаються лише цілі варіанти в межах 1–15."""
    with pytest.raises(ValueError):
        build_report(None, CVE, variant)
