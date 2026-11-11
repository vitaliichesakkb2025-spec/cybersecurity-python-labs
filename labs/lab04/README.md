# ЛР №4 — Інтеграція із зовнішніми Web API та pytest

**Варіант 12:** відбір записів NVD за умовою
`baseScore >= 6.0 and confidentialityImpact == "LOW"`.
Це навчальний критерій для `decision="review"`, а не оцінка реального
ризику чи твердження про безпечність інших записів.

## Склад роботи

- `api_client.py` — один HTTP GET до NVD CVE API 2.0, `apiKey` із середовища,
  таймаути `(3.05, 10)`, заборона перенаправлень і обробка помилок;
- `analysis.py` — перевірка відповіді, вибір `Primary` CVSS v3.1, правило
  варіанта та формування звіту без мережевих операцій;
- `main.py` — CLI, `--cve`, `--input`, JSON-вивід, коди завершення;
- `data/nvd_sample.json` — синтетичний, **не реальний** CVE-2099-10001;
- `tests/` — pytest-тести без звернень до NVD.

## Встановлення

Відкрийте кореневу папку репозиторію в PyCharm. У терміналі з
активованим `.venv` виконайте:

```powershell
python -m pip install -r requirements.txt
```

## Локальний режим — без інтернету

```powershell
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Для варіанта 12 очікується `score=9.8`, `observed="HIGH"`,
`decision="other"`, адже умова `confidentialityImpact="LOW"` не виконана.
Успішний запуск друкує один JSON-об'єкт у `stdout`, без додаткового тексту.
Поля: `cve_id`, `variant`, `description`, `vuln_status`,
`cvss_version`, `score`, `score_source`, `vector`, `rule`,
`observed`, `decision`.
Стани: `not_found`, `rejected`, `insufficient_data`, `review`, `other`.

## Реальний NVD API (один ручний запит)

Перед запитом перегляньте правила використання NVD API. Наявність ключа
не обов'язкова. За потреби передайте ключ через змінну середовища
`NVD_API_KEY`, не додавайте його до Git.

```powershell
python -m labs.lab04.main --cve CVE-2021-44228
```

Сервіс може бути недоступним або обмежувати частоту запитів. Дані NVD
можуть змінюватися; реальний результат не закріплений у тестах.

## Тести та якість

```powershell
python -m pytest labs/lab04/tests -q
ruff check .
ruff format --check .
python -m unittest discover -s tests -v
```

Тести в `labs/lab04/tests/conftest.py` забороняють реальні мережеві запити.
Фікстури `tmp_path`, `capsys`, `monkeypatch` забезпечують ізоляцію.
Попередні лабораторні збережено.

## Коди завершення

- `0` — JSON-звіт створено (включно з `not_found`);
- `1` — помилка мережі, файла, JSON або структури даних;
- `2` — неправильний CVE, аргументи або номер варіанта.

Для захисту покажіть успішний локальний запуск і один помилковий сценарій.
