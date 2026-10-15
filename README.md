# Лабораторні роботи з Python — кібербезпека

**Студент:** Чесак Віталій Володимирович  
**Група:** КБ-208  
**Варіант:** 12 · **Python:** 3.10+

Репозиторій лабораторних робіт зі скриптових мов: програмний код, тестові дані, перевірки та інструкції.

## Перелік робіт

| Лабораторна | Що реалізовано | Деталі |
| --- | --- | --- |
| **№1 — Основи Python, Git і стандарти коду** | Перевірка паролів, контроль доступу, хешування та журналювання | [ЛР №1 — код та README](labs/lab01/README.md) |
| **№2 — ООП і консольні утиліти** | Користувачі, ролі, сесії, аудит; **варіант 12:** аналіз поштових заголовків і фішингових індикаторів | [ЛР №2 — код та README](labs/lab02/README.md) |
| **№3 — FastAPI та SQLite** | REST API для обліку використання сховищ (варіант 12), Pydantic, SQLite, транзакції та 16 автоматичних тестів | [ЛР №3 — код та README](labs/lab03/README.md) |

Кожна лабораторна має **власний README**. Відкрийте посилання потрібної роботи, щоб побачити постановку завдань, файли та приклади запуску.

## Швидкий старт

Виконуйте команди з **кореня репозиторію**. Приклад для Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Для Linux/macOS активація: `source .venv/bin/activate`.

**ЛР №1**
```powershell
python -m labs.lab01.main --seed 12
```

**ЛР №2 — демонстрація ООП**
```powershell
python -m labs.lab02.main demo
```

**ЛР №2 — перевірка заголовків листів**
```powershell
python -m labs.lab02.main analyze
```

**ЛР №3 — FastAPI та SQLite**
```powershell
python -m labs.lab03.database
python -m labs.lab03.seed
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

**Тести та перевірки**
```powershell
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

> Правила Ruff визначені спільним `pyproject.toml`; перевірки слід запускати для **всього** репозиторію. У ЛР №2, запущеній окремо, конфігурація могла бути іншою.

## Структура репозиторію

```text
cybersecurity-python-labs/
├── labs/
│   ├── lab01/                 # Код ЛР №1 та README
│   ├── lab02/                 # Код ЛР №2, README і data/data_v12
│   └── lab03/                 # FastAPI, SQLite, README та seed.json
├── shared/                   # Спільні модулі
├── tests/
│   ├── test_lab01.py         # Тести ЛР №1
│   └── test_lab02.py         # Тести ЛР №2
├── pyproject.toml            # Налаштування Ruff
├── requirements.txt          # Залежності
└── README.md                 # Навігація по лабораторних
```

### Результати ЛР №2

- [Навчальні заголовки листів](labs/lab02/data/data_v12/mail_headers.log)
- [Словник підозрілих фраз](labs/lab02/data/data_v12/suspicious_keywords.txt)
- [CSV-результат](labs/lab02/data/phishing_report.csv)

**Примітка:** код створено для навчання. У ЛР №1 MD5 використано згідно з умовами завдання; для реальних паролів MD5 небезпечний. Евристична оцінка підозрілих листів у ЛР №2 не є доказом шахрайства.
