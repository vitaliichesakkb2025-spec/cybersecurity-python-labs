# Лабораторна робота №2 — варіант 12

**Тема:** розробка консольних утиліт для задач кібербезпеки.  
**Завдання 1:** класи `User`, `Admin`, `Session`, `AuditEntry`, `AuditLog`, `UserAccount`; команда `demo`.  
**Завдання 2:** аналізатор поштових заголовків і фішингових індикаторів; команда `analyze`.

## Вхідні дані з архіву лабораторної

- `data/data_v12/mail_headers.log`: шість навчальних листів, поля `From`, `Return-Path`, `Reply-To`, `Received`, `Subject`.
- `data/data_v12/suspicious_keywords.txt`: список пошукових фраз.
- `data/phishing_report.csv`: сформований програмою CSV-звіт (вихідні дані).

## Запуск із кореня репозиторію

```powershell
python -m pip install -r requirements.txt
python -m labs.lab02.main demo
python -m labs.lab02.main analyze
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

Користувацькі параметри CLI:

```powershell
python -m labs.lab02.main analyze --mail-log labs/lab02/data/data_v12/mail_headers.log --suspicious-keywords labs/lab02/data/data_v12/suspicious_keywords.txt --out-csv labs/lab02/data/phishing_report.csv --debug
```

- `--mail-log`: дамп поштових заголовків; типовий файл вище.
- `--suspicious-keywords`: словник підозрілих фраз; типовий файл вище.
- `--out-csv`: шлях для результату; типовий `data/phishing_report.csv`.
- `--debug`: увімкнути детальне журналювання.

У разі недоступного файлу або некоректного введення програма виводить `[ERROR]`, повертає код 2; `argparse` показує помилки невідомих ключів чи параметрів. Результат — ризик за навчальною шкалою, а не доказ шахрайства.

Приклади з навчального набору: 6 листів перевірено; 001, 003, 005 — LOW; 002, 004, 006 — CRITICAL. Перед здачею додай до звіту URL Git-репозиторію та хеш коміту.
