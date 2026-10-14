# Лабораторна робота №2 — варіант 12

[← Усі лабораторні](../../README.md) · [Як показати роботу в PyCharm](DEMO_PYCHARM.md)

**Студент:** Чесак Віталій Володимирович · **Група:** КБ-208

**Тема:** розробка консольних утиліт для задач кібербезпеки.  
**Завдання 1:** класи `User`, `Admin`, `Session`, `AuditEntry`, `AuditLog`, `UserAccount`; команда `demo`.  
**Завдання 2:** аналізатор поштових заголовків і фішингових індикаторів; команда `analyze`.

## Вхідні та вихідні дані

- `data/data_v12/mail_headers.log`: шість навчальних листів, поля `From`, `Return-Path`, `Reply-To`, `Received`, `Subject`.
- `data/data_v12/suspicious_keywords.txt`: список пошукових фраз.
- `data/phishing_report.csv`: сформований програмою CSV-звіт (вихідні дані).

## Запуск із кореня репозиторію

Потрібен Python 3.10 або новіший. Виконуйте команди з головної папки `cybersecurity-python-labs`.

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

## Результати для навчального набору

| Повідомлення | Бал ризику | Категорія |
| --- | ---: | --- |
| 001 | 0/100 | LOW |
| 002 | 80/100 | CRITICAL |
| 003 | 0/100 | LOW |
| 004 | 100/100 | CRITICAL |
| 005 | 0/100 | LOW |
| 006 | 80/100 | CRITICAL |

Програма нараховує до 100 балів: +30 за різницю доменів `From` та `Return-Path`, +30 — `From` і `Reply-To`, до +20 — за підозрілі фрази в темі, +20 — за щонайменше 4 рядки `Received`. Рівні: LOW (0–24), MEDIUM (25–49), HIGH (50–74), CRITICAL (75–100).

**Примітка:** правила оцінювання демонстраційні, тому результат не є автоматичним доказом фішингу.

Для звіту потрібні посилання на GitHub і хеш коміту. Перевірки Ruff для об'єднаного репозиторію використовують спільні правила з кореневого `pyproject.toml`.
