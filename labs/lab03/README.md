# Лабораторна робота №3 — FastAPI та SQLite, варіант 12

[← До переліку лабораторних](../../README.md) · [Показ у PyCharm](DEMO_PYCHARM.md)

**Тема:** прикладні бібліотеки Python для побудови вебзастосунків.  
**Предметна область:** облік використання сховищ `logs`, `backups`, `archive`.  
**Одиниця:** відсотки зайнятого простору, `value` від 0 до 100.  
**Поріг:** 85% — навчальна межа уваги, а не обмеження запису у базу.  
**Варіант:** 12; дані студента беруться з `shared/student.py`.

## Склад роботи

- **Завдання 1:** `schema.sql` — готовий SQL із методички; `database.py` — підключення й створення таблиць; `seed.py` — атомарне заповнення; `repository.py` — параметризовані SQL-запити.
- **Завдання 2:** `schemas.py` — Pydantic-моделі; `main.py` — FastAPI та обробники помилок; `routers/` — HTTP-маршрути.
- **Завдання 3:** `tests/test_lab03.py` — перевірки 14 сценаріїв методички та 2 додаткових.

## Запуск у PyCharm

Виконуйте з **кореня репозиторію** в активованому середовищі Python 3.10+:

```powershell
python -m pip install -r requirements.txt
python -m labs.lab03.database
python -m labs.lab03.seed
python -m labs.lab03.seed
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Другий запуск `seed` повинен повідомити, що база вже заповнена, без дублікатів.

Після старту сервера відкрийте:

- [Swagger UI](http://127.0.0.1:8000/docs) — перевіряйте маршрути через **Try it out**
- [OpenAPI](http://127.0.0.1:8000/openapi.json)
- [GET /ping](http://127.0.0.1:8000/ping)
- [GET /student](http://127.0.0.1:8000/student)
- [GET /categories](http://127.0.0.1:8000/categories)
- [GET /records](http://127.0.0.1:8000/records)

Для зупинки сервера натисніть `Ctrl+C` у терміналі.

## Основні маршрути

| Метод | URL | Успіх |
| --- | --- | --- |
| GET | `/ping` | 200, `{"status":"ok"}` |
| GET | `/student` | 200, ПІБ, група, варіант |
| GET | `/categories` | 200, список категорій |
| POST | `/categories` | 201, нова категорія |
| DELETE | `/categories/{category_id}` | 204, лише порожня категорія |
| GET | `/records` | 200, список із фільтрами |
| GET | `/records/{record_id}` | 200, один запис |
| POST | `/records` | 201, новий запис |
| PUT | `/records/{record_id}` | 200, повна заміна змінюваних полів |
| DELETE | `/records/{record_id}` | 204, без тіла |
| POST | `/records/bulk` | 201, атомарне пакетне створення |

Параметри `GET /records`: `category_id`, `status`, `min_value`, `q`, `limit` (1–100, типово 20), `offset` (від 0). Фільтри поєднуються через **AND**; `q` шукає **буквальний підрядок з урахуванням регістру**, через `instr(title, ?)`.

## Приклади для Swagger UI

Створення категорії — `POST /categories`:

```json
{"name":"temporary_store"}
```

Створення запису — `POST /records`:

```json
{
  "code": "V12-TEST",
  "title": "Вимірювання сховища тест",
  "category_id": 1,
  "value": 91.5,
  "status": "new"
}
```

Очікується **201 Created**, з `id` та `category_name: "logs"`. Для PUT передайте всі п’ять змінюваних полів без `id`.

Приклади фільтрів:

```text
/records?category_id=1&status=new&limit=5&offset=0
/records?min_value=85
/records?q=сховища
/records?q=%27%20OR%201%3D1%20--
```

Перша комбінація повертає `V12-01` і `V12-04` на початковій базі.

Коректний пакет — `POST /records/bulk`:

```json
[
  {"code":"V12-BULK-1","title":"Вимірювання сховища 21","category_id":1,"value":85,"status":"new"},
  {"code":"V12-BULK-2","title":"Вимірювання сховища 22","category_id":2,"value":99,"status":"done"}
]
```

Тест відкату, якщо `V12-01` уже існує:

```json
[
  {"code":"V12-ROLLBACK","title":"Вимірювання сховища 23","category_id":1,"value":75,"status":"new"},
  {"code":"V12-01","title":"Вимірювання сховища 24","category_id":2,"value":60,"status":"new"}
]
```

Очікується **409 Conflict**: `V12-ROLLBACK` теж не зберігається. Якщо другий елемент має неіснуючу категорію, відповідь **404** і жоден елемент пакета не записується. Порожній `title`, від’ємне `value`, значення понад 100, зайве поле, хибний статус — **422**.

## Реалізація та підготовка до захисту

- В SQLite є `categories(id, name)` і `records(id, code, title, category_id, value, status)`, зв’язок **один до багатьох**.
- `PRAGMA foreign_keys = ON` виконується для кожного з’єднання.
- SQL із параметрами `?` розташований у `repository.py` й не складається з введених користувачем значень.
- `with connection` підтверджує/скасовує транзакцію, `closing()` закриває з’єднання.
- Усі вставки `POST /records/bulk` виконуються в **одній транзакції**.
- База `labs/lab03/data/lab3.sqlite3` генерується локально й не потрапляє до Git. Початкові дані `data/seed.json`, код та готову `schema.sql` треба зберігати в Git.
- Помилки API: **404** — ресурс відсутній; **409** — конфлікт; **422** — порушення моделі; **500** — неочікувана помилка SQLite без витоку технічних деталей.

Для повторного показу чистої бази **зупиніть сервер**, видаліть лише `labs/lab03/data/lab3.sqlite3`, тоді виконайте `python -m labs.lab03.database` і `python -m labs.lab03.seed`. Не видаляйте `schema.sql` і `seed.json`.

**Порада:** короткі пояснення для захисту наведено у [DEMO_PYCHARM.md](DEMO_PYCHARM.md).
