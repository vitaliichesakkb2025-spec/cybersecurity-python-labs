# Шпаргалка для демонстрації ЛР №3 у PyCharm

[← Інструкція лабораторної](README.md)

1. **Що робить програма?** REST API для обліку використання сховищ за варіантом 12. Значення `value` — відсотки зайнятого місця (0–100), поріг уваги — 85%, категорії: `logs`, `backups`, `archive`.
2. **Які таблиці?** `categories(id, name)` і `records(id, code, title, category_id, value, status)`. `category_id` — зовнішній ключ, зв’язок один до багатьох.
3. **Де SQL?** Запити — в `repository.py`, схема таблиць з методички — в `schema.sql`, запуск схеми — в `database.py`.
4. **Як захиститися від SQL-ін’єкцій?** Передавати користувацькі значення через параметри `?`, а не вставляти їх у текст SQL.
5. **Навіщо FastAPI?** HTTP-маршрути, коди відповіді та документація Swagger `/docs`.
6. **Навіщо Pydantic?** Перевіряє типи, довжини, дозволені статуси, межі 0–100, зайві поля. Некоректні дані → 422.
7. **POST і PUT?** POST створює запис, PUT повністю замінює змінювані поля існуючого, але не його ID.
8. **Навіщо транзакція?** Пакет зберігається повністю або скасовується. Якщо другий `code` повторюється, перший запис теж не залишається.
9. **Навіщо `closing()`?** `with connection` робить commit/rollback, але з’єднання сам не закриває.
10. **Що йде на GitHub?** Код, SQL, `seed.json`, README і тести; не файл SQLite і не `.venv`.

## Запуск із термінала PyCharm

```powershell
python -m labs.lab03.database
python -m labs.lab03.seed
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Коли Uvicorn запущений, відкрийте в браузері **http://127.0.0.1:8000/docs**. У Swagger покажіть `GET /ping`, `GET /student`, `GET /records`, створення, оновлення й видалення запису, некоректне `value: 101` (422) та відкат пакета (409).

**Зелена кнопка PyCharm:** Run → Edit Configurations → Python; Module name: `uvicorn`, Parameters: `labs.lab03.main:app --reload --host 127.0.0.1 --port 8000`, Working directory — корінь `cybersecurity-python-labs`.
