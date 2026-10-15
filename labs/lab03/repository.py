"""Ізольований шар доступу до SQLite з параметризованими запитами."""

import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection
from labs.lab03.schemas import RecordCreate, RecordReplace

RECORD_COLUMNS = (
    "r.id, r.code, r.title, r.category_id, r.value, r.status, "
    "c.name AS category_name"
)
RECORD_JOIN = " FROM records AS r JOIN categories AS c ON c.id = r.category_id"


class NotFoundError(Exception):
    """Запитаний запис або категорія відсутні."""


class ConflictError(Exception):
    """Дані суперечать унікальності або наявним зв'язкам."""


def list_categories() -> list[dict[str, Any]]:
    """Отримати всі категорії за ID у зростаючому порядку."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id ASC"
        ).fetchall()
        return [dict(row) for row in rows]


def create_category(name: str) -> dict[str, Any]:
    """Створити категорію, повернувши її автоматичний ID."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                result = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
                return {"id": result.lastrowid, "name": name}
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Категорія з такою назвою вже існує") from exc


def delete_category(category_id: int) -> None:
    """Видалити лише порожню категорію; інакше повернути конфлікт."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                found = connection.execute(
                    "SELECT id FROM categories WHERE id = ?", (category_id,)
                ).fetchone()
                if found is None:
                    raise NotFoundError("Категорію не знайдено")
                count = connection.execute(
                    "SELECT COUNT(*) FROM records WHERE category_id = ?",
                    (category_id,),
                ).fetchone()[0]
                if count:
                    raise ConflictError("Категорія містить записи")
                connection.execute(
                    "DELETE FROM categories WHERE id = ?", (category_id,)
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Категорія містить записи") from exc


def _require_category(
    connection: sqlite3.Connection, category_id: int
) -> None:
    """Перевірити зовнішній ключ до вставлення або оновлення."""
    row = connection.execute(
        "SELECT id FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError("Категорію не знайдено")


def _get_record(
    connection: sqlite3.Connection, record_id: int
) -> dict[str, Any]:
    """Прочитати запис із назвою категорії або повернути 404-помилку."""
    row = connection.execute(
        "SELECT " + RECORD_COLUMNS + RECORD_JOIN + " WHERE r.id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("Запис не знайдено")
    return dict(row)


def get_record(record_id: int) -> dict[str, Any]:
    """Отримати вимірювання за його ID."""
    with closing(get_connection()) as connection:
        return _get_record(connection, record_id)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Фільтрувати вимірювання через AND та пагінацію за ID."""
    where: list[str] = []
    parameters: list[Any] = []
    if category_id is not None:
        where.append("r.category_id = ?")
        parameters.append(category_id)
    if status is not None:
        where.append("r.status = ?")
        parameters.append(status)
    if min_value is not None:
        where.append("r.value >= ?")
        parameters.append(min_value)
    if q is not None:
        where.append("instr(r.title, ?) > 0")
        parameters.append(q)
    query = "SELECT " + RECORD_COLUMNS + RECORD_JOIN
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    parameters.extend((limit, offset))
    with closing(get_connection()) as connection:
        rows = connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]


def _insert_record(
    connection: sqlite3.Connection, data: RecordCreate
) -> dict[str, Any]:
    """Додати вимірювання у вже відкритій транзакції."""
    _require_category(connection, data.category_id)
    cursor = connection.execute(
        """INSERT INTO records (code, title, category_id, value, status)
           VALUES (?, ?, ?, ?, ?)""",
        (
            data.code,
            data.title,
            data.category_id,
            data.value,
            data.status,
        ),
    )
    return _get_record(connection, cursor.lastrowid)


def create_record(data: RecordCreate) -> dict[str, Any]:
    """Додати запис, перевіряючи його категорію та унікальність коду."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                return _insert_record(connection, data)
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "Код запису вже існує або дані некоректні"
            ) from exc


def replace_record(
    record_id: int, data: RecordReplace
) -> dict[str, Any]:
    """Повністю замінити змінювані поля без заміни ID."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                existing = connection.execute(
                    "SELECT id FROM records WHERE id = ?", (record_id,)
                ).fetchone()
                if existing is None:
                    raise NotFoundError("Запис не знайдено")
                _require_category(connection, data.category_id)
                connection.execute(
                    """UPDATE records
                    SET code = ?, title = ?, category_id = ?,
                        value = ?, status = ?
                    WHERE id = ?""",
                    (
                        data.code,
                        data.title,
                        data.category_id,
                        data.value,
                        data.status,
                        record_id,
                    ),
                )
                return _get_record(connection, record_id)
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "Код запису вже існує або дані некоректні"
            ) from exc


def delete_record(record_id: int) -> None:
    """Видалити конкретне вимірювання або повідомити про відсутність."""
    with closing(get_connection()) as connection:
        with connection:
            result = connection.execute(
                "DELETE FROM records WHERE id = ?", (record_id,)
            )
            if result.rowcount == 0:
                raise NotFoundError("Запис не знайдено")


def create_records_bulk(
    records: list[RecordCreate],
) -> list[dict[str, Any]]:
    """Додати весь пакет атомарно або скасувати його цілком."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                return [_insert_record(connection, row) for row in records]
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "Дубль коду або порушення обмежень пакета"
            ) from exc
