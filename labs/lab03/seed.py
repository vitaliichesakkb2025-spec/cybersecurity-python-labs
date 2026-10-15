"""Перевірка seed.json та атомарне початкове заповнення SQLite."""

import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03 import database
from labs.lab03.schemas import RecordCreate

LOG = logging.getLogger(__name__)
SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


class InitialCategory(BaseModel):
    """Категорія початкового набору із заданим ID."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: int = Field(gt=0)
    name: str = Field(min_length=2, max_length=40)


class InitialData(BaseModel):
    """Початковий набір із трьох категорій та восьми записів."""

    model_config = ConfigDict(extra="forbid")
    categories: list[InitialCategory] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)


def load_seed(path: Path = SEED_PATH) -> InitialData:
    """Прочитати JSON і перевірити його структуру через Pydantic."""
    try:
        raw_data = json.loads(path.read_text(encoding="utf-8"))
        return InitialData.model_validate(raw_data)
    except (OSError, ValueError) as exc:
        raise ValueError("Некоректний файл початкових даних") from exc


def seed_database(path: Path = SEED_PATH) -> bool:
    """Записати весь набір разом або скасувати всі його зміни."""
    data = load_seed(path)
    database.initialize_database()
    with closing(database.get_connection()) as connection:
        try:
            with connection:
                categories_count = connection.execute(
                    "SELECT COUNT(*) FROM categories"
                ).fetchone()[0]
                records_count = connection.execute(
                    "SELECT COUNT(*) FROM records"
                ).fetchone()[0]
                if categories_count or records_count:
                    print("База вже заповнена; повторне додавання пропущено.")
                    return False
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(row.id, row.name) for row in data.categories],
                )
                connection.executemany(
                    """INSERT INTO records
                    (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)""",
                    [
                        (
                            row.code,
                            row.title,
                            row.category_id,
                            row.value,
                            row.status,
                        )
                        for row in data.records
                    ],
                )
        except sqlite3.IntegrityError as exc:
            LOG.warning("Початкове заповнення скасовано: %s", exc)
            raise ValueError(
                "Обмеження бази порушено; увесь набір скасовано"
            ) from exc
    print("Початкові дані додані: 3 категорії, 8 записів.")
    return True


def main() -> int:
    """Запустити початкове заповнення як консольну команду."""
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s"
    )
    try:
        seed_database()
    except (ValueError, sqlite3.Error) as exc:
        LOG.error("Не вдалося заповнити базу: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
