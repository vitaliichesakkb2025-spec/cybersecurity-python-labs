"""Ізольовані перевірки ЛР №3: API, обмеження та транзакції."""

import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from labs.lab03 import database, seed
from labs.lab03.main import app


class Lab03Tests(unittest.TestCase):
    """Перевірити всі 14 сценаріїв методички без зміни робочої бази."""

    def setUp(self) -> None:
        """Створити ізольований файл SQLite для кожного тесту."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database_patch = patch.object(
            database,
            "DATABASE_PATH",
            Path(temporary.name) / "test.sqlite3",
        )
        database_patch.start()
        self.addCleanup(database_patch.stop)
        self.client = TestClient(app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        seed.seed_database()

    @staticmethod
    def record(code: str, category_id: int = 1) -> dict:
        """Повернути валідний шаблон вимірювання для API."""
        return {
            "code": code,
            "title": "Вимірювання сховища 20",
            "category_id": category_id,
            "value": 91.5,
            "status": "new",
        }

    def count(self) -> int:
        """Отримати точну кількість записів без ліміту пагінації."""
        with closing(database.get_connection()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM records"
            ).fetchone()[0]

    def test_01_seed_and_repeat(self) -> None:
        """Початковий набір містить 3 категорії та 8 записів."""
        self.assertEqual(len(self.client.get("/categories").json()), 3)
        self.assertEqual(self.count(), 8)
        self.assertFalse(seed.seed_database())
        self.assertEqual(self.count(), 8)

    def test_02_ping_student_categories(self) -> None:
        """Службові маршрути мають правильні HTTP-коди та дані."""
        self.assertEqual(self.client.get("/ping").json(), {"status": "ok"})
        response = self.client.get("/student")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["variant_number"], 12)
        self.assertEqual(response.json()["group_name"], "КБ-208")
        names = [c["name"] for c in self.client.get("/categories").json()]
        self.assertEqual(names, ["logs", "backups", "archive"])

    def test_03_record_crud(self) -> None:
        """POST, GET, PUT, DELETE утворюють повний цикл CRUD."""
        created = self.client.post("/records", json=self.record("V12-CRUD"))
        self.assertEqual(created.status_code, 201)
        record_id = created.json()["id"]
        self.assertEqual(created.json()["category_name"], "logs")
        self.assertEqual(
            self.client.get(f"/records/{record_id}").status_code, 200
        )
        replacement = self.record("V12-CHANGED", category_id=2)
        updated = self.client.put(
            f"/records/{record_id}", json=replacement
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["category_name"], "backups")
        self.assertEqual(updated.json()["id"], record_id)
        removed = self.client.delete(f"/records/{record_id}")
        self.assertEqual(removed.status_code, 204)
        self.assertEqual(removed.content, b"")
        self.assertEqual(
            self.client.get(f"/records/{record_id}").status_code, 404
        )

    def test_04_filter_and_pagination(self) -> None:
        """Фільтри поєднуються AND і сторінки стабільні за ID."""
        first = self.client.get(
            "/records", params={"category_id": 1, "status": "new"}
        )
        self.assertEqual(
            [r["code"] for r in first.json()], ["V12-01", "V12-04"]
        )
        min_filtered = self.client.get(
            "/records", params={"min_value": 90}
        )
        self.assertEqual(
            [r["code"] for r in min_filtered.json()],
            ["V12-01", "V12-04"],
        )
        page = self.client.get(
            "/records", params={"limit": 2, "offset": 2}
        )
        self.assertEqual([r["id"] for r in page.json()], [3, 4])
        self.assertEqual(
            self.client.get(
                "/records", params={"category_id": 99}
            ).json(),
            [],
        )
        self.assertEqual(
            len(self.client.get("/records", params={"q": "сховища"}).json()),
            8,
        )
        self.assertEqual(
            self.client.get("/records", params={"q": "СХОВИЩА"}).json(),
            [],
        )

    def test_05_invalid_fields_422(self) -> None:
        """Некоректні поля повертають 422 без запису в базу."""
        original = self.count()
        for field, value in [
            ("value", -1.0),
            ("title", "  "),
            ("status", "pending"),
        ]:
            with self.subTest(field=field):
                payload = self.record("V12-INVALID")
                payload[field] = value
                self.assertEqual(
                    self.client.post("/records", json=payload).status_code,
                    422,
                )
        self.assertEqual(
            self.client.get("/records", params={"limit": 0}).status_code,
            422,
        )
        self.assertEqual(self.count(), original)

    def test_06_value_above_max_422(self) -> None:
        """Value понад 100% і нескінченність відхиляються."""
        data = self.record("V12-OUTRANGE")
        data["value"] = 100.1
        self.assertEqual(
            self.client.post("/records", json=data).status_code, 422
        )
        self.assertEqual(
            self.client.get("/records", params={"min_value": 101}).status_code,
            422,
        )

    def test_07_missing_record_and_category_404(self) -> None:
        """Відсутні ID і посилання на категорії повертають 404."""
        self.assertEqual(self.client.get("/records/999").status_code, 404)
        self.assertEqual(
            self.client.post(
                "/records", json=self.record("V12-NOCAT", 999)
            ).status_code,
            404,
        )
        self.assertEqual(self.client.put(
            "/records/1", json=self.record("V12-NOCAT", 999)
        ).status_code, 404)

    def test_08_duplicate_code_and_category_409(self) -> None:
        """Не дозволяти повторні code або назву категорії."""
        self.assertEqual(self.client.post(
            "/records", json=self.record("V12-01")
        ).status_code, 409)
        self.assertEqual(self.client.post(
            "/categories", json={"name": "logs"}
        ).status_code, 409)
        self.assertEqual(self.count(), 8)

    def test_09_delete_categories(self) -> None:
        """Непорожня категорія дає 409, порожня — 204."""
        self.assertEqual(self.client.delete("/categories/1").status_code, 409)
        created = self.client.post(
            "/categories", json={"name": "temp_store"}
        )
        self.assertEqual(created.status_code, 201)
        result = self.client.delete(
            f"/categories/{created.json()['id']}"
        )
        self.assertEqual(result.status_code, 204)
        self.assertEqual(result.content, b"")

    def test_10_valid_bulk(self) -> None:
        """Додати два різні записи одним пакетом."""
        response = self.client.post(
            "/records/bulk",
            json=[self.record("V12-BULK1"), self.record("V12-BULK2", 2)],
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(response.json()), 2)
        self.assertEqual(self.count(), 10)

    def test_11_duplicate_bulk_rollback(self) -> None:
        """Дублікат другого елемента відкатує навіть першу вставку."""
        before = self.count()
        response = self.client.post(
            "/records/bulk",
            json=[self.record("V12-ROLL1"), self.record("V12-01")],
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.count(), before)
        with closing(database.get_connection()) as connection:
            found = connection.execute(
                "SELECT code FROM records WHERE code = ?", ("V12-ROLL1",)
            ).fetchone()
        self.assertIsNone(found)

    def test_12_missing_category_bulk_rollback(self) -> None:
        """Неіснуюча категорія другого елемента скасовує перший."""
        before = self.count()
        response = self.client.post(
            "/records/bulk",
            json=[self.record("V12-ROLL2"), self.record("V12-ROLL3", 999)],
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.count(), before)
        with closing(database.get_connection()) as connection:
            found = connection.execute(
                "SELECT code FROM records WHERE code = ?", ("V12-ROLL2",)
            ).fetchone()
        self.assertIsNone(found)

    def test_13_sql_injection_is_literal(self) -> None:
        """SQL-подібний пошук не змінює жодного запису."""
        before = self.count()
        response = self.client.get(
            "/records", params={"q": "' OR 1=1 --"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])
        self.assertEqual(self.count(), before)

    def test_14_data_persists_after_restart(self) -> None:
        """Дані залишаються в SQLite після нового клієнта застосунку."""
        created = self.client.post(
            "/records", json=self.record("V12-RESTART")
        )
        self.assertEqual(created.status_code, 201)
        record_id = created.json()["id"]
        with TestClient(app) as restarted:
            response = restarted.get(f"/records/{record_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["code"], "V12-RESTART")

    def test_15_bulk_and_models_validation(self) -> None:
        """Відхиляти зайві поля, неповний PUT і порожній пакет."""
        data = self.record("V12-EXTRA")
        data["id"] = 88
        self.assertEqual(
            self.client.post("/records", json=data).status_code, 422
        )
        partial = {"status": "done"}
        self.assertEqual(
            self.client.put("/records/1", json=partial).status_code, 422
        )
        self.assertEqual(
            self.client.post("/records/bulk", json=[]).status_code, 422
        )
        self.assertEqual(self.client.get("/records/-1").status_code, 422)

    def test_16_foreign_keys_and_seed_rollback(self) -> None:
        """Зовнішній ключ активний, хибний seed не лишає записів."""
        with closing(database.get_connection()) as connection:
            self.assertEqual(
                connection.execute("PRAGMA foreign_keys").fetchone()[0], 1
            )
        with tempfile.TemporaryDirectory() as folder:
            database_path = Path(folder) / "x.db"
            with patch.object(database, "DATABASE_PATH", database_path):
                wrong = json.loads(seed.SEED_PATH.read_text(encoding="utf-8"))
                wrong["records"][5]["code"] = wrong["records"][0]["code"]
                wrong_path = Path(folder) / "wrong.json"
                wrong_path.write_text(
                    json.dumps(wrong, ensure_ascii=False), encoding="utf-8"
                )
                with self.assertRaises(ValueError):
                    seed.seed_database(wrong_path)
                with closing(database.get_connection()) as connection:
                    n = connection.execute(
                        "SELECT COUNT(*) FROM records"
                    ).fetchone()[0]
                    c = connection.execute(
                        "SELECT COUNT(*) FROM categories"
                    ).fetchone()[0]
                self.assertEqual((n, c), (0, 0))


if __name__ == "__main__":
    unittest.main()
