"""Автоматичні перевірки вимог лабораторної роботи."""

import hashlib
import io
import json
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from labs.lab01 import task1, task2, task3
from labs.lab01.variant import CRITERIA, FORBIDDEN_PASSWORDS, PASSWORDS


class LabTests(unittest.TestCase):
    """Перевірити основні алгоритми й роботу з файлами."""

    def setUp(self):
        """Ізолювати файли кожного тесту від демонстраційних даних."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patch = patch.object(task3, "DATA_DIR", Path(self.temp.name))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        task3.users_db.clear()

    def test_duplicates(self):
        """Додати рівно три копії без зміни початкового списку."""
        result, indices = task1.add_duplicates(PASSWORDS, 12)
        self.assertEqual(len(result), 13)
        self.assertEqual(indices, [7, 4, 5])
        self.assertEqual(result[10:], [PASSWORDS[i] for i in indices])
        self.assertEqual(len(PASSWORDS), 10)

    def test_each_unique_password_checked_once(self):
        """Зберегти всі рядки й не повторювати однакові перевірки."""
        with (
            patch.object(
                task1, "evaluate_password", wraps=task1.evaluate_password
            ) as evaluate,
            redirect_stdout(io.StringIO()),
        ):
            rows = task1.run(12)
        self.assertEqual(len(rows), 13)
        self.assertEqual(evaluate.call_count, len(set(PASSWORDS)))
        self.assertEqual(rows[4], rows[11])

    def test_password_categories(self):
        """Перевірити всі категорії та межі довжини."""
        cases = {
            "abcdefghj": "Слабкий",
            "Abcdefghi": "Середній",
            "Abcdefg1!": "Сильний",
            "Abcdefghijk1!": "Дуже сильний",
            "easy123": "Заборонений",
        }
        for password, expected in cases.items():
            with self.subTest(password=password):
                actual = task1.evaluate_password(
                    password,
                    Counter([password]),
                    CRITERIA,
                    FORBIDDEN_PASSWORDS,
                )
                self.assertEqual(actual, expected)

    def test_long_duplicate(self):
        """Повторний довгий пароль не може бути дуже сильним."""
        password = "Abcdefghij1!"
        self.assertEqual(
            task1.evaluate_password(
                password,
                Counter([password, password]),
                CRITERIA,
                set(),
            ),
            "Сильний",
        )

    def test_access_priority(self):
        """Блокування переважає активність і максимальний допуск."""
        users = {"a": {"active": False, "clearance": 4}}
        resource = ("r", 1)
        self.assertEqual(
            task2.check_access("x", resource, users, {"x"}),
            "DENY (User not found)",
        )
        self.assertEqual(
            task2.check_access("a", resource, users, {"a"}),
            "DENY (User is blocked)",
        )
        self.assertEqual(
            task2.check_access("a", resource, users, set()),
            "DENY (Account inactive)",
        )

    def test_clearance(self):
        """Рівний допуск дозволяє доступ, нижчий — відхиляється."""
        users = {"a": {"active": True, "clearance": 2}}
        self.assertEqual(
            task2.check_access("a", ("r", 2), users, set()),
            "ALLOW",
        )
        self.assertEqual(
            task2.check_access("a", ("r", 3), users, set()),
            "DENY (Insufficient clearance)",
        )

    def test_hash_vector(self):
        """Хеш відповідає MD5 саме password + salt."""
        password = "abcdefgh"
        expected = hashlib.md5(b"abcdefgh00012").hexdigest()
        self.assertEqual(task3.generate_hash(password, "00012"), expected)
        self.assertEqual(len(expected), 32)

    def test_hash_validation(self):
        """Порожні значення і короткий пароль дають різні винятки."""
        for password, salt in [
            (None, "s"),
            ("", "s"),
            ("longpassword", None),
            ("longpassword", ""),
        ]:
            with self.assertRaises(ValueError):
                task3.generate_hash(password, salt)
        with self.assertRaises(task3.ValidationError):
            task3.generate_hash("short")

    def test_csv_roundtrip(self):
        """Створити 10 записів без збереження відкритих паролів."""
        task3.create_users(task3.USERS_TO_REGISTER)
        rows = task3.read_users()
        self.assertEqual(len(rows), 10)
        text = (task3.DATA_DIR / "users.csv").read_text()
        self.assertNotIn("Study@Python", text)
        self.assertEqual(rows[0][0], "student01")

    def test_login_and_logs(self):
        """Залогувати успіх, відмови та винятки в одному JSON."""
        task3.create_users(task3.USERS_TO_REGISTER)
        task3.users_db[:] = task3.read_users()
        self.assertTrue(task3.login("student01", "Study@Python01"))
        self.assertFalse(
            task3.login(username="student01", password="WrongPassword!")
        )
        self.assertFalse(task3.login("unknown", "Study@Python01"))
        with self.assertRaises(ValueError):
            task3.login("", "Study@Python01")
        with self.assertRaises(task3.ValidationError):
            task3.login("student01", "short")
        events = json.loads((task3.DATA_DIR / "log.json").read_text())
        self.assertEqual(
            [event["result"] for event in events],
            ["success", "failure", "failure", "failure", "failure"],
        )
        self.assertTrue(
            all(
                event["args"] == [] and event["kwargs"] == {}
                for event in events
            )
        )
        log_text = (task3.DATA_DIR / "log.json").read_text()
        self.assertNotIn("Study@Python", log_text)
        self.assertNotIn("WrongPassword", log_text)
        self.assertNotIn("short", log_text)
        self.assertEqual(task3.login.__name__, "login")

    def test_duplicate_username(self):
        """Відхилити повторний логін до запису бази."""
        with self.assertRaises(task3.ValidationError):
            task3.create_users((("a", "longpassword"), ("a", "otherpassword")))
        self.assertFalse((task3.DATA_DIR / "users.csv").exists())

    def test_missing_and_malformed_csv(self):
        """Відсутній і пошкоджений CSV мають відхилятися."""
        with self.assertRaises(FileNotFoundError):
            task3.read_users()
        (task3.DATA_DIR / "users.csv").write_text("broken,row,extra")
        with self.assertRaises(task3.ValidationError):
            task3.read_users()

    def test_bad_log_not_overwritten(self):
        """Не затирати пошкоджений журнал новою подією."""
        task3.create_users(task3.USERS_TO_REGISTER)
        task3.users_db[:] = task3.read_users()
        path = task3.DATA_DIR / "log.json"
        path.write_text("broken json")
        with self.assertRaises(ValueError):
            task3.login("unknown", "longpassword")
        self.assertEqual(path.read_text(), "broken json")

    def test_log_permission_error(self):
        """Відсутність дозволу на журнал перериває вхід."""
        with patch.object(task3, "append_event", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                task3.login("unknown", "longpassword")


if __name__ == "__main__":
    unittest.main()
