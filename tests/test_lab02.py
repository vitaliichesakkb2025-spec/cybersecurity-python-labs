"""Тести ООП-моделі та аналізатора пошти, варіант 12."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from labs.lab02.task1 import Admin, Session, User, UserAccount
from labs.lab02.task2 import (
    analyze_message,
    extract_domain,
    find_suspicious_keywords,
    load_mail_messages,
    load_suspicious_keywords,
    run_audit,
)


class UserModelTests(unittest.TestCase):
    """Перевіряє модель облікового запису та права."""

    def setUp(self) -> None:
        """Створює тестового користувача з паролем."""
        self.user = User("student12", "student12@example.com")
        self.user.set_password("GoodPassword12!")

    def test_password_hash_verification(self) -> None:
        """Перевіряє правильний та хибний пароль."""
        self.assertTrue(self.user.check_password("GoodPassword12!"))
        self.assertFalse(self.user.check_password("wrong-password"))

    def test_email_validation(self) -> None:
        """Відхиляє хибну адресу та приймає правильну."""
        with self.assertRaises(ValueError):
            self.user.email = "bad-address"
        self.user.email = "updated12@example.com"
        self.assertEqual(self.user.email, "updated12@example.com")

    def test_admin_permissions(self) -> None:
        """Перевіряє додавання, пошук і вилучення дозволів."""
        admin = Admin("admin12", "admin12@example.com")
        admin.grant_permission("report:read")
        self.assertTrue(admin.has_permission("report:read"))
        admin.revoke_permission("report:read")
        self.assertFalse(admin.has_permission("report:read"))

    def test_session_timeout_rejects_nonpositive_timeout(self) -> None:
        """Перевіряє завершення сесії та хибний таймаут."""
        old = datetime.now(timezone.utc) - timedelta(seconds=1000)
        session = Session("192.0.2.12", old, old)
        self.assertFalse(session.is_active(900))
        with self.assertRaises(ValueError):
            session.is_active(0)

    def test_failed_login_does_not_create_session(self) -> None:
        """Відхиляє неправильні дані без створення сесії."""
        account = UserAccount(self.user)
        self.assertFalse(account.login("student12", "incorrect", "192.0.2.12"))
        self.assertIsNone(account.session)
        self.assertEqual(account.audit_log.records[-1].action, "login_failure")

    def test_successful_login_and_logout(self) -> None:
        """Перевіряє правильний вхід і завершення сесії."""
        account = UserAccount(self.user)
        self.assertTrue(
            account.login("student12", "GoodPassword12!", "192.0.2.12")
        )
        self.assertTrue(account.is_authenticated())
        account.logout()
        self.assertIsNone(account.session)
        self.assertEqual(account.audit_log.records[-1].action, "logout")

    def test_item_access_has_key_and_type_validation(self) -> None:
        """Перевіряє дозволені ключі та типи значень."""
        account = UserAccount(self.user)
        self.assertIs(account["user"], self.user)
        with self.assertRaises(KeyError):
            _ = account["password_hash"]
        with self.assertRaises(TypeError):
            account["user"] = "not a user"  # type: ignore[assignment]


class EmailAuditTests(unittest.TestCase):
    """Перевіряє розбір листів, оцінювання ризику та CSV."""

    @classmethod
    def setUpClass(cls) -> None:
        """Завантажує навчальні листи та словник варіанта 12."""
        cls.data_dir = (
            Path(__file__).parents[1] / "labs" / "lab02" / "data" / "data_v12"
        )
        cls.messages = load_mail_messages(cls.data_dir / "mail_headers.log")
        cls.keywords = load_suspicious_keywords(
            cls.data_dir / "suspicious_keywords.txt"
        )

    def test_six_sample_messages_are_loaded(self) -> None:
        """Перевіряє зчитування всіх шести листів."""
        self.assertEqual(len(self.messages), 6)

    def test_extract_domain_from_display_name(self) -> None:
        """Виділяє домен з адреси, що містить ім’я відправника."""
        self.assertEqual(
            extract_domain("Security Team <security@example.com>"),
            "example.com",
        )

    def test_keywords_are_case_insensitive(self) -> None:
        """Знаходить фрази незалежно від регістру."""
        self.assertEqual(
            find_suspicious_keywords(
                "URGENT: Verify your account now", self.keywords
            ),
            ["urgent", "verify your account"],
        )

    def test_suspicious_sample_is_high_risk(self) -> None:
        """Визначає критичний ризик у підозрілому листі."""
        row = analyze_message(self.messages[1], self.keywords)
        self.assertEqual(row["risk_level"], "CRITICAL")
        self.assertTrue(row["from_return_mismatch"])
        self.assertTrue(row["from_reply_mismatch"])
        self.assertIn("urgent", row["stopwords_found"])

    def test_clean_sample_is_low_risk(self) -> None:
        """Визначає низький ризик у звичайному листі."""
        row = analyze_message(self.messages[0], self.keywords)
        self.assertEqual(row["risk_level"], "LOW")
        self.assertEqual(row["risk_score"], 0)

    def test_csv_report_is_created(self) -> None:
        """Створює CSV-звіт із полем оцінки ризику."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.csv"
            rows = run_audit(
                self.data_dir / "mail_headers.log",
                self.data_dir / "suspicious_keywords.txt",
                output,
            )
            self.assertEqual(len(rows), 6)
            self.assertTrue(output.exists())
            self.assertIn("risk_score", output.read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    unittest.main()
