"""Unit tests for the OOP model and variant 12 email-header auditor."""

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
    """Test the account and permission models."""
    def setUp(self) -> None:
        """Build a fresh test user with a saved password."""
        self.user = User("student12", "student12@example.com")
        self.user.set_password("GoodPassword12!")

    def test_password_hash_verification(self) -> None:
        """Check valid and invalid password verification."""
        self.assertTrue(self.user.check_password("GoodPassword12!"))
        self.assertFalse(self.user.check_password("wrong-password"))

    def test_email_validation(self) -> None:
        """Reject invalid addresses and accept a valid update."""
        with self.assertRaises(ValueError):
            self.user.email = "bad-address"
        self.user.email = "updated12@example.com"
        self.assertEqual(self.user.email, "updated12@example.com")

    def test_admin_permissions(self) -> None:
        """Test permission granting, checking, and revocation."""
        admin = Admin("admin12", "admin12@example.com")
        admin.grant_permission("report:read")
        self.assertTrue(admin.has_permission("report:read"))
        admin.revoke_permission("report:read")
        self.assertFalse(admin.has_permission("report:read"))

    def test_session_timeout_rejects_nonpositive_timeout(self) -> None:
        """Test timeout limits and invalid timeout values."""
        old = datetime.now(timezone.utc) - timedelta(seconds=1000)
        session = Session("192.0.2.12", old, old)
        self.assertFalse(session.is_active(900))
        with self.assertRaises(ValueError):
            session.is_active(0)

    def test_failed_login_does_not_create_session(self) -> None:
        """Reject invalid credentials without creating a session."""
        account = UserAccount(self.user)
        self.assertFalse(account.login("student12", "incorrect", "192.0.2.12"))
        self.assertIsNone(account.session)
        self.assertEqual(account.audit_log.records[-1].action, "login_failure")

    def test_successful_login_and_logout(self) -> None:
        """Allow valid login and clear the session on logout."""
        account = UserAccount(self.user)
        self.assertTrue(
            account.login("student12", "GoodPassword12!", "192.0.2.12")
        )
        self.assertTrue(account.is_authenticated())
        account.logout()
        self.assertIsNone(account.session)
        self.assertEqual(account.audit_log.records[-1].action, "logout")

    def test_item_access_has_key_and_type_validation(self) -> None:
        """Validate allowed account keys and value types."""
        account = UserAccount(self.user)
        self.assertIs(account["user"], self.user)
        with self.assertRaises(KeyError):
            _ = account["password_hash"]
        with self.assertRaises(TypeError):
            account["user"] = "not a user"  # type: ignore[assignment]


class EmailAuditTests(unittest.TestCase):
    """Test email parsing, risk scoring, and CSV output."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load the shared variant-12 input messages and keywords."""
        cls.data_dir = (
            Path(__file__).parents[1] / "labs" / "lab02" / "data" / "data_v12"
        )
        cls.messages = load_mail_messages(cls.data_dir / "mail_headers.log")
        cls.keywords = load_suspicious_keywords(
            cls.data_dir / "suspicious_keywords.txt"
        )

    def test_six_sample_messages_are_loaded(self) -> None:
        """Check that all six messages are read."""
        self.assertEqual(len(self.messages), 6)

    def test_extract_domain_from_display_name(self) -> None:
        """Extract the domain from a display name address."""
        self.assertEqual(
            extract_domain("Security Team <security@example.com>"),
            "example.com",
        )

    def test_keywords_are_case_insensitive(self) -> None:
        """Match keywords regardless of letter case."""
        self.assertEqual(
            find_suspicious_keywords(
                "URGENT: Verify your account now", self.keywords
            ),
            ["urgent", "verify your account"],
        )

    def test_suspicious_sample_is_high_risk(self) -> None:
        """Assign a critical score to the phishing example."""
        row = analyze_message(self.messages[1], self.keywords)
        self.assertEqual(row["risk_level"], "CRITICAL")
        self.assertTrue(row["from_return_mismatch"])
        self.assertTrue(row["from_reply_mismatch"])
        self.assertIn("urgent", row["stopwords_found"])

    def test_clean_sample_is_low_risk(self) -> None:
        """Assign a low score to the clean example."""
        row = analyze_message(self.messages[0], self.keywords)
        self.assertEqual(row["risk_level"], "LOW")
        self.assertEqual(row["risk_score"], 0)

    def test_csv_report_is_created(self) -> None:
        """Write a CSV report containing the score field."""
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
