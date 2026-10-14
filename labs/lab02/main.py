"""Entry point for the OOP demo and variant 12 email phishing audit."""

from __future__ import annotations

import argparse
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import run_audit


def demo() -> None:
    """Demonstrate account access, session timeout, and auditing."""
    user = User("student12", "student12@example.com")
    user.set_password("LabPassword12!")
    account = UserAccount(user)

    print("=== OOP / USER ACCOUNT DEMO ===")
    correct_login = account.login("student12", "LabPassword12!", "192.0.2.12")
    print(f"Login with correct password: {correct_login}")
    print(f"Authenticated: {account.is_authenticated()}")
    wrong_login = account.login("student12", "wrong-password", "192.0.2.12")
    print(f"Login with wrong password: {wrong_login}")
    try:
        user.email = "bad-address"
    except ValueError as exc:
        print(f"Email validation caught invalid value: {exc}")
    user.email = "updated12@example.com"
    print(f"Validated email update: {user.email}")

    admin = Admin("admin12", "admin12@example.com", {"user:read"})
    admin.grant_permission("user:write")
    print(f"Admin has user:write: {admin.has_permission('user:write')}")
    admin.revoke_permission("user:read")
    print(admin)

    if account.session is not None:
        account.session.last_activity = datetime.now(timezone.utc) - timedelta(
            seconds=901
        )
    print(
        f"Authenticated after simulated timeout: {account.is_authenticated()}"
    )
    account.login("student12", "LabPassword12!", "192.0.2.12")
    account.logout()
    print("Audit log:")
    for entry in account.audit_log.show_all():
        print(
            f"  {entry.timestamp.isoformat()} | "
            f"{entry.username} | {entry.action}"
        )


def build_parser() -> argparse.ArgumentParser:
    """Create a parser for the demo and audit commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "demo", help="demonstrate OOP account and audit classes"
    )
    analyze = subparsers.add_parser(
        "analyze", help="audit email headers for phishing indicators"
    )
    analyze.add_argument(
        "--mail-log",
        type=Path,
        default=Path("labs/lab02/data/data_v12/mail_headers.log"),
    )
    analyze.add_argument(
        "--suspicious-keywords",
        type=Path,
        default=Path("labs/lab02/data/data_v12/suspicious_keywords.txt"),
    )
    analyze.add_argument(
        "--out-csv",
        type=Path,
        default=Path("labs/lab02/data/phishing_report.csv"),
    )
    analyze.add_argument(
        "--debug",
        action="store_true",
        help="enable detailed diagnostic logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the selected command and return its exit code."""
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        demo()
        return 0

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    try:
        rows = run_audit(args.mail_log, args.suspicious_keywords, args.out_csv)
    except ValueError as exc:
        logging.error("Audit failed: %s", exc)
        return 2

    print("\nEMAIL PHISHING AUDIT — VARIANT 12")
    print(f"Messages inspected: {len(rows)}")
    print(f"{'ID':18} {'RISK':10} {'SCORE':>7} {'RECEIVED':>8}  SUBJECT")
    print("-" * 95)
    for row in rows:
        print(
            f"{row['message_id'].split('@', maxsplit=1)[0]:18} "
            f"{row['risk_level']:10} "
            f"{row['risk_score']:>3}/100 {row['received_count']:>8}  "
            f"{row['subject'][:48]}"
        )
        if row["risk_level"] in {"HIGH", "CRITICAL"}:
            print(f"  Findings: {row['findings']}")
    print(f"\nCSV report: {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
