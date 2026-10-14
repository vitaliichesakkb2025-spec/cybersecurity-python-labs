"""Object-oriented model of users, sessions, accounts, and audit events."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

PASSWORD_ITERATIONS = 310_000
PASSWORD_SALT_BYTES = 16
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class User:
    """A user identity with a salted, iterated password hash."""

    def __init__(self, username: str, email: str, role: str = "user", active: bool = True) -> None:
        if not username.strip():
            raise ValueError("username must not be empty")
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        """Return the validated email address."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("email has an invalid format")
        self._email = value

    def set_password(self, password: str) -> None:
        """Store a PBKDF2-HMAC-SHA256 hash, never the clear-text password."""
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("password must contain at least 8 characters")
        self.__password_salt = os.urandom(PASSWORD_SALT_BYTES)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PASSWORD_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        """Compare a candidate password without timing-sensitive byte equality."""
        if self.__password_hash is None or self.__password_salt is None:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PASSWORD_ITERATIONS
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        """Disable this account."""
        self.active = False

    def __str__(self) -> str:
        return (
            f"User(username={self.username!r}, email={self.email!r}, "
            f"role={self.role!r}, active={self.active})"
        )


class Admin(User):
    """A user account with a set of administrative permissions."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, role="admin", active=active)
        self.permissions = set(permissions or set())

    def grant_permission(self, permission: str) -> None:
        if not permission.strip():
            raise ValueError("permission must not be empty")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        permissions = ", ".join(sorted(self.permissions)) or "none"
        return (
            f"Admin(username={self.username!r}, permissions=[{permissions}], active={self.active})"
        )


@dataclass
class Session:
    """An authenticated session whose timestamps are timezone-aware UTC."""

    ip: str
    login_time: datetime
    last_activity: datetime

    @classmethod
    def create(cls, ip: str) -> Session:
        now = datetime.now(timezone.utc)
        return cls(ip=ip, login_time=now, last_activity=now)

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")
        now = datetime.now(timezone.utc)
        return now - self.last_activity < timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditEntry:
    """One immutable audit record."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """In-memory audit trail that never stores credentials."""

    def __init__(self) -> None:
        self.records: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        self.records.append(AuditEntry(datetime.now(timezone.utc), username, action))

    def show_all(self) -> list[AuditEntry]:
        return list(self.records)


class UserAccount:
    """Compose a user, optional session, and an audit log into an account."""

    SESSION_TIMEOUT_SEC = SESSION_TIMEOUT_SEC
    _ALLOWED_KEYS = {"user", "session", "audit_log"}

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError("user must be a User instance")
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Authenticate; a failed attempt does not create or extend a session."""
        if (
            username != self.user.username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session.create(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        return bool(
            self.session and self.session.is_active(self.SESSION_TIMEOUT_SEC) and self.user.active
        )

    def logout(self) -> None:
        if self.session is not None:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str) -> Any:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(key)
        expected = {"user": User, "session": Session, "audit_log": AuditLog}[key]
        if value is None and key == "session":
            setattr(self, key, value)
            return
        if not isinstance(value, expected):
            raise TypeError(f"{key} must be an instance of {expected.__name__}")
        setattr(self, key, value)
