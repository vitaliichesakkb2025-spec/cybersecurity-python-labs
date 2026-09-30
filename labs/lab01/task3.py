"""Навчальні MD5, CSV-база та журнал авторизації без паролів."""

import csv
import hashlib
import hmac
import json
from datetime import datetime
from functools import wraps
from pathlib import Path

from labs.lab01.variant import HASH_ALGORITHM, HASH_MIN_LENGTH
from shared.student import VARIANT_NUMBER

DATA_DIR = Path(__file__).resolve().parent / "data"
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"
USERS_TO_REGISTER = (
    ("student01", "Study@Python01"),
    ("student02", "Study@Python02"),
    ("student03", "Study@Python03"),
    ("student04", "Study@Python04"),
    ("student05", "Study@Python05"),
    ("student06", "Study@Python06"),
    ("student07", "Study@Python07"),
    ("student08", "Study@Python08"),
    ("student09", "Study@Python09"),
    ("student10", "Study@Python10"),
)
users_db = []


class ValidationError(Exception):
    """Пароль або структура бази не відповідає вимогам."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Обчислити MD5 від UTF-8 подання password + salt."""
    if password is None or password == "" or salt is None or salt == "":
        raise ValueError("Пароль і сіль не можуть бути порожніми.")
    if len(password) < HASH_MIN_LENGTH:
        raise ValidationError(f"Мінімальна довжина: {HASH_MIN_LENGTH}.")
    return hashlib.new(HASH_ALGORITHM, (password + salt).encode()).hexdigest()


def create_user(username, password):
    """Повернути логін і хеш із персональною сіллю."""
    if not username or not username.strip():
        raise ValueError("Логін не може бути порожнім.")
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(users_list):
    """Створити CSV-базу користувачів із власною обробкою помилок доступу."""
    rows = [
        create_user(username, password) for username, password in users_list
    ]
    if len({row[0] for row in rows}) != len(rows):
        raise ValidationError("Логіни мають бути унікальними.")

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with (DATA_DIR / "users.csv").open(
            "w", encoding="utf-8", newline=""
        ) as file:
            csv.writer(file).writerows(rows)
        return rows
    except PermissionError:
        print("Помилка: немає прав для запису бази користувачів.")
        return []
    except (IOError, OSError) as error:
        print(f"Помилка створення файлу бази: {error}")
        return []


def read_users():
    """Зчитати й провалідувати базу CSV із власною обробкою відсутності файлу."""
    file_path = DATA_DIR / "users.csv"
    try:
        with file_path.open(encoding="utf-8", newline="") as file:
            rows = list(csv.reader(file))
    except FileNotFoundError:
        print("Помилка: файл бази користувачів не знайдено.")
        return []
    except PermissionError:
        print("Помилка: немає прав для читання бази користувачів.")
        return []
    except (IOError, OSError) as error:
        print(f"Помилка читання файлу бази: {error}")
        return []

    names = set()
    for row in rows:
        if len(row) != 2:
            raise ValidationError("Некоректна кількість полів CSV.")
        username, hash_value = row
        if not username or username in names:
            raise ValidationError("Порожній або повторний логін у CSV.")
        if len(hash_value) != 32 or any(
            c not in "0123456789abcdef" for c in hash_value
        ):
            raise ValidationError("Некоректний MD5 у CSV.")
        names.add(username)
    return rows


def append_event(username, result):
    """Безпечно додати подію в JSON-журнал із ізольованою обробкою помилок."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "log.json"

    events = []
    if path.exists():
        try:
            with path.open(encoding="utf-8") as file:
                loaded = json.load(file)
                if isinstance(loaded, list):
                    events = loaded
                else:
                    raise ValueError("Журнал повинен містити JSON-масив.")
        except (json.JSONDecodeError, ValueError) as error:
            print(f"Попередження: файл журналу пошкоджено ({error}).")
            raise

    events.append(
        {
            "event": "login",
            "user": username,
            "result": result,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": [],
            "kwargs": {},
        }
    )

    temporary = path.with_suffix(".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as file:
            json.dump(events, file, ensure_ascii=False, indent=2)
        temporary.replace(path)
    except PermissionError:
        print("Помилка: немає прав для запису журналу подій.")
        raise
    except (IOError, OSError) as error:
        print(f"Помилка збереження журналу: {error}")
        raise


def log_event(function):
    """Декоратор для автоматичного журналювання результату входу."""

    @wraps(function)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "")
        result = "failure"
        try:
            success = function(*args, **kwargs)
            result = "success" if success else "failure"
            return success
        finally:
            append_event(username, result)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевірити облікові дані користувача у завантаженій users_db."""
    username, hash_value = create_user(username, password)
    for stored_username, stored_hash in users_db:
        if stored_username == username:
            return hmac.compare_digest(hash_value, stored_hash)
    return False


def run():
    """Демонстрація Завдання 3: створення бази та виконання тестових входів."""
    print(
        f"\nЗавдання 3 | {HASH_ALGORITHM.upper()} | "
        f"min_length={HASH_MIN_LENGTH} | salt={PERSONAL_SALT}"
    )

    created_rows = create_users(USERS_TO_REGISTER)
    if not created_rows:
        return False

    loaded_rows = read_users()
    if not loaded_rows:
        return False

    users_db[:] = loaded_rows
    print(f"{'Логін':<14} {HASH_ALGORITHM.upper()}")
    for username, hash_value in users_db:
        print(f"{username:<14} {hash_value}")

    attempts = (
        ("student01", "Study@Python01"),
        ("student01", "WrongPassword!"),
        ("unknown", "Study@Python01"),
        ("", "Study@Python01"),
        ("student01", "short"),
    )

    completed = True
    for username, password in attempts:
        try:
            result = login(username, password)
            print(f"login({username!r}) -> {result}")
        except ValidationError:
            print(f"login({username!r}) -> ValidationError")
        except ValueError:
            print(f"login({username!r}) -> ValueError")
        except (PermissionError, IOError, OSError):
            completed = False

    return completed