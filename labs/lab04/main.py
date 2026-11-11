"""CLI для аналізу одного запису NVD у мережевому або локальному режимі."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from labs.lab04 import api_client, analysis
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def _cve_argument(value: str) -> str:
    """Перевірити точний формат CVE без нормалізації регістру."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("очікується CVE-РРРР-НННН (4+ цифри)")
    return value


def load_response(path: Path) -> Any:
    """Зчитати локальну UTF-8 JSON-відповідь без мережевого доступу."""
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    """Перевірити аргументи й дані та вивести рівно один JSON-звіт."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", type=_cve_argument, required=True)
    parser.add_argument("--input", type=Path, default=None)
    args = parser.parse_args(argv)
    if (
        isinstance(VARIANT_NUMBER, bool)
        or not isinstance(VARIANT_NUMBER, int)
        or not 1 <= VARIANT_NUMBER <= 15
    ):
        print(
            "Помилка: номер варіанта має бути цілим від 1 до 15",
            file=sys.stderr,
        )
        return 2

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)
    except OSError:
        print("Помилка читання локального JSON-файла", file=sys.stderr)
        return 1
    except UnicodeError:
        print("Файл має бути закодований у UTF-8", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("Локальний файл містить некоректний JSON", file=sys.stderr)
        return 1
    except api_client.NVDClientError as exc:
        print(f"Помилка NVD: {exc}", file=sys.stderr)
        return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        print(f"Некоректні дані NVD: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
