"""Налаштування індивідуального варіанта обліку сховищ."""

from shared.student import VARIANT_NUMBER

VARIANT = VARIANT_NUMBER
DOMAIN_NAME = "Облік використання сховищ"
RECORD_TITLE = "Вимірювання сховища"
UNIT = "% зайнятого простору"
THRESHOLD = 85.0
MIN_VALUE = 0.0
MAX_VALUE = 100.0
CATEGORY_NAMES = ("logs", "backups", "archive")
VALUES = (90.0, 60.0, 45.0, 95.0, 83.0, 70.0, 85.0, 88.0)
STATUSES = ("new", "in_progress", "done")
