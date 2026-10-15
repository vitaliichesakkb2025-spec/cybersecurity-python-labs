"""FastAPI-сервіс обліку використання сховищ, варіант 12."""

import logging
import sqlite3
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from labs.lab03 import config, database, repository
from labs.lab03.routers.categories import router as categories_router
from labs.lab03.routers.records import router as records_router
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

LOG = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці лише при запуску вебзастосунку."""
    database.initialize_database()
    yield


app = FastAPI(
    title=f"ЛР №3 — {config.DOMAIN_NAME}",
    description=(
        "Варіант 12: використання сховищ logs, backups, archive. "
        f"Значення value — {config.UNIT} (0–100), "
        f"поріг уваги {config.THRESHOLD}%. "
        "Дані навчальні; збереження реалізовано через SQLite."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories_router)
app.include_router(records_router)


@app.exception_handler(repository.NotFoundError)
async def handle_missing(
    _request: Request, error: repository.NotFoundError
) -> JSONResponse:
    """Перетворити відсутній ресурс на HTTP 404."""
    return JSONResponse(status_code=404, content={"detail": str(error)})


@app.exception_handler(repository.ConflictError)
async def handle_conflict(
    _request: Request, error: repository.ConflictError
) -> JSONResponse:
    """Перетворити порушення унікальності або зв'язку на HTTP 409."""
    return JSONResponse(status_code=409, content={"detail": str(error)})


@app.exception_handler(sqlite3.Error)
async def handle_sqlite_error(
    _request: Request, error: sqlite3.Error
) -> JSONResponse:
    """Сховати SQL та шляхи від клієнта; записати технічну помилку."""
    LOG.error("Внутрішня помилка SQLite", exc_info=error)
    return JSONResponse(
        status_code=500, content={"detail": "Внутрішня помилка сервера"}
    )


@app.get("/ping", tags=["Службові"], summary="Перевірка доступності")
def ping() -> dict[str, str]:
    """Повідомити, що API приймає запити."""
    return {"status": "ok"}


@app.get("/student", tags=["Службові"], summary="Дані студента")
def student() -> dict[str, str | int]:
    """Прочитати дані лише з чинного спільного модуля."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
