"""HTTP-маршрути читання та зміни вимірювань використання сховищ."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, status

from labs.lab03 import repository
from labs.lab03.schemas import (
    RecordCreate,
    RecordRead,
    RecordReplace,
    Status,
)

router = APIRouter(prefix="/records", tags=["Вимірювання"])
NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Код дублюється або порушено зв'язки"}}
WRITE_ERRORS = NOT_FOUND | CONFLICT


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список вимірювань із фільтрами",
)
def get_records(
    category_id: Annotated[int | None, Query(gt=0)] = None,
    status_filter: Annotated[
        Status | None, Query(alias="status")
    ] = None,
    min_value: Annotated[
        float | None, Query(ge=0, le=100, allow_inf_nan=False)
    ] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    """Відібрати за категорією, статусом, значенням і фрагментом назви."""
    return repository.list_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    responses=WRITE_ERRORS,
    summary="Атомарно додати пакет вимірювань",
)
def add_bulk(
    payload: Annotated[
        list[RecordCreate], Body(min_length=1, max_length=100)
    ],
) -> list[dict]:
    """Або додати весь пакет з 1–100 записів, або не додати нічого."""
    return repository.create_records_bulk(payload)


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    responses=NOT_FOUND,
    summary="Отримати вимірювання за ID",
)
def get_one(record_id: Annotated[int, Path(gt=0)]) -> dict:
    """Повернути запис разом із назвою категорії."""
    return repository.get_record(record_id)


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    responses=WRITE_ERRORS,
    summary="Створити нове вимірювання",
)
def add_one(payload: RecordCreate) -> dict:
    """Створити запис із перевіркою категорії та унікальності коду."""
    return repository.create_record(payload)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    responses=WRITE_ERRORS,
    summary="Замінити всі змінювані поля вимірювання",
)
def replace_one(
    record_id: Annotated[int, Path(gt=0)], payload: RecordReplace
) -> dict:
    """Оновити п'ять полів запису, залишивши його ID незмінним."""
    return repository.replace_record(record_id, payload)


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=NOT_FOUND,
    summary="Видалити вимірювання",
)
def remove_one(record_id: Annotated[int, Path(gt=0)]) -> None:
    """Видалити запис за ID або повернути 404."""
    repository.delete_record(record_id)
