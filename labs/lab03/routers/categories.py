"""HTTP-маршрути керування категоріями сховищ."""

from typing import Annotated

from fastapi import APIRouter, Path, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Категорії"])
COMMON_ERRORS = {
    404: {"description": "Категорію не знайдено"},
    409: {"description": "Конфлікт назви або наявних записів"},
}


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Отримати список категорій",
)
def get_categories() -> list[dict]:
    """Повернути всі категорії в порядку зростання ID."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    responses={409: COMMON_ERRORS[409]},
    summary="Додати категорію",
)
def add_category(payload: CategoryCreate) -> dict:
    """Створити нову категорію з унікальною назвою."""
    return repository.create_category(payload.name)


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=COMMON_ERRORS,
    summary="Видалити порожню категорію",
)
def remove_category(category_id: Annotated[int, Path(gt=0)]) -> None:
    """Заборонити видалення категорій, у яких є записи."""
    repository.delete_category(category_id)
