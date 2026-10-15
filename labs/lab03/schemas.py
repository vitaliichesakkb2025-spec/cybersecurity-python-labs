"""Pydantic-моделі вхідних даних і відповідей API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["new", "in_progress", "done"]


class StrictModel(BaseModel):
    """Заборонити невідомі поля та обрізати зовнішні пробіли."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )


class CategoryCreate(StrictModel):
    """Назва нової категорії без її ідентифікатора."""

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія з ідентифікатором, створеним SQLite."""

    id: int = Field(gt=0)


class RecordCreate(StrictModel):
    """Нове навчальне вимірювання заповненості сховища."""

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=0, le=100, allow_inf_nan=False)
    status: Status


class RecordReplace(RecordCreate):
    """Повна заміна п'яти змінюваних полів вимірювання."""


class RecordRead(RecordCreate):
    """Вимірювання з ID і назвою пов'язаної категорії."""

    id: int = Field(gt=0)
    category_name: str
