"""JSON export wrapper (EXPORT_CONTRACT §3) — adds schema_version/exported_at."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from CVEzD3FEND.util import now_iso

SCHEMA_VERSION = "1.0.0"


def export_json(obj: BaseModel | dict | list) -> dict[str, Any]:
    if isinstance(obj, BaseModel):
        data: Any = obj.model_dump(mode="json")
    elif isinstance(obj, list):
        data = [item.model_dump(mode="json") if isinstance(item, BaseModel) else item for item in obj]
    else:
        data = obj
    return {"schema_version": SCHEMA_VERSION, "exported_at": now_iso(), "data": data}
