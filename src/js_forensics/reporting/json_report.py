"""JSON serialization of reports. The schema is in docs/output-schema.md."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def to_json(payload: Any) -> str:
    """Serialize a report dataclass, or a dict/list containing them.

    Output is ASCII-only: analyzed strings can contain lone surrogates, which
    are valid in JSON as escapes but cannot be written as UTF-8.
    """
    return json.dumps(payload, indent=2, default=_encode_dataclass) + "\n"


def _encode_dataclass(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError(f"{type(value).__name__} is not JSON serializable")
