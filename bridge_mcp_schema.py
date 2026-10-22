"""Bounded JSON values and an explicit, non-executable JSON Schema subset.

No remote references, regular expressions, custom formats or implicit coercion.
Unsupported schemas fail closed rather than being partially validated.
"""

import json
import math
from typing import Any, cast

from bridge_http import CapabilityError

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}
JSON_ARGUMENT_BYTES = 65536
KEYWORDS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "anyOf",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
    "title",
    "description",
    "default",
    "$schema",
}


def values(value: Any, depth: int = 0) -> list[str]:
    """Validate before serialization; return raw leaves for privacy filtering."""
    if depth > 6:
        raise CapabilityError("MCP JSON depth exceeded")
    if type(value) is dict:
        if len(value) > 32 or any(type(k) is not str or len(k) > 128 for k in value):
            raise CapabilityError("Invalid MCP object")
        return [s for k, v in value.items() for s in [k, *values(v, depth + 1)]]
    if type(value) is list:
        if len(value) > 32:
            raise CapabilityError("MCP array limit exceeded")
        return [s for v in value for s in values(v, depth + 1)]
    if type(value) not in (str, int, float, bool, type(None)):
        raise CapabilityError("Invalid MCP JSON value")
    if (type(value) is float and not math.isfinite(value)) or len(str(value)) > 4096:
        raise CapabilityError("Invalid MCP JSON scalar")
    return [str(value)]


def bounded(value: Any, *, max_bytes: int = JSON_ARGUMENT_BYTES) -> list[str]:
    try:
        leaves = values(value)
        if (
            len(leaves) > 256
            or len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > max_bytes
        ):
            raise CapabilityError("MCP JSON size exceeded")
        return leaves
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, CapabilityError):
            raise
        raise CapabilityError("Invalid MCP JSON value") from None


def schema_check(schema: Any, depth: int = 0) -> None:
    if depth > 6 or not isinstance(schema, dict) or set(schema) - KEYWORDS:
        raise CapabilityError("Unsupported MCP input schema")
    kind = schema.get("type")
    if kind is not None and (not isinstance(kind, str) or kind not in TYPES):
        raise CapabilityError("Unsupported MCP schema type")
    props, required = schema.get("properties", {}), schema.get("required", [])
    if (
        not isinstance(props, dict)
        or len(props) > 32
        or any(not isinstance(k, str) or len(k) > 128 for k in props)
        or not isinstance(required, list)
        or any(not isinstance(k, str) for k in required)
        or not set(required) <= set(props)
        or type(schema.get("additionalProperties", True)) is not bool
    ):
        raise CapabilityError("Invalid MCP object schema")
    for child in props.values():
        schema_check(child, depth + 1)
    if "items" in schema:
        schema_check(schema["items"], depth + 1)
    if "anyOf" in schema:
        choices = schema["anyOf"]
        if not isinstance(choices, list) or not 1 <= len(choices) <= 8:
            raise CapabilityError("Invalid MCP schema alternatives")
        for child in choices:
            schema_check(child, depth + 1)
    if "enum" in schema:
        if not isinstance(schema["enum"], list) or not 1 <= len(schema["enum"]) <= 16:
            raise CapabilityError("Invalid MCP schema enum")
        bounded(schema["enum"])
    for key in ("minLength", "maxLength", "minItems", "maxItems"):
        if key in schema and (type(schema[key]) is not int or not 0 <= schema[key] <= 8192):
            raise CapabilityError("Invalid MCP schema limit")
    for key in ("minimum", "maximum"):
        if key in schema and (
            type(schema[key]) not in (int, float)
            or type(schema[key]) is float
            and not math.isfinite(schema[key])
        ):
            raise CapabilityError("Invalid MCP schema bound")


def matches(value: Any, schema: dict[str, Any]) -> bool:
    kind = schema.get("type")
    if kind and (
        type(value) is bool
        and kind == "number"
        or type(value) not in ((int, float) if kind == "number" else (TYPES[kind],))
    ):
        return False
    if "enum" in schema and not any(type(value) is type(v) and value == v for v in schema["enum"]):
        return False
    if "anyOf" in schema and not any(matches(value, child) for child in schema["anyOf"]):
        return False
    if isinstance(value, dict):
        props = schema.get("properties", {})
        if not set(schema.get("required", [])) <= set(value):
            return False
        if schema.get("additionalProperties") is False and set(value) - set(props):
            return False
        if any(not matches(v, props[k]) for k, v in value.items() if k in props):
            return False
    if isinstance(value, list) and "items" in schema:
        if any(not matches(v, schema["items"]) for v in value):
            return False
    for kind_type, low, high, metric in (
        (str, "minLength", "maxLength", len),
        (list, "minItems", "maxItems", len),
        ((int, float), "minimum", "maximum", lambda v: v),
    ):
        if isinstance(value, kind_type) and type(value) is not bool:
            size = cast(Any, metric)(value)
            if (low in schema and size < schema[low]) or (high in schema and size > schema[high]):
                return False
    return True


def checked_schema(schema: Any) -> None:
    # Schema metadata is bounded independently of argument depth/size.
    try:
        if len(json.dumps(schema).encode("utf-8")) > 16384:
            raise CapabilityError("MCP schema size exceeded")
        schema_check(schema)
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        if isinstance(exc, CapabilityError):
            raise
        raise CapabilityError("Invalid MCP input schema") from None


def validate(value: Any, schema: Any) -> None:
    bounded(value)
    checked_schema(schema)
    if not matches(value, schema):
        raise CapabilityError("MCP arguments do not match schema")
