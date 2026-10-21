"""Exercise real schema admission and validation with bounded adversarial data."""

import math

import pytest

from bridge_http import CapabilityError
from bridge_mcp_schema import bounded, schema_check, validate


@pytest.mark.parametrize(
    "value",
    [
        {str(i): 0 for i in range(33)},
        {1: "x"},
        {"x" * 129: 1},
        [0] * 33,
        [[[[[[[0]]]]]]],
        {"bad": set()},
        float("inf"),
        float("nan"),
        "x" * 4097,
        ["x" * 4096] * 17,
        [[0] * 32] * 9,
    ],
)
def test_json_resource_limits(value):
    with pytest.raises(CapabilityError):
        bounded(value)


def test_raw_privacy_leaves_preserve_keys_quotes_and_nested_strings():
    assert bounded({"key": ['secret\nquoted"value', {"nested": False}, None, 1.2]}) == [
        "key",
        'secret\nquoted"value',
        "nested",
        "False",
        "None",
        "1.2",
    ]


@pytest.mark.parametrize(
    "schema",
    [
        [],
        {"$ref": "https://untrusted.invalid/schema"},
        {"type": []},
        {"type": "unknown"},
        {"properties": []},
        {"properties": {1: {}}},
        {"properties": {"x" * 129: {}}},
        {"properties": {str(i): {} for i in range(33)}},
        {"required": "x"},
        {"required": [1]},
        {"required": ["unknown"]},
        {"additionalProperties": {}},
        {"items": []},
        {"anyOf": None},
        {"anyOf": []},
        {"anyOf": [{}] * 9},
        {"enum": None},
        {"enum": []},
        {"enum": list(range(17))},
        {"enum": ["x" * 4097]},
        {"minLength": True},
        {"maxLength": -1},
        {"maxItems": 8193},
        {"minItems": "1"},
        {"minimum": True},
        {"maximum": math.inf},
        {"minimum": "1"},
        {"items": {"items": {"items": {"items": {"items": {"items": {"items": {}}}}}}}},
    ],
)
def test_unsupported_or_malformed_schemas_are_explicitly_denied(schema):
    with pytest.raises(CapabilityError):
        schema_check(schema)


@pytest.mark.parametrize(
    "schema,good,bad",
    [
        ({"type": "integer"}, 3, True),
        ({"type": "number"}, 1.5, True),
        ({"type": "boolean"}, True, 1),
        ({"type": "null"}, None, "null"),
        ({"type": "string", "minLength": 1, "maxLength": 3}, "abc", ""),
        ({"maxLength": 2}, "a", "abc"),
        ({"type": "array", "items": {"type": "integer"}}, [1, 2], [1, False]),
        ({"minItems": 1, "maxItems": 2}, [0], []),
        ({"maxItems": 1}, [], [0, 0]),
        ({"minimum": 0, "maximum": 3}, 2.5, -1),
        ({"maximum": 3}, 2, 4),
        ({"enum": [1, "x"]}, "x", True),
        ({"anyOf": [{"type": "null"}, {"type": "string"}]}, None, 1),
        (
            {
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "required": ["x"],
                "additionalProperties": False,
            },
            {"x": "ok"},
            {},
        ),
        (
            {"properties": {"x": {"type": "string"}}, "additionalProperties": False},
            {"x": "ok"},
            {"extra": 1},
        ),
        ({"properties": {"x": {"type": "string"}}}, {"other": "ok"}, {"x": 1}),
    ],
)
def test_actual_schema_validation_without_coercion(schema, good, bad):
    validate(good, schema)
    with pytest.raises(CapabilityError):
        validate(bad, schema)


def test_metadata_size_and_serialization_are_bounded():
    validate({"nested": [1, None]}, {})
    for schema in ({"description": "x" * 17000}, {"default": set()}):
        with pytest.raises(CapabilityError):
            validate({}, schema)
    recursive = {}
    recursive["items"] = recursive
    with pytest.raises(CapabilityError):
        validate({}, recursive)
    with pytest.raises(CapabilityError, match="Invalid MCP JSON value"):
        bounded({"invalid_utf8": "\ud800"})
