"""Deliberately narrow v1 fixture contracts; no remote input is supported."""
import hashlib
import json
from datetime import datetime
from pathlib import Path

MAX_INPUT_BYTES = 64 * 1024 * 1024


class ContractError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _bad_constant(value):
    raise ContractError(f"invalid JSON constant: {value}")


def loads(raw, limit=MAX_INPUT_BYTES):
    """Strict bounded JSON: duplicate keys, NaN/Infinity and deep nesting are rejected."""
    if len(raw) > limit:
        raise ContractError("input exceeds size limit")
    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=_bad_constant)
    except RecursionError as exc:
        raise ContractError("input nesting too deep") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {exc}") from exc


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    return loads(raw)


def fields(obj, required, optional=()):
    if not isinstance(obj, dict):
        raise ContractError("expected object")
    missing = set(required) - obj.keys()
    extra = obj.keys() - set(required) - set(optional)
    if missing or extra:
        raise ContractError(f"missing fields {sorted(missing)}; unknown fields {sorted(extra)}")


def string(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 512 or "\x00" in value:
        raise ContractError(f"invalid {name}")


def number(value, name):
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ContractError(f"{name} must be a positive SQLite integer")


def boolean(value, name, nullable=False):
    if type(value) is not bool and not (nullable and value is None):
        raise ContractError(f"invalid {name}")


def timestamp(value):
    string(value, "timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ContractError("invalid observation timestamp") from exc
    if parsed.utcoffset() is None:
        raise ContractError("timestamp must contain a timezone")


def envelope(obj, keys):
    fields(obj, ("schema_version", *keys))
    if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
        raise ContractError("unsupported schema version")
