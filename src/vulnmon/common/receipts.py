"""Delivery receipt payload (kind ``delivery.receipt``), notify -> core.

A receipt reports one fact about one delivery attempt. It never changes
applicability or priority; the core accepts it only when ``event_id`` and
``attempt_id`` correlate with an attempt it exported. Provider acceptance,
observed delivery and human acknowledgement are distinct outcomes.
"""
from vulnmon.common.contracts import ContractError, fields, string, timestamp

KIND = "delivery.receipt"
OUTCOMES = ("accepted", "delivered", "acknowledged", "failed", "ambiguous")
MAX_DETAIL = 1024


def validate(payload):
    fields(payload, ("event_id", "attempt_id", "channel", "outcome", "occurred_at",
                     "provider_reference", "detail"))
    for key in ("event_id", "attempt_id", "channel"):
        string(payload[key], key)
    if payload["outcome"] not in OUTCOMES:
        raise ContractError("unsupported receipt outcome")
    timestamp(payload["occurred_at"])
    if payload["provider_reference"] is not None:
        string(payload["provider_reference"], "provider_reference")
    detail = payload["detail"]
    if detail is not None and (not isinstance(detail, str) or len(detail) > MAX_DETAIL
                               or "\x00" in detail):
        raise ContractError("invalid detail")
    return payload
