"""Normalized advisory intake. Live source adapters are deferred."""
from vulnmon.common.contracts import (
    ContractError, boolean, envelope, number, string, timestamp,
)


def validate(advisory):
    keys = ("source", "advisory_id", "vulnerability_id", "revision",
            "observed_at", "ecosystem", "package", "origin", "os_release",
            "architecture", "status", "fixed_version", "affected_from",
            "impact", "authentication_required", "known_exploited")
    envelope(advisory, keys)
    for key in ("source", "advisory_id", "vulnerability_id", "ecosystem",
                "package", "origin", "os_release", "architecture", "impact"):
        string(advisory[key], key)
    number(advisory["revision"], "revision")
    timestamp(advisory["observed_at"])
    if advisory["status"] not in ("affected", "not_affected", "unknown"):
        raise ContractError("unsupported advisory status")
    for key in ("fixed_version", "affected_from"):
        if advisory[key] is not None:
            string(advisory[key], key)
            if advisory["status"] != "affected":
                raise ContractError("version bounds require affected status")
    boolean(advisory["authentication_required"], "authentication_required", True)
    boolean(advisory["known_exploited"], "known_exploited", True)
    return advisory
