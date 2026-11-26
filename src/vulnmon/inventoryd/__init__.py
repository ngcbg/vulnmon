"""Inventory intake, not inventory generation."""
from vulnmon.common.contracts import (
    ContractError, boolean, envelope, fields, number, string, timestamp,
)


def validate(snapshot):
    envelope(snapshot, ("producer", "scope", "snapshot_id", "revision",
                        "observed_at", "complete", "components"))
    for key in ("producer", "scope", "snapshot_id"):
        string(snapshot[key], key)
    number(snapshot["revision"], "revision")
    timestamp(snapshot["observed_at"])
    boolean(snapshot["complete"], "complete")
    components = snapshot["components"]
    if not isinstance(components, list):
        raise ContractError("components must be an array")
    seen = set()
    keys = ("asset_id", "component_id", "ecosystem", "name", "version",
            "origin", "os_release", "architecture", "exposure")
    for item in components:
        fields(item, keys, ("source_package",))
        for key in keys:
            string(item[key], key)
        if "source_package" in item:
            string(item["source_package"], "source_package")
        if item["exposure"] not in ("edge", "internal", "build-only", "unknown"):
            raise ContractError("unsupported exposure")
        identity = (item["asset_id"], item["component_id"])
        if identity in seen:
            raise ContractError(f"duplicate component instance: {identity}")
        seen.add(identity)
    return snapshot
