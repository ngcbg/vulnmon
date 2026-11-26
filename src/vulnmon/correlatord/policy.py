"""Illustrative policy only, not the organization's approved P0-P3 rules."""
from .matchers import Applicability

VERSION = "fixture-policy-v1"


def priority(component, match, advisories):
    if match.applicability not in (Applicability.AFFECTED, Applicability.UNKNOWN):
        return None
    if any(a["source"] == "ubuntu-fixture" and (
        a["known_exploited"] is True or (
            component["exposure"] == "edge" and a["impact"] == "remote_code_execution"
            and a["authentication_required"] is False
        )
    ) for a in advisories):
        return "P0"
    if match.applicability == Applicability.AFFECTED:
        return "P1"
    return None
