"""Ubuntu package applicability using the native dpkg version semantics."""
from dataclasses import dataclass
from enum import Enum
import subprocess


class Applicability(str, Enum):
    UNKNOWN = "unknown"
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"


@dataclass(frozen=True)
class Match:
    applicability: Applicability
    reason: str


def _dpkg(*args):
    return subprocess.run(["dpkg", *args], timeout=2, check=False,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def _compare(left, op, right):
    result = _dpkg("--compare-versions", left, op, right)
    if result not in (0, 1):
        raise ValueError("dpkg comparison failed")
    return result == 0


def evaluate(component, advisory):
    unknown = Applicability.UNKNOWN
    # Only explicitly normalized Ubuntu fixture claims are authoritative here.
    # Real source authentication and distro adapters must replace this convention.
    if (advisory["source"] != "ubuntu-fixture"
            or component["ecosystem"] != "deb" or advisory["ecosystem"] != "deb"
            or component["origin"] != "ubuntu" or advisory["origin"] != "ubuntu"
            or component["os_release"] != advisory["os_release"]
            or advisory["architecture"] not in ("all", component["architecture"])):
        return Match(unknown, "unsupported or unmatched source/build scope")
    version = component["version"]
    lower = advisory["affected_from"]
    fixed = advisory["fixed_version"]
    try:
        for value in (version, lower, fixed):
            if value is not None and _dpkg("--validate-version", value) != 0:
                return Match(unknown, "invalid Debian version")
        if lower is not None and fixed is not None and not _compare(lower, "lt", fixed):
            return Match(unknown, "inconsistent advisory bounds")
        if advisory["status"] == "unknown":
            return Match(unknown, "source status unknown")
        if advisory["status"] == "not_affected":
            return Match(Applicability.NOT_AFFECTED, "explicit fixture non-applicability")
        if lower is not None and _compare(version, "lt", lower):
            return Match(Applicability.NOT_AFFECTED, "below explicit affected range")
        if fixed is not None and _compare(version, "ge", fixed):
            return Match(Applicability.FIXED, "at or above distro fixed build")
        return Match(Applicability.AFFECTED, "within source-asserted affected range")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return Match(unknown, "version comparator unavailable or failed")


def reconcile(component, advisories):
    matches = [evaluate(component, advisory) for advisory in advisories]
    statuses = {match.applicability for match in matches}
    if len(statuses) != 1:
        return Match(Applicability.UNKNOWN, "conflicting or unresolved evidence")
    if not matches:
        return Match(Applicability.UNKNOWN, "no evidence")
    return Match(matches[0].applicability,
                 "; ".join(sorted({match.reason for match in matches})))
