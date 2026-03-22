import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def scan_security_posture(input_type: str, content: str) -> dict:
    """
    Run static security checks against the provided input.
    Returns a posture report with individual check results and an overall score.
    """
    checks = _get_checks(input_type)
    results = []

    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        parsed = None

    for check in checks:
        try:
            passed, detail = check["fn"](content, parsed)
        except Exception as exc:
            logger.warning("Check '%s' raised an exception: %s", check["name"], exc)
            passed, detail = False, "Check could not be evaluated"

        results.append({
            "check": check["name"],
            "passed": passed,
            "severity": check["severity"],
            "detail": detail,
        })

    passed_count = sum(1 for r in results if r["passed"])
    total = len(results)
    score = round((passed_count / total) * 100) if total else 0

    if score >= 80:
        posture = "GOOD"
    elif score >= 50:
        posture = "FAIR"
    else:
        posture = "POOR"

    return {
        "input_type": input_type,
        "posture": posture,
        "score": score,
        "checks_passed": passed_count,
        "checks_total": total,
        "findings": results,
    }


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def _check_no_wildcard_action(raw: str, parsed: Any):
    if not parsed:
        return False, "Could not parse policy"
    for stmt in parsed.get("Statement", []):
        action = stmt.get("Action", [])
        if isinstance(action, str):
            action = [action]
        if "*" in action and stmt.get("Effect") == "Allow":
            return False, "One or more statements allow all actions (*)"
    return True, "No wildcard actions found"


def _check_no_wildcard_resource(raw: str, parsed: Any):
    if not parsed:
        return False, "Could not parse policy"
    for stmt in parsed.get("Statement", []):
        resource = stmt.get("Resource", [])
        if isinstance(resource, str):
            resource = [resource]
        if "*" in resource and stmt.get("Effect") == "Allow":
            return False, "One or more statements allow access to all resources (*)"
    return True, "No wildcard resources found"


def _check_has_condition(raw: str, parsed: Any):
    if not parsed:
        return False, "Could not parse policy"
    for stmt in parsed.get("Statement", []):
        if stmt.get("Effect") == "Allow" and not stmt.get("Condition"):
            return False, "At least one Allow statement is missing a Condition block"
    return True, "All Allow statements include conditions"


def _check_no_full_admin(raw: str, parsed: Any):
    if not parsed:
        return False, "Could not parse policy"
    for stmt in parsed.get("Statement", []):
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]
        if "*" in action and "*" in resource and stmt.get("Effect") == "Allow":
            return False, "Policy grants full administrator access (Action:* Resource:*)"
    return True, "No full administrator access detected"


def _check_cloudtrail_has_user_identity(raw: str, parsed: Any):
    if not parsed:
        return False, "Could not parse CloudTrail log"
    events = parsed if isinstance(parsed, list) else parsed.get("Records", [parsed])
    for event in events:
        if not event.get("userIdentity"):
            return False, "One or more events are missing userIdentity"
    return True, "All events contain userIdentity"


def _check_cloudtrail_no_root_usage(raw: str, parsed: Any):
    if not parsed:
        return False, "Could not parse CloudTrail log"
    events = parsed if isinstance(parsed, list) else parsed.get("Records", [parsed])
    for event in events:
        identity = event.get("userIdentity", {})
        if identity.get("type") == "Root":
            return False, f"Root account activity detected: {event.get('eventName', 'unknown')}"
    return True, "No root account activity detected"


def _check_cloudtrail_mfa_used(raw: str, parsed: Any):
    if not parsed:
        return False, "Could not parse CloudTrail log"
    events = parsed if isinstance(parsed, list) else parsed.get("Records", [parsed])
    for event in events:
        ctx = event.get("requestParameters", {}) or {}
        mfa = event.get("additionalEventData", {}) or {}
        if mfa.get("mfaUsed") == "No":
            return False, "At least one event was performed without MFA"
    return True, "MFA usage not flagged in provided events"


def _check_finding_has_severity(raw: str, parsed: Any):
    if not parsed:
        return "Severity" in raw or "severity" in raw, "Parsed as plain text"
    return bool(parsed.get("severity") or parsed.get("Severity")), "Severity field present"


def _check_finding_has_remediation(raw: str, parsed: Any):
    keywords = ["remediat", "fix", "mitigat", "recommend"]
    found = any(k in raw.lower() for k in keywords)
    return found, "Remediation guidance present" if found else "No remediation guidance found"


def _check_incident_has_timeline(raw: str, parsed: Any):
    keywords = ["time", "timestamp", "when", "occurred", "detected"]
    found = any(k in raw.lower() for k in keywords)
    return found, "Timeline information present" if found else "No timeline information found"


def _check_incident_has_affected_resources(raw: str, parsed: Any):
    keywords = ["resource", "instance", "bucket", "role", "account", "arn"]
    found = any(k in raw.lower() for k in keywords)
    return found, "Affected resources mentioned" if found else "No affected resources mentioned"


# ---------------------------------------------------------------------------
# Check registry per input type
# ---------------------------------------------------------------------------

_IAM_CHECKS = [
    {"name": "No wildcard actions", "severity": "HIGH", "fn": _check_no_wildcard_action},
    {"name": "No wildcard resources", "severity": "HIGH", "fn": _check_no_wildcard_resource},
    {"name": "No full admin access", "severity": "CRITICAL", "fn": _check_no_full_admin},
    {"name": "All Allow statements have conditions", "severity": "MEDIUM", "fn": _check_has_condition},
]

_CLOUDTRAIL_CHECKS = [
    {"name": "Events contain userIdentity", "severity": "MEDIUM", "fn": _check_cloudtrail_has_user_identity},
    {"name": "No root account usage", "severity": "HIGH", "fn": _check_cloudtrail_no_root_usage},
    {"name": "MFA used for sensitive actions", "severity": "HIGH", "fn": _check_cloudtrail_mfa_used},
]

_FINDING_CHECKS = [
    {"name": "Finding includes severity", "severity": "LOW", "fn": _check_finding_has_severity},
    {"name": "Finding includes remediation", "severity": "MEDIUM", "fn": _check_finding_has_remediation},
]

_INCIDENT_CHECKS = [
    {"name": "Incident includes timeline", "severity": "MEDIUM", "fn": _check_incident_has_timeline},
    {"name": "Incident identifies affected resources", "severity": "HIGH", "fn": _check_incident_has_affected_resources},
]

_CHECK_REGISTRY = {
    "iam_policy": _IAM_CHECKS,
    "cloudtrail": _CLOUDTRAIL_CHECKS,
    "security_finding": _FINDING_CHECKS,
    "incident": _INCIDENT_CHECKS,
}


def _get_checks(input_type: str) -> list[dict]:
    return _CHECK_REGISTRY.get(input_type, [])
