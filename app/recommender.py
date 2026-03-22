import json
import logging

logger = logging.getLogger(__name__)

# Patterns that indicate overly permissive IAM configurations
_WILDCARD_ACTION = "*"
_WILDCARD_RESOURCE = "*"


def generate_iam_recommendations(policy_content: str) -> list[dict]:
    """
    Parse an IAM policy document and return a list of remediation recommendations.
    Each recommendation contains a finding, risk level, and suggested fix.
    """
    recommendations = []

    try:
        policy = json.loads(policy_content)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Policy content is not valid JSON; returning generic recommendations")
        return [
            {
                "finding": "Policy could not be parsed as JSON",
                "risk": "UNKNOWN",
                "recommendation": "Ensure the policy is a valid IAM JSON document before analysis.",
            }
        ]

    statements = policy.get("Statement", [])
    if not statements:
        return [
            {
                "finding": "No statements found in policy",
                "risk": "LOW",
                "recommendation": "Verify the policy structure includes at least one Statement block.",
            }
        ]

    for idx, statement in enumerate(statements):
        effect = statement.get("Effect", "")
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        conditions = statement.get("Condition", {})

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        label = f"Statement[{idx}]"

        # Wildcard action
        if _WILDCARD_ACTION in actions and effect == "Allow":
            recommendations.append({
                "finding": f"{label}: Action is set to '*' (allow all)",
                "risk": "HIGH",
                "recommendation": (
                    "Replace wildcard action with the minimum set of actions required. "
                    "Use IAM Access Analyzer to identify which actions are actually used."
                ),
            })

        # Wildcard resource
        if _WILDCARD_RESOURCE in resources and effect == "Allow":
            recommendations.append({
                "finding": f"{label}: Resource is set to '*' (all resources)",
                "risk": "HIGH",
                "recommendation": (
                    "Scope the resource to specific ARNs. For example, restrict S3 access "
                    "to a specific bucket ARN rather than allowing access to all resources."
                ),
            })

        # Allow without condition
        if effect == "Allow" and not conditions:
            recommendations.append({
                "finding": f"{label}: Allow statement has no conditions",
                "risk": "MEDIUM",
                "recommendation": (
                    "Add conditions such as aws:MultiFactorAuthPresent, aws:RequestedRegion, "
                    "or aws:SourceIp to restrict when and where permissions apply."
                ),
            })

    if not recommendations:
        recommendations.append({
            "finding": "No obvious misconfigurations detected",
            "risk": "LOW",
            "recommendation": (
                "Run AWS IAM Access Analyzer for a deeper unused-access review and "
                "validate against your organization's SCPs."
            ),
        })

    return recommendations
