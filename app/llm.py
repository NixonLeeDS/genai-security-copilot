_MOCK_RESPONSES = {
    "iam_policy": """\
Summary:
The provided IAM policy contains overly broad permissions. One or more statements
use wildcard actions ('*') or wildcard resources ('*'), which violates the principle
of least privilege and significantly expands the blast radius of any credential compromise.

Risk Level:
HIGH

Why This Matters:
A principal granted Action:* on Resource:* has full administrative access to your AWS
account. If these credentials are leaked or a role is assumed by an attacker, they can
exfiltrate data, create backdoor users, or destroy infrastructure. AWS Security Hub and
CIS AWS Foundations Benchmark both flag this as a critical control failure.

Recommended Actions:
1. Replace wildcard actions with the minimum required permission set (e.g., s3:GetObject instead of s3:*).
2. Scope Resource to specific ARNs — never use '*' for production workloads.
3. Add Condition blocks to restrict access by IP, MFA status, or requested region.
4. Run IAM Access Analyzer to identify unused permissions and generate least-privilege policies.
5. Enable AWS CloudTrail and set alerts for IAM policy changes.

Limitations Disclaimer:
This analysis is advisory only and based solely on the provided input. It does not
account for SCPs, permission boundaries, or runtime context. Validate all changes
in a non-production environment before applying to production.
""",

    "cloudtrail": """\
Summary:
The CloudTrail log entries indicate authentication and API activity across your AWS
environment. Several events warrant closer review, including actions performed by
privileged identities and API calls originating from unfamiliar IP ranges.

Risk Level:
MEDIUM

Why This Matters:
CloudTrail is the primary audit trail for AWS API activity. Anomalous patterns — such
as root account usage, API calls from unexpected regions, or a spike in failed
authentication attempts — are common indicators of credential misuse or an active
intrusion attempt. Undetected, these can lead to data exfiltration or privilege escalation.

Recommended Actions:
1. Investigate any root account activity immediately — root should not be used for routine operations.
2. Cross-reference source IP addresses against known corporate egress ranges.
3. Enable GuardDuty to automatically correlate CloudTrail events with threat intelligence feeds.
4. Set CloudWatch alarms for: console logins without MFA, IAM policy changes, and S3 bucket policy changes.
5. Ensure CloudTrail logs are delivered to an immutable S3 bucket with Object Lock enabled.

Limitations Disclaimer:
This analysis is advisory only and based solely on the provided log sample. A full
investigation should include correlation across VPC Flow Logs, DNS logs, and any
relevant SIEM alerts.
""",

    "security_finding": """\
Summary:
The submitted security finding describes a potential vulnerability or misconfiguration
in your cloud environment. Based on the details provided, this appears to involve
insufficient access controls or an exposed service that could be exploited by
an external or internal threat actor.

Risk Level:
MEDIUM

Why This Matters:
Unresolved security findings compound over time — individually they may appear low
severity, but in combination they can form an exploitable attack chain. Many high-profile
cloud breaches began with a single unpatched misconfiguration that allowed lateral movement.

Recommended Actions:
1. Triage the finding against your asset inventory to confirm scope and impact.
2. Apply the suggested remediation within your defined SLA for the stated severity.
3. Verify the fix by re-running the originating scanner or audit rule.
4. Document the finding, remediation steps, and closure evidence in your tracking system.
5. Consider whether the root cause indicates a systemic gap (e.g., missing guardrails in IaC pipelines).

Limitations Disclaimer:
This analysis is advisory only. Remediation priority should be determined by your
organisation's risk tolerance, asset criticality, and threat model.
""",

    "incident": """\
Summary:
The submitted incident report describes a potential security event in progress or
recently concluded. The details indicate possible unauthorised access or abnormal
behaviour affecting cloud resources. Immediate containment and investigation are advised.

Risk Level:
HIGH

Why This Matters:
Active security incidents can escalate rapidly in cloud environments due to the
ephemeral and interconnected nature of cloud resources. Delayed response increases
the risk of data exfiltration, lateral movement to additional accounts or services,
and reputational damage. Mean Time to Contain (MTTC) is a critical metric in
cloud incident response.

Recommended Actions:
1. Immediately isolate affected resources — revoke exposed credentials, detach suspicious IAM roles.
2. Preserve evidence: take snapshots of affected EC2 instances and export relevant CloudTrail logs before remediation.
3. Engage your incident response runbook and notify relevant stakeholders per your escalation policy.
4. Identify the initial access vector and patch or remediate it before restoring services.
5. Conduct a post-incident review to document timeline, root cause, and preventive controls.

Limitations Disclaimer:
This analysis is advisory only and based on the provided incident description. Active
incidents require human judgement and should involve your security operations team.
Do not rely solely on this output for containment decisions.
""",
}

_DEFAULT_RESPONSE = """\
Summary:
The provided input suggests a potential cloud security concern.

Risk Level:
MEDIUM

Why This Matters:
Misconfigurations and undetected security gaps can increase the attack surface
of your cloud environment and raise the risk of unauthorised access or data loss.

Recommended Actions:
Review the input against least privilege principles and ensure that logging,
monitoring, and alerting are enabled for the affected resources.

Limitations Disclaimer:
This analysis is advisory only and is based solely on the provided input.
"""


def call_llm(prompt: str, user_input: str, input_type: str = "") -> str:
    """
    Mock LLM response for local development.
    Returns input-type-aware responses to simulate a GenAI model (e.g. Amazon Bedrock).
    """
    return _MOCK_RESPONSES.get(input_type, _DEFAULT_RESPONSE)
