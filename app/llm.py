def call_llm(prompt: str, user_input: str) -> str:
    """
    Mock LLM response for local development.
    This simulates a GenAI model such as Amazon Bedrock.
    """

    return f"""
Summary:
The provided input suggests a potential cloud security misconfiguration.

Risk Level:
MEDIUM

Why This Matters:
Overly permissive or misconfigured cloud resources can increase the attack surface
and raise the risk of unauthorized access.

Recommended Actions:
Review the configuration against least privilege principles and ensure proper
logging and monitoring are enabled.

Limitations Disclaimer:
This analysis is advisory only and is based solely on the provided input.
"""
