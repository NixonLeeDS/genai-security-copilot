from app.llm import call_llm

INPUT_TYPES = ["iam_policy", "cloudtrail", "security_finding", "incident"]


def test_call_llm_returns_string():
    result = call_llm("system prompt", "user input")
    assert isinstance(result, str)


def test_call_llm_contains_expected_sections():
    result = call_llm("system prompt", "check this IAM policy")
    assert "Summary" in result
    assert "Risk Level" in result
    assert "Recommended Actions" in result
    assert "Limitations Disclaimer" in result


def test_call_llm_nonempty():
    result = call_llm("system prompt", "user input")
    assert len(result.strip()) > 0


def test_each_input_type_returns_unique_response():
    responses = [call_llm("prompt", "content", input_type=t) for t in INPUT_TYPES]
    assert len(set(responses)) == len(INPUT_TYPES), "Each input type should return a distinct response"


def test_iam_policy_response_mentions_least_privilege():
    result = call_llm("prompt", "content", input_type="iam_policy")
    assert "least privilege" in result.lower()


def test_cloudtrail_response_mentions_guardduty():
    result = call_llm("prompt", "content", input_type="cloudtrail")
    assert "guardduty" in result.lower()


def test_incident_response_risk_is_high():
    result = call_llm("prompt", "content", input_type="incident")
    assert "HIGH" in result


def test_unknown_input_type_returns_default():
    result = call_llm("prompt", "content", input_type="unknown_type")
    assert "Summary" in result
    assert len(result.strip()) > 0
