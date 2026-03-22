from app.llm import call_llm


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
