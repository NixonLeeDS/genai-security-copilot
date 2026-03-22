from unittest.mock import MagicMock, patch

import pytest

import app.bedrock  # ensure module is loaded before patching


def _make_bedrock_response(text: str) -> dict:
    body_mock = MagicMock()
    body_mock.read.return_value = (
        '{"content": [{"text": "' + text + '"}]}'
    ).encode()
    return {"body": body_mock}


@patch("app.bedrock.boto3.client")
def test_invoke_bedrock_returns_text(mock_boto_client):
    mock_client = MagicMock()
    mock_boto_client.return_value = mock_client
    mock_client.invoke_model.return_value = _make_bedrock_response("Risk Level: HIGH")

    result = app.bedrock.invoke_bedrock("system prompt", "user input")

    assert result == "Risk Level: HIGH"
    mock_client.invoke_model.assert_called_once()


@patch("app.bedrock.boto3.client")
def test_invoke_bedrock_passes_correct_model_id(mock_boto_client):
    from app.config import BEDROCK_MODEL_ID

    mock_client = MagicMock()
    mock_boto_client.return_value = mock_client
    mock_client.invoke_model.return_value = _make_bedrock_response("ok")

    app.bedrock.invoke_bedrock("prompt", "input")

    call_kwargs = mock_client.invoke_model.call_args[1]
    assert call_kwargs["modelId"] == BEDROCK_MODEL_ID


@patch("app.bedrock.boto3.client")
def test_invoke_bedrock_raises_on_client_error(mock_boto_client):
    from botocore.exceptions import ClientError

    mock_client = MagicMock()
    mock_boto_client.return_value = mock_client
    mock_client.invoke_model.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "no access"}},
        "InvokeModel",
    )

    with pytest.raises(RuntimeError, match="Bedrock error"):
        app.bedrock.invoke_bedrock("prompt", "input")


@patch("app.llm.USE_MOCK", False)
@patch("app.bedrock.invoke_bedrock")
def test_call_llm_routes_to_bedrock_when_mock_disabled(mock_invoke):
    mock_invoke.return_value = "live bedrock response"

    from app.llm import call_llm
    result = call_llm("prompt", "input", input_type="iam_policy")

    mock_invoke.assert_called_once_with("prompt", "input")
    assert result == "live bedrock response"


@patch("app.llm.USE_MOCK", True)
def test_call_llm_returns_mock_when_mock_enabled():
    from app.llm import call_llm
    result = call_llm("prompt", "input", input_type="iam_policy")
    assert "least privilege" in result.lower()
