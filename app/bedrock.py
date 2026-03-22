import json
import logging

import boto3
from botocore.exceptions import ClientError

from app.config import AWS_REGION, BEDROCK_MODEL_ID, MAX_TOKENS

logger = logging.getLogger(__name__)


def invoke_bedrock(system_prompt: str, user_input: str) -> str:
    """
    Invoke Amazon Bedrock using the Claude Messages API.
    Requires valid AWS credentials and Bedrock model access in the configured region.
    """
    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": MAX_TOKENS,
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": user_input},
        ],
    })

    try:
        response = client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=body,
            contentType="application/json",
            accept="application/json",
        )
        response_body = json.loads(response["body"].read())
        return response_body["content"][0]["text"]

    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        logger.error("Bedrock invocation failed [%s]: %s", code, message)
        raise RuntimeError(f"Bedrock error: {code}") from e
