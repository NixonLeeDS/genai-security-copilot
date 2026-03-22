import os

# Set USE_MOCK=false to enable live Amazon Bedrock calls.
# Defaults to true for local development.
USE_MOCK: bool = os.getenv("USE_MOCK", "true").lower() == "true"

AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID: str = os.getenv(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
)
MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "1024"))
