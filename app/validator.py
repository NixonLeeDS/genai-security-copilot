MAX_INPUT_LENGTH = 4000

def validate_input(input_type: str, content: str):
    allowed_types = [
        "iam_policy",
        "cloudtrail",
        "security_finding",
        "incident"
    ]

    if input_type not in allowed_types:
        raise ValueError("Unsupported input type")

    if not content or len(content) > MAX_INPUT_LENGTH:
        raise ValueError("Invalid input length")
