import pytest
from app.validator import validate_input


VALID_TYPES = ["iam_policy", "cloudtrail", "security_finding", "incident"]


def test_valid_input_types():
    for input_type in VALID_TYPES:
        validate_input(input_type, "some security content")


def test_invalid_input_type():
    with pytest.raises(ValueError, match="Unsupported input type"):
        validate_input("unknown_type", "some content")


def test_empty_content():
    with pytest.raises(ValueError):
        validate_input("iam_policy", "")


def test_content_exceeds_max_length():
    long_content = "a" * 4001
    with pytest.raises(ValueError):
        validate_input("iam_policy", long_content)


def test_content_at_max_length():
    content = "a" * 4000
    validate_input("iam_policy", content)
