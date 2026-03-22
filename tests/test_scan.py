import json
from fastapi.testclient import TestClient
from app.main import app
from app.scanner import scan_security_posture

client = TestClient(app)

FULL_ADMIN_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
})

SCOPED_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::my-bucket/*",
        "Condition": {"StringEquals": {"aws:RequestedRegion": "ap-southeast-1"}}
    }]
})

CLOUDTRAIL_WITH_ROOT = json.dumps({
    "Records": [
        {"userIdentity": {"type": "Root"}, "eventName": "ConsoleLogin"}
    ]
})

CLOUDTRAIL_CLEAN = json.dumps({
    "Records": [
        {"userIdentity": {"type": "IAMUser", "userName": "alice"}, "eventName": "GetObject"}
    ]
})


def test_full_admin_policy_is_poor():
    report = scan_security_posture("iam_policy", FULL_ADMIN_POLICY)
    assert report["posture"] == "POOR"


def test_scoped_policy_passes_all_checks():
    report = scan_security_posture("iam_policy", SCOPED_POLICY)
    assert report["posture"] == "GOOD"


def test_cloudtrail_root_usage_fails():
    report = scan_security_posture("cloudtrail", CLOUDTRAIL_WITH_ROOT)
    root_check = next(f for f in report["findings"] if "root" in f["check"].lower())
    assert not root_check["passed"]


def test_cloudtrail_clean_passes():
    report = scan_security_posture("cloudtrail", CLOUDTRAIL_CLEAN)
    assert report["score"] > 0


def test_scan_endpoint_returns_correct_shape():
    response = client.post("/scan", json={"input_type": "iam_policy", "content": FULL_ADMIN_POLICY})
    assert response.status_code == 200
    body = response.json()
    assert "posture" in body
    assert "score" in body
    assert "findings" in body
    assert isinstance(body["findings"], list)


def test_scan_endpoint_invalid_type():
    response = client.post("/scan", json={"input_type": "bad_type", "content": "x"})
    assert response.status_code == 400


def test_scan_score_between_0_and_100():
    report = scan_security_posture("iam_policy", FULL_ADMIN_POLICY)
    assert 0 <= report["score"] <= 100
