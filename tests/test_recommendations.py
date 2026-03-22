import json
from fastapi.testclient import TestClient
from app.main import app
from app.recommender import generate_iam_recommendations

client = TestClient(app)

WILDCARD_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}
    ]
})

SCOPED_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "ap-southeast-1"}}
        }
    ]
})


def test_wildcard_policy_returns_high_risk():
    recs = generate_iam_recommendations(WILDCARD_POLICY)
    risks = [r["risk"] for r in recs]
    assert "HIGH" in risks


def test_scoped_policy_no_high_risk():
    recs = generate_iam_recommendations(SCOPED_POLICY)
    risks = [r["risk"] for r in recs]
    assert "HIGH" not in risks


def test_invalid_json_returns_unknown():
    recs = generate_iam_recommendations("not json")
    assert recs[0]["risk"] == "UNKNOWN"


def test_recommendations_endpoint():
    response = client.post("/recommendations", json={"policy": WILDCARD_POLICY})
    assert response.status_code == 200
    body = response.json()
    assert "recommendations" in body
    assert len(body["recommendations"]) > 0


def test_recommendations_each_has_required_fields():
    response = client.post("/recommendations", json={"policy": WILDCARD_POLICY})
    for rec in response.json()["recommendations"]:
        assert "finding" in rec
        assert "risk" in rec
        assert "recommendation" in rec
