from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    input_type: str
    content: str


class RecommendRequest(BaseModel):
    policy: str


class Recommendation(BaseModel):
    finding: str
    risk: str
    recommendation: str


class RecommendResponse(BaseModel):
    recommendations: list[Recommendation]


class ScanRequest(BaseModel):
    input_type: str
    content: str


class ScanFinding(BaseModel):
    check: str
    passed: bool
    severity: str
    detail: str


class ScanResponse(BaseModel):
    input_type: str
    posture: str
    score: int
    checks_passed: int
    checks_total: int
    findings: list[ScanFinding]
