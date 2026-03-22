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
