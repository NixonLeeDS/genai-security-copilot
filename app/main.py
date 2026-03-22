import logging
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from app.validator import validate_input
from app.llm import call_llm
from app.models import AnalyzeRequest, RecommendRequest, RecommendResponse, Recommendation
from app.recommender import generate_iam_recommendations

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="GenAI Security Copilot", version="0.1.0")


@app.get("/health")
def health():
    logger.info("Health check requested")
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/analyze")
def analyze(payload: AnalyzeRequest):
    logger.info("Analyze request received: input_type=%s", payload.input_type)
    try:
        validate_input(payload.input_type, payload.content)

        with open("prompts/security_prompt.txt") as f:
            prompt = f.read()

        result = call_llm(prompt, payload.content)
        logger.info("Analysis complete: input_type=%s", payload.input_type)
        return {"result": result}

    except ValueError as e:
        logger.warning("Validation failed: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Unexpected error during analysis: %s", str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/recommendations", response_model=RecommendResponse)
def recommendations(payload: RecommendRequest):
    logger.info("Recommendations request received")
    try:
        raw = generate_iam_recommendations(payload.policy)
        items = [Recommendation(**r) for r in raw]
        logger.info("Generated %d recommendations", len(items))
        return RecommendResponse(recommendations=items)
    except Exception as e:
        logger.error("Error generating recommendations: %s", str(e))
        raise HTTPException(status_code=500, detail="Internal server error")

