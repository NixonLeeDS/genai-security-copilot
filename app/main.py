import logging
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from app.validator import validate_input
from app.llm import call_llm
from app.models import (
    AnalyzeRequest,
    RecommendRequest, RecommendResponse, Recommendation,
    ScanRequest, ScanResponse, ScanFinding,
)
from app.recommender import generate_iam_recommendations
from app.scanner import scan_security_posture

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

        result = call_llm(prompt, payload.content, input_type=payload.input_type)
        logger.info("Analysis complete: input_type=%s", payload.input_type)
        return {"result": result}

    except ValueError as e:
        logger.warning("Validation failed: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Unexpected error during analysis: %s", str(e))
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/scan", response_model=ScanResponse)
def scan(payload: ScanRequest):
    logger.info("Scan request received: input_type=%s", payload.input_type)
    try:
        validate_input(payload.input_type, payload.content)
        report = scan_security_posture(payload.input_type, payload.content)
        findings = [ScanFinding(**f) for f in report["findings"]]
        logger.info(
            "Scan complete: input_type=%s posture=%s score=%d",
            payload.input_type, report["posture"], report["score"],
        )
        return ScanResponse(
            input_type=report["input_type"],
            posture=report["posture"],
            score=report["score"],
            checks_passed=report["checks_passed"],
            checks_total=report["checks_total"],
            findings=findings,
        )
    except ValueError as e:
        logger.warning("Validation failed: %s", str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Unexpected error during scan: %s", str(e))
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

