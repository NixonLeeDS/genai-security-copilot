from fastapi import FastAPI, HTTPException
from app.validator import validate_input
from app.llm import call_llm
from app.models import AnalyzeRequest


app = FastAPI()

@app.post("/analyze")
def analyze(payload: AnalyzeRequest):
    try:
        validate_input(payload.input_type, payload.content)

        with open("prompts/security_prompt.txt") as f:
            prompt = f.read()

        result = call_llm(prompt, payload.content)
        return {"result": result}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

