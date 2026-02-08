from fastapi import FastAPI, HTTPException
from app.validator import validate_input
from app.llm import call_llm

app = FastAPI()

@app.post("/analyze")
def analyze(payload: dict):
    try:
        input_type = payload.get("input_type")
        content = payload.get("content")

        validate_input(input_type, content)

        with open("prompts/security_prompt.txt") as f:
            prompt = f.read()

        result = call_llm(prompt, content)
        return {"result": result}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
