from pydantic import BaseModel

class AnalyzeRequest(BaseModel):
    input_type: str
    content: str
