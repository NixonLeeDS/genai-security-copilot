from validator import validate_input
from llm import call_llm

def analyze(input_type: str, content: str) -> str:
    validate_input(input_type, content)

    with open("prompts/security_prompt.txt") as f:
        prompt = f.read()

    return call_llm(prompt, content)

if __name__ == "__main__":
    result = analyze("iam_policy", "Policy allows full access to all resources")
    print(result)
