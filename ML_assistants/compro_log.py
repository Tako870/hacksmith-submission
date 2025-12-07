import json
import os
from dotenv import load_dotenv
from huggingface_hub import InferenceClient

load_dotenv()  # Load environment variables from .env file
HF_Key = os.getenv("HF_Key")

def extract_json_block(raw: str) -> str:
    """
    Return the substring from the first '{' to the last '}'.
    Raises ValueError if braces are missing.
    """
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in the response.")
    return raw[start:end+1]

def analyze_sysmon_logs(sysmon_xml: str, hf_token: str) -> dict:
    """
    Sends Sysmon logs to Qwen via Hugging Face Inference API and returns parsed JSON.
    """
    # Initialize client
    client = InferenceClient(
        model="Qwen/Qwen3-32B",
        token=hf_token
    )

    # Define the instruction prompt (without logs)
    base_prompt = r'''You are a JSON-generating engine. Your entire reply MUST be a single JSON object and NOTHING else. Do not show me your thinking or reasoning process.
    Do NOT include any explanatory text, comments, markdown, code blocks, or surrounding characters.
    Your first character MUST be "{" and your last character MUST be "}".

    Analyze the provided Sysmon logs using behavioral reasoning to determine:
    - Which host is compromised (if any),
    - Which hosts are at risk due to connectivity or dependency,
    - Lateral movement indicators,
    - Potential data access impact.

    Output ONLY a JSON object matching this exact schema:

    {
    "incident_id": "string",
    "summary": "string",
    "severity": "string",
    "detected_at": "ISO8601 timestamp",
    "affected_hosts": [
        {
        "ip": "string",
        "status": "compromised|at_risk|suspicious",
        "risk_level": "critical|high|medium|low",
        "reason": "string",
        "affected_ports": [number],
        "tags": ["string"]
        }
    ]
    }

    Rules (DO NOT OUTPUT THESE):
    - Use only the IPs and timestamps from the logs. These are in the SourceIp and DestinationIp tags.
    - The earliest event time is the detection time.
    - Only include hosts that appear in the logs.
    - THE LOGS ARE IN THE XML BELOW.

    Now analyze these logs and output ONLY the JSON:
    '''

    # Combine prompt + dynamic logs
    full_prompt = base_prompt + sysmon_xml

    # Call model
    response = client.chat_completion(
        messages=[{"role": "user", "content": full_prompt}],
        max_tokens=2000,
        temperature=0.0,  # Use 0.0 for deterministic output
    )
    
    cleaned = extract_json_block(response.choices[0].message.content.strip())
    raw_output = cleaned
    # Attempt to parse JSON
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        # If parsing fails, raise error with raw output for debugging
        raise ValueError(f"Model did not return valid JSON. Raw output:\n{raw_output}")