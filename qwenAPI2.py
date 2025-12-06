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
- Use only the IPs and timestamps from the logs.
- The earliest event time is the detection time.
- Only include hosts that appear in the logs: 172.16.34.21 (ws-eng-1) and 172.16.34.6 (db-1).
- PowerShell (PID 816) spawns cmd.exe and accesses it with full privileges (0x1fffff) → strong indicator of malicious activity.
- Network connection from 172.16.34.21 to 172.16.34.6:1433 (MSSQL) → potential data access.
- All activity runs under CORP\alice with High integrity.
- If a host shows process manipulation + outbound DB connection → likely compromised.

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

    
    raw_output = response.choices[0].message.content.strip()
    cleaned = extract_json_block(raw_output)
    raw_output = cleaned

    # Attempt to parse JSON
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        # If parsing fails, raise error with raw output for debugging
        raise ValueError(f"Model did not return valid JSON. Raw output:\n{raw_output}")

# ===== USAGE EXAMPLE =====
if __name__ == "__main__":
    # Example: sysmon_logs comes from another function, file, or API
    with open("sysmon_logs.xml", "r", encoding="utf-8") as f:
        sysmon_xml = f.read()


    try:
        result = analyze_sysmon_logs(
            sysmon_xml=sysmon_xml,
            hf_token=HF_Key  # Ensure HF_Key is defined in your environment or .env file
        )
        print(json.dumps(result, indent=2))
    except Exception as e:
        print("Error:", e)