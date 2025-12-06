import json
import os
from dotenv import load_dotenv
from huggingface_hub import InferenceClient

load_dotenv()
HF_Key = os.getenv("HF_Key")

def extract_json_block(raw: str) -> str:
    """Extract the first top-level JSON object."""
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found.")
    return raw[start:end+1]

# ====== PASTE YOUR FULL PROMPT HERE ======
# It must accept {sysmon_logs} and {asset_map_json} as placeholders.
PROMPT = r'''You are a cybersecurity blast radius analyzer. Analyze the following Sysmon logs and full asset map to output a JSON assessment in the exact schema specified.

### Rules:
- Output ONLY a JSON object. First char: {{, last char: }}.
- Use real attack reasoning: credential theft, lateral movement, admin reuse.
- "primary_compromised" = hosts with direct log evidence.
- All other at-risk hosts must be justified using the asset map.
- Use ISO8601 for detected_at (earliest timestamp in logs).

### Schema:
{{
  "incident_id": "string",
  "summary": "string",
  "severity": "critical|high|medium|low",
  "detected_at": "ISO8601",
  "primary_compromised": ["IPs"],
  "affected_hosts": [
    {{
      "ip": "string",
      "status": "at_risk",
      "risk_level": "critical|high|medium|low",
      "risk_of_subsequent_compromise": "critical|high|medium_high|medium|low",
      "reason": "string",
      "likely_vectors": ["string"],
      "affected_ports": [number],
      "tags": ["string"]
    }}
  ]
}}

### Input:
--- SYSMON LOGS ---
{sysmon_logs}
--- END LOGS ---

--- FULL ASSET MAP (JSON) ---
{asset_map_json}
--- END ASSET MAP ---

Now output ONLY the JSON.
'''

# =========================================
def analyze_perimeter_logs(logpath, assetpath) :
    # Read raw files
    with open(logpath, "r", encoding="utf-8") as f:
        sysmon_logs = f.read()

    with open(assetpath, "r", encoding="utf-8") as f:
        asset_map = json.load(f)

    # Format prompt
    asset_json_str = json.dumps(asset_map, separators=(',', ':'))
    full_prompt = PROMPT.format(
        sysmon_logs=sysmon_logs.strip(),
        asset_map_json=asset_json_str
    )

    # Call model
    client = InferenceClient(model="Qwen/Qwen3-32B", token=HF_Key)
    response = client.chat_completion(
        messages=[{"role": "user", "content": full_prompt}],
        max_tokens=4000,
        temperature=0.0,
    )

    # Parse and output
    raw_output = response.choices[0].message.content
    json_str = extract_json_block(raw_output)
    result = json.loads(json_str)
    return result

