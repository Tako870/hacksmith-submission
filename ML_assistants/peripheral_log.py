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
PROMPT = r'''You are a cybersecurity blast radius analyzer. Your job is not to re-describe the primary detection, but to reason about peripheral blast radius: which other assets become at risk given the observed activity and the environment/identity graph.

Analyze the following Sysmon logs and full asset map to output a JSON assessment in the exact schema specified.

Intent / Focus

Treat the logs as evidence of one or more primary compromised hosts.

Your main task is to identify peripheral / downstream at-risk hosts using:

network relationships (e.g. db_backend, user_http_access, allows_*)

identity relationships (member_of, admin_on, local_admin_on, interactive_logon, data_access)

service dependencies (e.g. app ↔ DB, workstation ↔ fileshare)

Use real attack reasoning: credential theft, lateral movement, admin credential reuse, data access, identity pivot paths, and cross-subnet spread.

Rules:

Output ONLY a JSON object. First char: {open_brace}, last char: {close_brace}.

Use realistic attack chains, for example:

stolen workstation user creds → local admin on servers → DB or file server access

Domain Admin / server admin paths via member_of + admin_on/local_admin_on

user → group → host paths for interactive logon and data access

"primary_compromised" = hosts with direct log evidence of suspicious/malicious activity:

e.g., suspicious PowerShell, process access, network connections to sensitive services, etc.

These should be derived directly from the Sysmon logs.

"affected_hosts" = peripheral / indirectly impacted hosts only:

Do not repeat "primary_compromised" hosts inside "affected_hosts".

Every at-risk host must be justified using paths/relationships from the asset map.

Each host should have:

explanation of why it is at risk given the primary compromise

expected / likely vector (e.g., RDP with stolen admin creds, SMB lateral movement, SQL access)

relevant ports from the asset map.

detected_at = the earliest timestamp found in the Sysmon logs, formatted as ISO8601 (UTC).

Schema (must match exactly):

{open_brace} 
"incident_id": "string",
"summary": "string",
"severity": "critical|high|medium|low",
"detected_at": "ISO8601",
"primary_compromised": ["IPs"],
"affected_hosts": [
    {open_brace}
    "ip": "string",
    "status": "at_risk",
    "risk_level": "critical|high|medium|low",
    "risk_of_subsequent_compromise": "critical|high|medium_high|medium|low",
    "reason": "string",
    "likely_vectors": ["string"],
    "affected_ports": [number],
    "tags": ["string"]
    {close_brace}
]
{close_brace}

Reasoning Guidelines:

Use hostnames, IPs, and identity info from the logs to map to nodes in the asset map:

e.g. Computer, SourceHostname, DestinationHostname, User like CORP\alice → user-alice → groups → hosts.

From each primary compromised host/IP:

Walk the graph via edges such as:

admin_on, local_admin_on, interactive_logon, data_access

application/data paths like db_backend, user_fileshare_access, business_app_access

network perimeter edges like allows_*, dmz_exposed

For each peripheral host, describe why it is at risk in terms of:

which credentials or identities might be stolen,

which paths/edges in the asset map connect it to a primary compromised host,

what the likely attacker goal would be (e.g., data theft, ransomware spread, email abuse).

Input:

--- SYSMON LOGS ---
{sysmon_logs}
--- END LOGS ---

--- FULL ASSET MAP (JSON) ---
{asset_map_json}
--- END ASSET MAP ---

Now output ONLY the JSON object in the schema above.
'''

# =========================================
def analyze_perimeter_logs(logpath, assetpath) :
    # Read raw files
    with open(logpath, "r", encoding="utf-8") as f:
        sysmon_logs = f.read()

    with open(assetpath, "r", encoding="utf-8") as f:
        asset_map = json.load(f)

    # Format prompt with actual data
    asset_json_str = json.dumps(asset_map, separators=(',', ':'))
    full_prompt = PROMPT.format(
        open_brace='{',
        close_brace='}',
        sysmon_logs=sysmon_logs.strip(),
        asset_map_json=asset_json_str
    )
    
    print(full_prompt)

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

