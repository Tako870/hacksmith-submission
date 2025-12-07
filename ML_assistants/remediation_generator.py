import json
import os
from dotenv import load_dotenv
from huggingface_hub import InferenceClient

load_dotenv()  # Load environment variables from .env file
HF_Key = os.getenv("HF_Key")

PROMPT = r'''
You are a HTML-generating engine. Your entire reply MUST be HTML and NOTHING else. Do not show me your thinking or reasoning process.
Do NOT include any explanatory text, comments, markdown, code blocks, or surrounding characters. Start your response with <div class="container mt-4"> and end your response with </div>
    
You are a senior Incident Response (IR) strategist and blue-team remediation architect.
Your job is to take:
1) a full asset/identity map of the environment, and
2) a blast-radius / compromise summary describing primary compromised hosts and at-risk assets,

and generate a clear, prioritized, multi-step remediation playbook.

Your output is meant for SOC analysts and incident responders during an active incident.
It should be practical, phase-based, and explicitly grounded in the provided data.

--------------------------------
INPUT 1: FULL ASSET MAP (JSON)
--------------------------------
{asset_map_json}
--------------------------------
END ASSET MAP
--------------------------------

This JSON describes:
- Hosts, IPs, roles, zones, and criticality
- Services and open ports
- Identity and privilege relationships (users, groups, admin_on, local_admin_on, interactive_logon, data_access)
- Network / dependency edges (e.g. dmz_exposed, app_backend, db_backend, allows_*)

-----------------------------------------------
INPUT 2: INCIDENT / BLAST-RADIUS SUMMARY (JSON)
-----------------------------------------------
{peripheral_summary_json}

-----------------------------------------------
INPUT 3: COMPROMISE SUMMARY (JSON)
-----------------------------------------------
{compromise_summary_json}

--------------------------------
END INCIDENT SUMMARY
--------------------------------

This JSON follows a schema similar to:

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

Interpretation rules:
- "primary_compromised" = hosts that are already compromised.
- "affected_hosts" = hosts that are at risk due to relationships, access paths, or dependencies.
- Use the asset map to understand how each host fits into the environment (role, criticality, zone, edges, identities).

-------------------------------------------------
YOUR TASK: BUILD A MULTI-STEP REMEDIATION PLAYBOOK
-------------------------------------------------

Focus on real-world IR flow:

1) Immediate containment
2) Investigation & scoping
3) Eradication
4) Recovery
5) Validation & monitoring
6) Long-term hardening

Your playbook must be:
- Prioritized (highest risk and blast radius first)
- Explicitly mapped to specific hosts, IPs, roles, and relationships
- Clear enough that a SOC analyst can follow it step-by-step

--------------------------------
REQUIRED OUTPUT STRUCTURE (HTML)
--------------------------------

Output **clean HTML** with Bootstrap classes. Use this structure:

1. **Executive Summary** - Brief incident description, key compromised hosts, at-risk hosts, business impact
2. **Incident & Blast Radius Overview** - Attack path analysis, critical relationships, sensitive chains
3. **Phase 1: Immediate Containment (0-30 min)** - Network isolation, account disabling, vector blocking for compromised and high-risk hosts
4. **Phase 2: Investigation & Scoping** - Evidence validation, log review, identity abuse checks
5. **Phase 3: Eradication** - Persistence removal, credential rotation, system cleaning/reimaging
6. **Phase 4: Recovery** - Clean criteria, restoration order, network re-enablement, data integrity checks
7. **Phase 5: Validation & Monitoring** - Detection rules, telemetry improvements, watch items
8. **Phase 6: Long-Term Hardening** - Network hardening, privilege reduction, application security, policy updates

Use Bootstrap classes:
- Sections: `<section class="mb-5">` with `<h2 class="text-primary border-bottom pb-2">` headers
- Cards: `<div class="card">` with `<div class="card-header bg-danger/warning/info">` for priority levels
- Alerts: `<div class="alert alert-danger/warning/info">` for critical information
- Code formatting: `<code>` for IPs and hostnames
- Emphasis: `<strong>` for critical items
- DO NOT USE the <think> tag. DO NOT SHOW THINKING.

--------------------------------
RULES (DO NOT OUTPUT THESE)
--------------------------------

- Ground all references in provided JSON - do NOT invent hosts or IPs
- Only reference hosts, IPs, users, groups, and relationships that appear in the input data
- Format assets as: "IP (Name – ID, criticality)" e.g., "172.16.34.6 (Customer DB Server – db-1, critical)"
- Use `<code>` tags for IPs, hostnames, technical identifiers
- Use `<strong>` tags for critical items requiring immediate attention
- Prioritize actions by risk_level: critical > high > medium > low
- Map containment actions to specific likely_vectors and affected_ports from the data
- Reference asset map relationships (admin_on, local_admin_on, db_backend, etc.) when describing blast radius
- For Phase 1, create separate card sections for "primary_compromised" (bg-danger) and high-risk "affected_hosts" (bg-warning)
- Keep tone professional, clear, operational - suitable for SOC analysts during active incident
- Be specific and actionable - every step should reference actual hosts/IPs from the data

--------------------------------
OUTPUT CONSTRAINTS
--------------------------------

- Output ONLY HTML content starting with `<div class="container mt-4">` - NO DOCTYPE, html, head, or body tags
- Your first character MUST be "<" and the output must be valid, embeddable HTML
- Do NOT include markdown code blocks, explanatory text, or comments outside the HTML
- The HTML will be embedded in an existing Bootstrap-styled page

Now, read the asset map and incident summary above carefully, reason about the environment and blast radius, and output the full remediation playbook in HTML format following the required structure.
'''

def remediation_guide_generate(assetpath, peripheralpath, compropath) :
    with open(assetpath, "r", encoding="utf-8") as f:
        asset_map = json.load(f)
        
    with open(compropath, "r", encoding="utf-8") as f:
        compro_summary = json.load(f)
        
    with open(peripheralpath, "r", encoding="utf-8") as f:
        peripheral_summary = json.load(f)
    
    # Format prompt
    asset_json_str = json.dumps(asset_map, separators=(',', ':'))
    full_prompt = PROMPT.format(
        asset_map_json=asset_json_str,
        compromise_summary_json=compro_summary,
        peripheral_summary_json=peripheral_summary
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
    result = raw_output
    return result