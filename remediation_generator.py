import json
import os
from dotenv import load_dotenv
from huggingface_hub import InferenceClient

load_dotenv()  # Load environment variables from .env file
HF_Key = os.getenv("HF_Key")

PROMPT = r'''
You are a HTML-generating engine. Your entire reply MUST be HTML and NOTHING else. Do not show me your thinking or reasoning process.
Do NOT include any explanatory text, comments, markdown, code blocks, or surrounding characters.
    
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

-----------------------------------------------
INPUT 4: ORIGINAL LOGS (XML)
-----------------------------------------------
{sysmon_logs}

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

Output **clean HTML** with the following sections and structure. Use semantic HTML5 elements, Bootstrap classes for styling, and ensure the output is well-formatted and professional.

The HTML should have this structure:

<div class="container mt-4">
  <h1 class="mb-4">Incident Response Remediation Playbook</h1>
  
  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">1. Executive Summary</h2>
    <p>Brief description of the incident in plain language</p>
    <ul>
      <li><strong>Key compromised hosts:</strong> (from "primary_compromised")</li>
      <li><strong>Key at-risk hosts:</strong> (from "affected_hosts")</li>
      <li><strong>Overall business/technical impact:</strong> referencing critical assets (e.g., DB servers, DC, jump hosts)</li>
    </ul>
  </section>

  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">2. Incident & Blast Radius Overview</h2>
    <p>Describe the blast radius using the asset map:</p>
    <ul>
      <li>How the compromise can move from primary hosts to at-risk hosts</li>
      <li>Important relationships (e.g., admin_on/local_admin_on, db_backend, business_app_access, data_access)</li>
    </ul>
    <div class="alert alert-warning">
      <strong>Critical Attack Chains:</strong>
      <ul>
        <li>Example: compromised workstation → app server → database</li>
        <li>Example: compromised host → jump host → domain controller</li>
      </ul>
    </div>
  </section>

  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">3. Phase 1 – Immediate Containment (0–30 minutes)</h2>
    <div class="card mb-3">
      <div class="card-header bg-danger text-white">
        <strong>Primary Compromised Hosts (by IP, name, role)</strong>
      </div>
      <div class="card-body">
        <ul>
          <li>Isolate from network (how and why)</li>
          <li>Disable or reset involved user accounts / sessions</li>
          <li>Kill or block specific access vectors (RDP, SMB, SQL, VPN) based on likely_vectors and affected_ports</li>
        </ul>
      </div>
    </div>
    <div class="card mb-3">
      <div class="card-header bg-warning">
        <strong>High-Risk At-Risk Hosts (critical/high risk_level)</strong>
      </div>
      <div class="card-body">
        <ul>
          <li>Proactive access restrictions (e.g., temporary firewall rules, NAC, RDP lockdown)</li>
          <li>Elevated logging / alerting</li>
        </ul>
      </div>
    </div>
    <p class="text-muted"><em>Make these steps bullet-pointed, actionable, and clearly reference specific IPs and roles from the data.</em></p>
  </section>

  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">4. Phase 2 – Investigation & Scoping</h2>
    <p>Prioritized checklist for:</p>
    <ul>
      <li>Validating whether each at-risk host shows evidence of compromise</li>
      <li>Reviewing log evidence along likely_vectors (e.g., RDP, SMB, SQL, WinRM)</li>
      <li>Checking identity abuse:
        <ul>
          <li>Which accounts/groups could realistically be compromised?</li>
          <li>Which admin paths (admin_on/local_admin_on/member_of) should be investigated first?</li>
        </ul>
      </li>
    </ul>
    <p class="text-muted"><em>Tie these back to specific hosts from "affected_hosts" and their roles and criticality from the asset map.</em></p>
  </section>

  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">5. Phase 3 – Eradication</h2>
    <p>For each major host group (e.g., workstations, application servers, DB servers, domain controllers, jump hosts):</p>
    <ul>
      <li>Removing persistence mechanisms (if suggested by vectors)</li>
      <li>Rotating credentials and secrets (service accounts, admin accounts)</li>
      <li>Cleaning or reimaging systems where appropriate (call this out explicitly for high/critical risk_level)</li>
    </ul>
    <p class="text-muted"><em>Reference realistic attacker behaviors implied by the likely_vectors and consider impact on downstream assets.</em></p>
  </section>

  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">6. Phase 4 – Recovery</h2>
    <p>How to safely bring systems back into production:</p>
    <ul>
      <li><strong>Criteria for considering a host "clean"</strong></li>
      <li><strong>Order of restoration:</strong> (e.g., domain controller, DB, app server, web, workstations)</li>
      <li><strong>Steps to safely re-enable network access and normal workflows</strong></li>
      <li><strong>Data integrity checks:</strong> for critical data stores (e.g., database servers tagged as critical)</li>
    </ul>
  </section>

  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">7. Phase 5 – Validation & Monitoring</h2>
    <h4>Additional detection rules to deploy:</h4>
    <ul>
      <li>Example: suspicious PowerShell usage, abnormal SQL access from workstations, unauthorized RDP, etc.</li>
    </ul>
    <h4>Telemetry improvements:</h4>
    <ul>
      <li>Logs to enable or retain</li>
      <li>Hosts/zones requiring stricter monitoring</li>
    </ul>
    <h4>Short-term watch items:</h4>
    <ul>
      <li>Specific accounts, hosts, protocols</li>
    </ul>
  </section>

  <section class="mb-5">
    <h2 class="text-primary border-bottom pb-2">8. Phase 6 – Long-Term Hardening & Lessons Learned</h2>
    <h4>Network hardening:</h4>
    <ul>
      <li>Reduce unnecessary exposure (e.g., RDP/SMB/SQL) on high-value hosts</li>
      <li>Improve segmentation between zones (e.g., User ↔ Server ↔ DMZ ↔ HR-FIN)</li>
    </ul>
    <h4>Identity and privilege hardening:</h4>
    <ul>
      <li>Reduce broad admin_on/local_admin_on paths</li>
      <li>Strengthen policies for jump host usage and domain admins</li>
    </ul>
    <h4>Application and data-layer improvements:</h4>
    <ul>
      <li>Hardening guidance for critical DBs, application servers, file servers involved in blast radius</li>
    </ul>
    <h4>Policy/process updates:</h4>
    <ul>
      <li>Improvements to access management, monitoring, IR playbooks</li>
    </ul>
  </section>
</div>

--------------------------------
STYLE & CONSTRAINTS
--------------------------------

- Do **NOT** invent hosts or IPs: always ground references in the provided JSON inputs.
- When referring to assets, use both IP and name/role where available (e.g., "172.16.34.6 (Customer DB Server – db-1, critical)").
- Use <code> tags for IPs, hostnames, and technical identifiers.
- Use <strong> tags for emphasis on critical items.
- Use Bootstrap alert classes (alert-danger, alert-warning, alert-info) for highlighting critical sections.
- Keep the tone professional, clear, and operational.
- Output ONLY the HTML content (the <div class="container"> and its contents). Do NOT include <!DOCTYPE>, <html>, <head>, or <body> tags.
- The HTML will be embedded in an existing Bootstrap-styled page.

Now, read the asset map and incident summary above carefully, reason about the environment and blast radius, and output the full remediation playbook in HTML format following the required structure.
'''

def remediation_guide_generate(assetpath, peripheralpath, compropath, logpath) :
    with open(assetpath, "r", encoding="utf-8") as f:
        asset_map = json.load(f)
        
    with open(logpath, "r", encoding="utf-8") as f:
        sysmon_logs = f.read()
    
    with open(compropath, "r", encoding="utf-8") as f:
        compro_summary = json.load(f)
        
    with open(peripheralpath, "r", encoding="utf-8") as f:
        peripheral_summary = json.load(f)
    
    # Format prompt
    asset_json_str = json.dumps(asset_map, separators=(',', ':'))
    full_prompt = PROMPT.format(
        sysmon_logs=sysmon_logs.strip(),
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