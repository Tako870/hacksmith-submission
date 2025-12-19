from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from pathlib import Path
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from ML_assistants.compro_log import analyze_sysmon_logs
from ML_assistants.peripheral_log import analyze_perimeter_logs
from ML_assistants.remediation_generator import remediation_guide_generate

app = Flask(__name__)

# Load environment variables from a local .env file if present.
# Prefer python-dotenv when available, fall back to a simple parser.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    env_path = Path('.env')
    if env_path.exists():
        try:
            with env_path.open('r', encoding='utf-8') as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        k, v = line.split('=', 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        os.environ.setdefault(k, v)
        except Exception:
            # If manual .env parsing fails, continue — we'll fall back below.
            pass

# Secret key for session/csrf. Prefer an explicit SecretKey in env/.env.
_secret = os.getenv('SecretKey')
if not _secret:
    # Generate a temporary key for local development to avoid crashes during demo.
    # Warning: ephemeral key means sessions will not persist across restarts.
    import sys
    print('Warning: SecretKey not set in environment or .env; using ephemeral key for dev.', file=sys.stderr)
    _secret = os.urandom(24)

app.secret_key = _secret

# HF API key
HF_Key = os.getenv('HF_Key')

# Path to your asset map JSON file
# Use the JSON structure I sent earlier as asset_map_with_identities.json
ASSET_MAP_PATH = Path("assetmaps/assetMap.json")
LOGS_PATH = "logs/logs.xml"
perimeter_path = Path('logs/perimeterLogs.json')
compro_path = Path("logs/filteredLogs.json")

def load_asset_map():
    """
    Load the asset map JSON from disk.
    Expected structure:
    {
      "metadata": {...},
      "nodes": [...],
      "edges": [...]
    }
    """
    if not ASSET_MAP_PATH.exists():
        # For a hackathon, it's fine to fail loudly, but let's be nice:
        return {"metadata": {}, "nodes": [], "edges": []}

    with ASSET_MAP_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)

def save_asset_map(graph: dict):
    """
    Optional: allow overwriting the asset map via upload,
    if you later want to support that.
    """
    with ASSET_MAP_PATH.open("w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)

# ============================================================================
# LOG INGESTION & PARSING
# ============================================================================

def parse_sysmon_xml(xml_content):
    """
    Parse Windows Sysmon XML log format into canonical events.
    Extracts key fields from Sysmon events and maps to canonical schema.
    """
    canonical_events = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {str(e)}")

    # Sysmon XML namespace
    ns = {'s': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    for event in root.findall('.//s:Event', ns):
        system = event.find('s:System', ns)
        event_data = event.find('s:EventData', ns)

        if system is None or event_data is None:
            continue

        # Extract System fields
        event_id_elem = system.find('s:EventID', ns)
        time_created = system.find('s:TimeCreated', ns)
        computer = system.find('s:Computer', ns)
        security = system.find('s:Security', ns)

        event_id = event_id_elem.text if event_id_elem is not None else "0"
        timestamp = time_created.get('SystemTime') if time_created is not None else datetime.utcnow().isoformat()
        hostname = computer.text if computer is not None else "UNKNOWN"
        user_id = security.get('UserID') if security is not None else "UNKNOWN"

        # Build event data dict from all Data elements
        event_dict = {}
        for data_elem in event_data.findall('s:Data', ns):
            name = data_elem.get('Name')
            text = data_elem.text or ""
            event_dict[name] = text

        # Map Sysmon event types to canonical event schema
        canonical_event = {
            "timestamp": timestamp,
            "hostname": hostname,
            "src_ip": None,
            "dst_ip": None,
            "src_hostname": None,
            "dst_hostname": None,
            "user": None,
            "event_type": None,
            "detector": "sysmon",
            "raw_event": event_dict,
            "severity": "medium"
        }

        # EventID 1: Process Creation
        if event_id == "1":
            canonical_event["event_type"] = "process_creation"
            canonical_event["user"] = event_dict.get("User", "UNKNOWN")
            canonical_event["process_image"] = event_dict.get("Image", "")
            canonical_event["command_line"] = event_dict.get("CommandLine", "")
            canonical_event["parent_image"] = event_dict.get("ParentImage", "")
            # Suspicious process creation chains
            if "powershell" in event_dict.get("Image", "").lower():
                canonical_event["severity"] = "high"

        # EventID 3: Network Connection
        elif event_id == "3":
            canonical_event["event_type"] = "network_connection"
            canonical_event["src_ip"] = event_dict.get("SourceIp", "")
            canonical_event["dst_ip"] = event_dict.get("DestinationIp", "")
            canonical_event["src_hostname"] = event_dict.get("SourceHostname", "")
            canonical_event["dst_hostname"] = event_dict.get("DestinationHostname", "")
            canonical_event["src_port"] = event_dict.get("SourcePort", "")
            canonical_event["dst_port"] = event_dict.get("DestinationPort", "")
            canonical_event["protocol"] = event_dict.get("Protocol", "")
            canonical_event["user"] = event_dict.get("User", "")

        # EventID 10: Process Access
        elif event_id == "10":
            canonical_event["event_type"] = "process_access"
            canonical_event["source_process"] = event_dict.get("SourceImage", "")
            canonical_event["target_process"] = event_dict.get("TargetImage", "")
            canonical_event["granted_access"] = event_dict.get("GrantedAccess", "")
            canonical_event["severity"] = "high"

        # EventID 7: Image Loaded
        elif event_id == "7":
            canonical_event["event_type"] = "image_loaded"
            canonical_event["image"] = event_dict.get("ImageLoaded", "")

        # EventID 8: CreateRemoteThread
        elif event_id == "8":
            canonical_event["event_type"] = "create_remote_thread"
            canonical_event["source_process"] = event_dict.get("SourceImage", "")
            canonical_event["target_process"] = event_dict.get("TargetImage", "")
            canonical_event["severity"] = "critical"

        # EventID 11: File Created
        elif event_id == "11":
            canonical_event["event_type"] = "file_created"
            canonical_event["file_path"] = event_dict.get("TargetFilename", "")

        # EventID 13: Registry Set
        elif event_id == "13":
            canonical_event["event_type"] = "registry_set"
            canonical_event["registry_path"] = event_dict.get("TargetObject", "")

        canonical_events.append(canonical_event)

    return canonical_events

def resolve_assets(event, asset_map):
    """
    Resolve src/dst IPs and hostnames to asset IDs using the provided CMDB.
    Returns the event enriched with asset_id mappings.
    """
    nodes = asset_map.get("nodes", [])
    
    # Build lookup tables
    ip_to_asset = {}
    hostname_to_asset = {}
    
    for node in nodes:
        if node.get("type") == "host":
            if "ip" in node:
                ip_to_asset[node["ip"]] = node["id"]
            if "name" in node:
                hostname_to_asset[node["name"].lower()] = node["id"]

    # Resolve source
    if event.get("src_ip") and event["src_ip"] in ip_to_asset:
        event["src_asset_id"] = ip_to_asset[event["src_ip"]]
    elif event.get("src_hostname"):
        src_host_lower = event["src_hostname"].lower()
        if src_host_lower in hostname_to_asset:
            event["src_asset_id"] = hostname_to_asset[src_host_lower]
        else:
            event["src_asset_id"] = "unknown_asset"
    elif event.get("hostname"):
        host_lower = event["hostname"].lower()
        if host_lower in hostname_to_asset:
            event["src_asset_id"] = hostname_to_asset[host_lower]
        else:
            event["src_asset_id"] = "unknown_asset"

    # Resolve destination
    if event.get("dst_ip") and event["dst_ip"] in ip_to_asset:
        event["dst_asset_id"] = ip_to_asset[event["dst_ip"]]
    elif event.get("dst_hostname"):
        dst_host_lower = event["dst_hostname"].lower()
        if dst_host_lower in hostname_to_asset:
            event["dst_asset_id"] = hostname_to_asset[dst_host_lower]
        else:
            event["dst_asset_id"] = "unknown_asset"

    return event

# -------------------------------- WEB ROUTES -------------------------------- #

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/uploadall', methods=['POST'])
def upload_all():
    """
    Accept both an optional asset map JSON and a required Sysmon XML log file
    in one multipart/form-data request. Process asset map first (if provided),
    then parse logs and resolve assets. Returns a rendered results page.
    """
    # Files
    asset_file = request.files.get('asset_map')
    log_file = request.files.get('log_file')

    if not log_file:
        flash("No log file uploaded", "error")
        return redirect(url_for('index'))

    # If asset map provided, try to load and save it
    if asset_file and asset_file.filename:
        try:
            graph = json.load(asset_file.stream)
            if not isinstance(graph, dict) or "nodes" not in graph or "edges" not in graph:
                flash("Invalid asset map format (missing 'nodes' or 'edges'). Skipped.", "error")
            else:
                save_asset_map(graph)
                flash("Asset map uploaded successfully.", "success")
        except json.JSONDecodeError:
            flash("Uploaded asset map is not valid JSON. Skipped.", "error")

    # Parse log file
    try:
        content = log_file.read()
        if log_file.filename.endswith('.xml'):
            # Save the uploaded log file to LOGS_PATH
            logs_path = Path(LOGS_PATH)
            logs_path.parent.mkdir(parents=True, exist_ok=True)
            with open(logs_path, 'wb') as f:
                f.write(content)
            
            canonical_events = parse_sysmon_xml(content)
        else:
            flash("Unsupported log format. Please upload .xml Sysmon logs.", "error")
            return redirect(url_for('index'))

        
        # Resolve against current asset map
        asset_map = load_asset_map()
        enriched_events = [resolve_assets(e, asset_map) for e in canonical_events]

        # After upload, redirect to the vulnerable map view which will trigger
        # the HF analysis endpoint and highlight compromised/at-risk hosts.
        flash(f"Uploaded and parsed {len(enriched_events)} events.", "success")
        return redirect(url_for('render_map_vuln'))

    except Exception as e:
        flash(f"Error processing log file: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/rendermap')
def render_map():
    """
    Render a webpage that will visualise the asset map.
    The template can use 'nodes' and 'edges' directly,
    or fetch /api/assetmap via JavaScript.
    """
    graph = load_asset_map()

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    metadata = graph.get("metadata", {})

    # Optional: split nodes by type to make templating easier
    host_nodes = [n for n in nodes if n.get("type") == "host"]
    user_nodes = [n for n in nodes if n.get("type") == "user"]
    group_nodes = [n for n in nodes if n.get("type") == "group"]

    return render_template(
        'renderMap.html',
        metadata=metadata,
        nodes=nodes,
        edges=edges,
        host_nodes=host_nodes,
        user_nodes=user_nodes,
        group_nodes=group_nodes
    )

@app.route('/rendermap_vuln')
def render_map_vuln():
    """
    Render the map page that includes vulnerability highlighting.
    This view will call /api/logs from the client to trigger HF analysis
    and fetch filtered results to highlight nodes.
    """
    graph = load_asset_map()
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    metadata = graph.get("metadata", {})

    host_nodes = [n for n in nodes if n.get("type") == "host"]
    user_nodes = [n for n in nodes if n.get("type") == "user"]
    group_nodes = [n for n in nodes if n.get("type") == "group"] 

    return render_template(
        'renderMapVuln.html',
        metadata=metadata,
        nodes=nodes,
        edges=edges,
        host_nodes=host_nodes,
        user_nodes=user_nodes,
        group_nodes=group_nodes,
    )

@app.route('/api/assetmap')
def api_asset_map():
    """
    Simple JSON API so the frontend JS can fetch the full graph
    and render it with a graph library (D3, Cytoscape, vis-network, etc).
    """
    graph = load_asset_map()
    return jsonify(graph)

@app.route('/api/logs')
def api_log_generate():
    # API to get JSON of the filtered logs from AI
    # Read log text from logs/logs.xml
    logs_file = Path(LOGS_PATH)
    if logs_file.exists():
        with open(logs_file, 'r', encoding='utf-8') as f:
            logtext = f.read()
    else:
        logtext = ""

    logs = analyze_sysmon_logs(logtext, HF_Key)    
    with open(compro_path, 'w', encoding='utf-8') as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)
    
    return jsonify(logs)

@app.route('/api/peripherals')
def api_peripheral_generate():
    peripheral_logs = analyze_perimeter_logs(LOGS_PATH, str(ASSET_MAP_PATH))
    
    peripheral_logs_path = Path('logs/perimeterLogs.json')
    with open (peripheral_logs_path, 'w', encoding='utf-8') as f:
        json.dump(peripheral_logs, f, indent=2, ensure_ascii=False)
        
    return jsonify(peripheral_logs)

@app.route('/api/remediation')
def api_remediation_generate():
    remediation = remediation_guide_generate(ASSET_MAP_PATH, str(perimeter_path), str(compro_path))
    result = {
        "remediation":remediation
    }
    
    return jsonify(result)

if __name__ == '__main__':
    # For hackathon demo purposes; behind a reverse proxy in "real life"
    app.run(host="0.0.0.0", port=5000)
