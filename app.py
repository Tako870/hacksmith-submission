from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from pathlib import Path
import json
import xml.etree.ElementTree as ET
from datetime import datetime

app = Flask(__name__)

# Path to your asset map JSON file
# Use the JSON structure I sent earlier as asset_map_with_identities.json
ASSET_MAP_PATH = Path("assetMap.json")


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


@app.route('/')
def index():
    return 'Future Black Hat Arsenal Exhibitors.'


@app.route('/uploadlogs', methods=['GET', 'POST'])
def upload_logs():
    """
    GET: show a simple form to upload security logs (XML, JSON, etc).
    POST: accept a log file, parse it to canonical events, resolve assets,
          and return the enriched events for visualization.
    """
    if request.method == 'POST':
        log_file = request.files.get('log_file')
        if not log_file:
            flash("No log file uploaded", "error")
            return redirect(url_for('upload_logs'))

        try:
            # Read file content
            content = log_file.read()
            
            # Try to parse as XML (Sysmon format)
            if log_file.filename.endswith('.xml'):
                try:
                    canonical_events = parse_sysmon_xml(content)
                except ValueError as e:
                    flash(f"Failed to parse XML: {str(e)}", "error")
                    return redirect(url_for('upload_logs'))
            else:
                flash("Unsupported file format. Please upload a .xml Sysmon log file.", "error")
                return redirect(url_for('upload_logs'))

            # Load asset map for resolution
            asset_map = load_asset_map()
            
            # Resolve assets for all events
            enriched_events = []
            for event in canonical_events:
                resolved_event = resolve_assets(event, asset_map)
                enriched_events.append(resolved_event)

            # Return enriched events as JSON
            return jsonify({
                "status": "success",
                "event_count": len(enriched_events),
                "events": enriched_events
            })

        except Exception as e:
            flash(f"Error processing log file: {str(e)}", "error")
            return redirect(url_for('upload_logs'))

    # For GET: show upload form
    return render_template('uploadLogs.html')


@app.route('/api/uploadlogs', methods=['POST'])
def api_upload_logs():
    """
    API endpoint for uploading logs and getting back canonical + asset-resolved events.
    Accepts multipart/form-data with 'log_file' field.
    Returns JSON with parsed events.
    """
    log_file = request.files.get('log_file')
    if not log_file:
        return jsonify({"status": "error", "message": "No log file uploaded"}), 400

    try:
        content = log_file.read()
        
        # Detect format by file extension
        if log_file.filename.endswith('.xml'):
            canonical_events = parse_sysmon_xml(content)
        else:
            return jsonify({"status": "error", "message": "Unsupported file format. Use .xml"}), 400

        # Load asset map and resolve
        asset_map = load_asset_map()
        enriched_events = []
        for event in canonical_events:
            resolved_event = resolve_assets(event, asset_map)
            enriched_events.append(resolved_event)

        return jsonify({
            "status": "success",
            "event_count": len(enriched_events),
            "events": enriched_events
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
def upload_asset_map():
    """
    GET: show a simple form to upload an asset map JSON.
    POST: accept a JSON file and save it as the current asset map.
    """
    if request.method == 'POST':
        file = request.files.get('asset_map')
        if not file:
            flash("No file uploaded", "error")
            return redirect(url_for('upload_asset_map'))

        try:
            graph = json.load(file.stream)
            # Basic sanity check
            if not isinstance(graph, dict) or "nodes" not in graph or "edges" not in graph:
                flash("Invalid asset map format (missing 'nodes' or 'edges')", "error")
                return redirect(url_for('upload_asset_map'))

            save_asset_map(graph)
            flash("Asset map uploaded successfully", "success")
            return redirect(url_for('render_map'))
        except json.JSONDecodeError:
            flash("Uploaded file is not valid JSON", "error")
            return redirect(url_for('upload_asset_map'))

    # For GET
    return render_template('uploadMap.html')


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


@app.route('/api/assetmap')
def api_asset_map():
    """
    Simple JSON API so the frontend JS can fetch the full graph
    and render it with a graph library (D3, Cytoscape, vis-network, etc).
    """
    graph = load_asset_map()
    return jsonify(graph)


if __name__ == '__main__':
    # For hackathon demo purposes; behind a reverse proxy in "real life"
    app.run(debug=True, host="0.0.0.0", port=5000)
