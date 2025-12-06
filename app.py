from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from pathlib import Path
import json

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


@app.route('/')
def index():
    return 'Future Black Hat Arsenal Exhibitors.'


@app.route('/uploadmap', methods=['GET', 'POST'])
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
