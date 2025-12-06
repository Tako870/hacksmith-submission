#!/usr/bin/env python3
"""
Enrich logs.xml with asset map details (subnet, zone, criticality).
Creates detailed_logs.xml without modifying the original log structure.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import json

# Load asset map
asset_map_path = Path("assetmaps/assetMap.json")
with asset_map_path.open('r', encoding='utf-8') as f:
    asset_map = json.load(f)

# Build lookup tables
ip_to_asset = {}
hostname_to_asset = {}

for node in asset_map.get("nodes", []):
    if node.get("type") == "host":
        if "ip" in node:
            ip_to_asset[node["ip"]] = node
        if "name" in node:
            hostname_to_asset[node["name"].lower()] = node

# Parse original logs
logs_path = Path("logs/logs.xml")
tree = ET.parse(logs_path)
root = tree.getroot()

# Namespace
ns = {'s': 'http://schemas.microsoft.com/win/2004/08/events/event'}

# Process each event
for event in root.findall('.//s:Event', ns):
    system = event.find('s:System', ns)
    event_data = event.find('s:EventData', ns)
    
    if system is None or event_data is None:
        continue
    
    # Get Computer (hostname)
    computer_elem = system.find('s:Computer', ns)
    if computer_elem is not None:
        hostname = computer_elem.text
        asset = hostname_to_asset.get(hostname.lower())
        
        if asset:
            # Add enrichment Data elements for this host
            enrichment_data = [
                ('AssetId', asset.get('id', 'N/A')),
                ('AssetName', asset.get('name', 'N/A')),
                ('AssetIP', asset.get('ip', 'N/A')),
                ('AssetZone', asset.get('zone', 'N/A')),
                ('AssetCriticality', asset.get('criticality', 'N/A')),
                ('AssetRole', asset.get('role', 'N/A')),
            ]
            
            for name, value in enrichment_data:
                data_elem = ET.Element('Data')
                data_elem.set('Name', name)
                data_elem.text = str(value)
                event_data.append(data_elem)
    
    # Also enrich network events with source/destination asset details
    event_id_elem = system.find('s:EventID', ns)
    if event_id_elem is not None and event_id_elem.text == '3':  # Network connection event
        # Find source and destination IPs
        src_ip = None
        dst_ip = None
        
        for data_elem in event_data.findall('s:Data', ns):
            name = data_elem.get('Name')
            text = data_elem.text or ""
            if name == 'SourceIp':
                src_ip = text
            elif name == 'DestinationIp':
                dst_ip = text
        
        # Enrich with source asset details
        if src_ip and src_ip in ip_to_asset:
            src_asset = ip_to_asset[src_ip]
            src_enrichment = [
                ('SourceAssetId', src_asset.get('id', 'N/A')),
                ('SourceAssetName', src_asset.get('name', 'N/A')),
                ('SourceAssetZone', src_asset.get('zone', 'N/A')),
                ('SourceAssetCriticality', src_asset.get('criticality', 'N/A')),
            ]
            for name, value in src_enrichment:
                data_elem = ET.Element('Data')
                data_elem.set('Name', name)
                data_elem.text = str(value)
                event_data.append(data_elem)
        
        # Enrich with destination asset details
        if dst_ip and dst_ip in ip_to_asset:
            dst_asset = ip_to_asset[dst_ip]
            dst_enrichment = [
                ('DestinationAssetId', dst_asset.get('id', 'N/A')),
                ('DestinationAssetName', dst_asset.get('name', 'N/A')),
                ('DestinationAssetZone', dst_asset.get('zone', 'N/A')),
                ('DestinationAssetCriticality', dst_asset.get('criticality', 'N/A')),
            ]
            for name, value in dst_enrichment:
                data_elem = ET.Element('Data')
                data_elem.set('Name', name)
                data_elem.text = str(value)
                event_data.append(data_elem)

# Write enriched logs to detailed_logs.xml
output_path = Path("logs/detailed_logs.xml")
tree.write(output_path, encoding='utf-8', xml_declaration=True)
print(f"✓ Created {output_path}")
print(f"  Added asset enrichment data to all events:")
print(f"    - Host asset details (AssetId, AssetName, AssetIP, AssetZone, AssetCriticality, AssetRole)")
print(f"    - Network events (EventID 3): Source/Destination asset details")
