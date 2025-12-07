# ALLES KLAR

**ALLES KLAR** is an AI-powered incident response and threat analysis platform designed for Security Operations Centers (SOC). The application provides automated analysis of Sysmon logs, visualizes network asset maps with vulnerabilities, and generates comprehensive remediation playbooks using advanced language models.

## Features

### 🔍 Intelligent Log Analysis
- **Automated Threat Detection**: Analyzes Sysmon XML logs using AI to identify compromised hosts and at-risk systems
- **Behavioral Reasoning**: Uses LLMs to detect lateral movement, privilege escalation, and data access attempts
- **Risk Categorization**: Automatically classifies threats by severity (critical, high, medium, low)

### 🗺️ Interactive Asset Mapping
- **Network Visualization**: Interactive graph-based visualization of your network infrastructure
- **Vulnerability Overlay**: Highlights compromised and at-risk hosts with color-coded severity indicators
- **Detailed Asset Profiles**: View comprehensive information about each node including:
  - Services and open ports
  - Security profiles and credentials
  - Identity relationships (users, groups, privileges)
  - Network dependencies and attack paths

### 📋 AI-Generated Remediation Playbooks
- **Multi-Phase Response Plans**: Step-by-step incident response guidance covering:
  1. Executive Summary
  2. Blast Radius Analysis
  3. Immediate Containment (0-30 minutes)
  4. Investigation & Scoping
  5. Eradication
  6. Recovery
  7. Validation & Monitoring
  8. Long-Term Hardening
- **Context-Aware Recommendations**: Tailored to your specific infrastructure and incident details
- **Professional Format**: HTML output styled with Bootstrap for easy reading and presentation

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Flask Web App                         │
├─────────────────────────────────────────────────────────┤
│  • Upload Logs (XML)                                     │
│  • Upload Asset Map (JSON)                               │
│  • View Network Visualizations                           │
│  • Generate Remediation Playbooks                        │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              AI Analysis Layer (HuggingFace)             │
├─────────────────────────────────────────────────────────┤
│  • compro_log.py - Compromise Analysis                   │
│  • peripheral_log.py - Perimeter Threat Analysis         │
│  • remediation_generator.py - Playbook Generation        │
│                                                           │
│  Model: Qwen/Qwen3-32B                                   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Data Storage                           │
├─────────────────────────────────────────────────────────┤
│  • logs/logs.xml - Sysmon event logs                     │
│  • logs/filteredLogs.json - Compromise analysis          │
│  • logs/perimeterLogs.json - Perimeter analysis          │
│  • assetmaps/assetMap.json - Network topology            │
└─────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Python 3.8+
- pip
- HuggingFace API token

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Tako870/hacksmith-submission.git
   cd hacksmith-submission
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   HF_Key=your_huggingface_api_token_here
   SecretKey=your_flask_secret_key_here
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the web interface**
   
   Navigate to `http://localhost:5000` in your web browser

## Usage

### Uploading Logs

1. Navigate to **Upload Logs** from the navbar
2. Upload your Sysmon XML log file
3. Optionally upload an asset map JSON file
4. Click **Process** to analyze

The system will:
- Extract security events from the logs
- Identify compromised and at-risk hosts
- Save analysis results to `logs/filteredLogs.json` and `logs/perimeterLogs.json`

### Viewing the Asset Map

1. Navigate to **Asset Map** from the navbar
2. Click on any node to view detailed information
3. Use the vulnerability map to see highlighted at-risk systems

**Legend:**
- 🔴 Red = Critical / Compromised
- 🟠 Orange = High Risk
- 🟡 Yellow = Medium / At Risk
- ⚫ Gray = Normal

### Generating Remediation Playbooks

The system automatically generates HTML-formatted incident response playbooks based on:
- Your network asset map
- Identified compromised hosts
- At-risk systems and attack paths
- Original log evidence

Access via the API endpoint: `/api/remediation`

## Asset Map Format

Asset maps should be JSON files with this structure:

```json
{
  "metadata": {
    "name": "Network Name",
    "subnet": "IP Range",
    "description": "Description"
  },
  "nodes": [
    {
      "id": "unique-id",
      "type": "host|user|group",
      "name": "Display Name",
      "ip": "IP Address",
      "role": "Server Role",
      "zone": "Network Zone",
      "criticality": "critical|high|medium|low",
      "services": [...],
      "open_ports": [...],
      "security_profile": {...}
    }
  ],
  "edges": [
    {
      "source": "node-id",
      "target": "node-id",
      "relation": "relationship-type"
    }
  ]
}
```

See `assetmaps/assetMap.json` for a complete example.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page |
| `/uploadlogs` | GET/POST | Upload and process logs interface |
| `/api/uploadlogs` | POST | Upload logs programmatically |
| `/api/logs` | GET | Retrieve filtered log analysis |
| `/api/assetmap` | GET | Retrieve current asset map |
| `/rendermap` | GET | Interactive asset map visualization |
| `/rendermapvuln` | GET | Asset map with vulnerability overlay |
| `/api/remediation` | GET | Generate remediation playbook |

## Technology Stack

- **Backend**: Flask (Python)
- **AI/ML**: HuggingFace Inference API (Qwen3-32B)
- **Frontend**: Bootstrap 5, vis-network
- **Data Processing**: XML parsing, JSON handling
- **Visualization**: vis-network.js for graph rendering

## Security Considerations

- Store the `.env` file securely and never commit it to version control
- Use strong secret keys for production deployments
- Ensure HuggingFace API tokens are kept confidential
- Deploy behind a reverse proxy in production environments
- Implement proper authentication and authorization for production use

## Contributing

This project was developed for the Hacksmith hackathon. Contributions, issues, and feature requests are welcome.

## License

[Specify your license here]

## Acknowledgments

- Built with HuggingFace's Qwen3-32B model
- Network visualization powered by vis-network
- UI components by Bootstrap

---

**Note**: This application is designed for demonstration and SOC use cases. For production deployment, ensure proper security hardening, authentication, and monitoring are in place.
