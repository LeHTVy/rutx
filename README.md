# 🔒 AI-Driven Penetration Testing Framework v3.0

A local AI-powered automated security scanning framework with robust data persistence.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER INPUT                                         │
│                    "Scan ports and find vulns on snode.com"                  │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATION LAYER                                   │
│                      (intelligent_agent.py)                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │   Ollama LLM    │  │  Tool Selection │  │   Conversation  │              │
│  │  (llama3.2:3b)  │◄─┤    Strategy     │  │    Management   │              │
│  └────────┬────────┘  └─────────────────┘  └─────────────────┘              │
└───────────┼─────────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TOOL EXECUTION LAYER                               │
│                        (tools/native_tools.py)                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │   Nmap   │  │  Amass   │  │   BBOT   │  │  Shodan  │  │  SQLMap  │      │
│  │  (5 fn)  │  │  (2 fn)  │  │  (3 fn)  │  │  (2 fn)  │  │ (future) │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────────┘      │
└───────┼─────────────┼─────────────┼─────────────┼───────────────────────────┘
        │             │             │             │
        └─────────────┴──────┬──────┴─────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     DATA PERSISTENCE LAYER (NEW!)                            │
│                          (database/)                                         │
│                                                                              │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐      │
│  │ Step A: Raw     │      │ Step B: Parse   │      │ Step C: Store   │      │
│  │ XML/JSON Output ├─────►│ & Normalize     ├─────►│ in SQLite DB    │      │
│  │ (scan_results/) │      │ (parsers.py)    │      │ (data/pentest.db)│     │
│  └─────────────────┘      └─────────────────┘      └────────┬────────┘      │
│                                                              │               │
│                                                              ▼               │
│  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐      │
│  │ Step D: Query   │◄─────│ Repositories    │◄─────│ Models (ORM)    │      │
│  │ for Reports     │      │ (CRUD Layer)    │      │ Scan, Finding,  │      │
│  │ (reporting.py)  │      │ (repositories.py│      │ Host, Asset...  │      │
│  └─────────────────┘      └─────────────────┘      └─────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REPORTING LAYER                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  get_llm_context() → Structured Data → LLM Analysis → Final Report   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Directory Structure

```
rutx/
├── config.py                    # Centralized configuration
├── intelligent_agent.py         # Main AI agent orchestrator
├── prompts.py                   # System prompts for LLM
│
├── tools/                       # Tool Execution Layer
│   ├── __init__.py              # Tool exports (dual architecture)
│   ├── native_tools.py          # LLM tool definitions (12 tools)
│   ├── unified_tool_runner.py   # Core tool executors
│   ├── nmap_tools.py            # Nmap wrapper functions
│   ├── amass_tools.py           # Amass subdomain enumeration
│   ├── bbot_tools.py            # BBOT reconnaissance
│   ├── shodan_tools.py          # Shodan threat intelligence
│   ├── output_manager.py        # Large output handling
│   └── scan_results/            # Raw tool outputs (XML/JSON)
│
├── database/                    # Data Persistence Layer (NEW!)
│   ├── __init__.py              # Module exports
│   ├── models.py                # SQLAlchemy ORM models
│   ├── database.py              # Connection management
│   ├── parsers.py               # Tool output parsers
│   ├── repositories.py          # Data access layer
│   ├── service.py               # High-level services
│   ├── reporting.py             # Report generation
│   └── tool_integration.py      # Tool runner integration
│
├── data/                        # Database storage
│   └── pentest.db               # SQLite database
│
├── logs/                        # Log files
│   ├── log_normal.json
│   └── log_anomaly.json
│
└── backup/                      # Archived code
```

---

## 🗃️ Data Schema (Database Models)

### Scan Entity
```json
{
  "id": "uuid",
  "tool": "nmap|amass|bbot|shodan",
  "target": "snode.com",
  "scan_profile": "vuln",
  "status": "completed",
  "start_time": "2025-11-23T17:00:00Z",
  "elapsed_seconds": 1171.73,
  "hosts_discovered": 1,
  "ports_discovered": 2,
  "findings_count": 5
}
```

### Finding Entity
```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "finding_type": "vulnerability|open_port|subdomain",
  "title": "Open port 80/tcp (http)",
  "severity": "critical|high|medium|low|info",
  "cve_id": "CVE-2021-44228",
  "status": "new|confirmed|remediated",
  "evidence": "Raw output proving the finding"
}
```

### Host Entity
```json
{
  "id": "uuid",
  "ip_address": "192.168.1.100",
  "hostname": "web-server-01",
  "os_name": "Ubuntu 20.04",
  "open_ports": 5,
  "ports": [
    {"port": 80, "service": "http", "product": "nginx"},
    {"port": 443, "service": "https", "product": "nginx"}
  ]
}
```

### Asset Entity
```json
{
  "id": "uuid",
  "name": "Production Web Server",
  "ip_address": "192.168.1.100",
  "domain": "snode.com",
  "criticality": "high",
  "owner": "IT Security",
  "risk_score": 75.5,
  "open_findings_count": 12
}
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Python dependencies
pip install sqlalchemy shodan requests

# Scanning tools
sudo apt install nmap amass

# BBOT
pipx install bbot

# Ollama
curl https://ollama.ai/install.sh | sh
ollama pull llama3.2:3b
```

### 2. Initialize Database

```python
from database import init_database

# Creates tables in data/pentest.db
db = init_database()
```

### 3. Run the Agent

```bash
# Interactive mode
python intelligent_agent.py

# Enter prompt:
> Perform comprehensive security scan on snode.com
```

---

## 💾 Data Persistence Examples

### Save Scan Results to Database

```python
from database import save_scan_result

# After running a tool, save to database
result = save_scan_result(
    tool="nmap",
    target="snode.com",
    output_file="tools/scan_results/nmap_snode_com.xml",
    scan_profile="vuln",
    elapsed_seconds=1171.73
)

print(f"Saved scan: {result['scan_id']}")
print(f"Hosts: {result['hosts_discovered']}")
print(f"Findings: {result['findings_count']}")
```

### Query Database for Reports

```python
from database import query_database

# Get all scans for a target
scans = query_database("scans", target="snode.com")

# Get critical findings
findings = query_database("findings", severity="critical")

# Get statistics
stats = query_database("stats")
print(f"Total scans: {stats['scan_stats']['total_scans']}")
print(f"Critical findings: {stats['finding_stats']['by_severity']['critical']}")
```

### Generate LLM Context (for Report Generation)

```python
from database import get_llm_context

# Instead of reading raw logs, the LLM gets structured data
context = get_llm_context()

# Returns comprehensive JSON with:
# - Executive summary
# - Findings by severity
# - Host inventory
# - Risk assessment
# - Recommendations
```

---

## 🔧 Tool Integration

### With Database Persistence (Recommended)

```python
from database.tool_integration import (
    run_nmap_with_db,
    run_amass_with_db,
    run_bbot_with_db
)

# Runs Nmap AND saves to database
result = run_nmap_with_db(
    target="192.168.1.100",
    scan_type="vuln",
    session_id="my-session-123"
)

print(f"Database scan_id: {result['database']['scan_id']}")
```

### Without Database (Direct Execution)

```python
from tools import run_nmap_native

# Just runs Nmap, saves to files only
result = run_nmap_native(
    target="192.168.1.100",
    scan_type="quick"
)
```

---

## 📊 Available Tools

| Tool | Type | Description |
|------|------|-------------|
| **Nmap** | Network | Port scanning, service detection, OS fingerprinting |
| **Amass** | OSINT | Subdomain enumeration, attack surface mapping |
| **BBOT** | Recon | Advanced recursive scanning, web discovery |
| **Shodan** | Intel | Threat intelligence, vulnerability data |

### Nmap Scan Profiles
- `quick` - Fast top 100 ports
- `aggressive` - Full OS/version detection
- `vuln` - Vulnerability scripts
- `stealth` - SYN stealth scan
- `comprehensive` - Everything

---

## 📈 Reporting

### Executive Summary Query
```python
from database import ReportingService

summary = ReportingService.get_executive_summary()
print(f"Risk Level: {summary['risk_assessment']['overall_risk']}")
print(f"Critical: {summary['critical_findings']}")
```

### Generate Full Report
```python
from database import PentestReporter

reporter = PentestReporter(session_id="my-session")
report = reporter.get_full_report()

# Contains:
# - report_metadata
# - executive_summary
# - findings (by severity)
# - hosts
# - subdomains
# - risk_assessment
# - recommendations
```

---

## ⚙️ Configuration

```python
# config.py

# Ollama AI
OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3.2:3b"

# Timeouts (seconds)
TIMEOUT_NMAP = 1200   # 20 minutes
TIMEOUT_AMASS = 1200  # 20 minutes
TIMEOUT_BBOT = 1200   # 20 minutes

# Database
ENABLE_DATABASE = True
AUTO_PARSE_RESULTS = True
DATABASE_URL = "sqlite:///data/pentest.db"

# API Keys
SHODAN_API_KEY = "your-api-key"
```

---

## 🔒 Security & Ethics

⚠️ **IMPORTANT:**
- Only scan systems you have explicit permission to test
- Comply with local laws and regulations
- Use for legitimate security testing only

**Authorized Use Cases:**
- ✅ Testing your own infrastructure
- ✅ Authorized penetration testing
- ✅ Security research (with permission)
- ✅ CTF competitions

---

## 📚 Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.8+ |
| AI/LLM | Ollama (llama3.2:3b) |
| Database | SQLite + SQLAlchemy |
| Scanning | Nmap, Amass, BBOT, Shodan |
| Data Format | JSON, XML |

---

## 🗺️ Roadmap

- [ ] PostgreSQL support for production
- [ ] SQLMap integration for SQL injection testing
- [ ] ZAP integration for web app scanning
- [ ] Nuclei integration for template-based scanning
- [ ] Dashboard UI for visualization
- [ ] Scheduled scanning
- [ ] Slack/Teams notifications

---

**Version**: 3.0
**Status**: Production Ready ✅
**Last Updated**: November 2025
