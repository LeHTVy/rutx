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

## 🚀 Installation Guide

### System Requirements

- **Python**: 3.8+ (3.12+ recommended for Linux)
- **OS**: Windows 10/11 or Linux (Debian/Ubuntu)
- **Memory**: 4GB RAM minimum
- **Disk**: 500MB for tools + database

---

## 📦 Installation

### Linux (Debian/Ubuntu)

#### 1. Install System Dependencies

```bash
# Update package list
sudo apt update

# Install Python and essential tools
sudo apt install python3 python3-pip python3-venv nmap pipx

# Install Amass (Go required)
sudo apt install golang-go
go install -v github.com/owasp-amass/amass/v4/...@master

# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 2. Install BBOT

```bash
# Install with pipx (recommended)
pipx install bbot

# Make bbot available to sudo
sudo ln -s ~/.local/bin/bbot /usr/local/bin/bbot

# Verify installation
bbot --version
```

#### 3. Install Python Dependencies

**Option A: Using pip (system-wide)**
```bash
cd ~/wireless/rutx
sudo pip3 install -r requirements.txt --break-system-packages
```

**Option B: Using virtual environment (recommended)**
```bash
cd ~/wireless/rutx

# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# When running with sudo, use full path:
sudo ./venv/bin/python main.py
```

#### 4. Install Ollama (AI Engine)

```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull the AI model
ollama pull llama3.2:3b

# Verify it's running
ollama list
```

#### 5. Configure Shodan API (Optional)

```bash
# Edit config.py and add your API key
nano config.py

# Add this line:
SHODAN_API_KEY = "your-api-key-here"
```

---

### Windows

#### 1. Install Python

Download and install Python 3.12+ from [python.org](https://www.python.org/downloads/)

✅ Check "Add Python to PATH" during installation

#### 2. Install Scanning Tools

**Nmap:**
- Download from [nmap.org](https://nmap.org/download.html)
- Run installer as Administrator
- Verify: `nmap --version`

**Amass:**
- Download from [GitHub Releases](https://github.com/owasp-amass/amass/releases)
- Extract to `C:\Tools\amass\`
- Add to PATH: `C:\Tools\amass\`

**BBOT:**
```powershell
pip install bbot
```

#### 3. Install Python Dependencies

```powershell
cd E:\Wireless
pip install -r requirements.txt
```

#### 4. Install Ollama

- Download from [ollama.ai](https://ollama.ai/download/windows)
- Run installer
- Open PowerShell and run:
  ```powershell
  ollama pull llama3.2:3b
  ```

---

## 🔐 Running Modes: Admin vs User

### Feature Comparison

| Feature | 🔓 Admin Mode | 🔒 User Mode |
|---------|--------------|--------------|
| **Port Scanning** | All 65535 ports | All 65535 ports |
| **Service Detection** | ✅ Full (-sV) | ✅ Full (-sV) |
| **OS Detection** | ✅ Yes (-O) | ❌ No (skipped) |
| **NSE Scripts** | ✅ All scripts (-sC) | ⚠️ Limited |
| **SYN Scan** | ✅ Stealth (-sS) | ⚠️ TCP Connect (-sT) |
| **Vulnerability Scan** | ✅ Full vuln scripts | ⚠️ Basic detection |

### Linux: How to Run

**User Mode (Limited Features):**
```bash
python3 main.py
```

**Admin Mode (Full Features):**
```bash
sudo python3 main.py
# or with venv:
sudo ./venv/bin/python main.py
```

**In-App Elevation:**
```
SNODE> sudo
💡 Please restart with sudo:
   sudo python3 main.py
```

### Windows: How to Run

**User Mode:**
```powershell
python main.py
```

**Admin Mode:**
1. Right-click **PowerShell** → Run as Administrator
2. Navigate to project:
   ```powershell
   cd E:\Wireless
   python main.py
   ```

**In-App Elevation:**
```
SNODE> sudo
🚀 Attempting to elevate privileges...
# UAC prompt will appear
```

---

## 🎯 Quick Start Examples

### Example 1: Subdomain Enumeration (Any Mode)

```
SNODE> Find subdomains of example.com
```

Output:
```
📦 PHASE 1: TOOL SELECTION
  ✓ Selected: amass_enum (passive mode)
  ✓ Selected: bbot_subdomain_enum (active mode)

⚙️  PHASE 2: EXECUTION
  [1/2] Running: amass_enum
    📥 Found: 45 subdomains
  [2/2] Running: bbot_subdomain_enum
    📥 Found: 67 subdomains

📝 PHASE 4: REPORT GENERATION
  🚨 CRITICAL targets: api.example.com, admin.example.com
  🎯 High-value targets: dev.example.com, staging.example.com
```

### Example 2: Port Scan with Smart Prioritization

```
SNODE> Port scan those subdomains
```

**User Mode Output:**
```
🔒 User mode: Comprehensive scan (all ports, no OS detection)
💡 Tip: Run as Administrator for OS detection
```

**Admin Mode Output:**
```
🔓 Admin mode: Full comprehensive scan (all ports + OS detection)
```

### Example 3: Vulnerability Scan (Requires Admin)

```
SNODE> Run vulnerability scan on 192.168.1.100
```

**User Mode:**
```
🔒 User mode: Basic vulnerability detection
💡 Tip: Run with sudo/admin for full vuln scripts
```

**Admin Mode:**
```
🔓 Admin mode: Full vulnerability scan with NSE scripts
🔍 Auto-enabling Shodan for CVE enrichment
```

---

## 🛠️ Advanced Configuration

### Enable Database Persistence

```python
# config.py
ENABLE_DATABASE = True
AUTO_PARSE_RESULTS = True
DATABASE_URL = "sqlite:///data/pentest.db"
```

### Configure Timeouts

```python
# config.py
TIMEOUT_NMAP = 3600    # 60 minutes for comprehensive scans
TIMEOUT_AMASS = 1800   # 30 minutes
TIMEOUT_BBOT = 1800    # 30 minutes
TIMEOUT_OLLAMA = 300   # 5 minutes for AI analysis
```

### Shodan API Setup

1. Get free API key from [shodan.io](https://account.shodan.io/)
2. Edit `config.py`:
   ```python
   SHODAN_API_KEY = "your-key-here"
   ```

---

## 🎨 Interactive Commands

| Command | Description |
|---------|-------------|
| `help` | Show help menu |
| `tools` | List all available tools |
| `sudo` | Restart with admin privileges |
| `history` | Show command history |
| `clear` | Clear screen |
| `quit` | Exit SNODE |

---

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
