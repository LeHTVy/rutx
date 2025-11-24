"""
Configuration file for RUTX Security Scanning Framework
Centralized settings for all agents and tools

Active Tools:
- Nmap: Network scanning and service detection
- Shodan: Threat intelligence and vulnerability data
- Amass: OWASP subdomain enumeration and attack surface mapping
- BBOT: Recursive internet scanner for advanced reconnaissance
- Output Manager: Handles large scan outputs efficiently
"""

# Ollama AI Configuration
OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
OLLAMA_LIST_ENDPOINT = "http://localhost:11434/api/tags"
MODEL_NAME = "mathstral:latest"  

# Timeout Settings (in seconds)
TIMEOUT_NMAP = 1200  # 20 minutes
TIMEOUT_OLLAMA = 1800 # 30 minutes 
TIMEOUT_AMASS = 1200  # 20 minutes
TIMEOUT_BBOT = 1200   # 20 minutes  

# Agent Settings
MAX_ITERATIONS = 15
ENABLE_DEBUG = False

# Tool Configuration
ENABLE_NMAP = True
ENABLE_NIKTO = False  # Nikto disabled - moved to backup folder
ENABLE_SHODAN = True
ENABLE_AMASS = True  # OWASP Amass - Subdomain enumeration and reconnaissance
ENABLE_BBOT = True   # BBOT - Recursive internet scanner
ENABLE_OUTPUT_MANAGER = True  # Save large outputs to files to reduce token usage

# Native Tools Mode (RECOMMENDED - Runs tools like terminal with native JSON export)
USE_NATIVE_TOOLS = True  # Tools run with native output formats, LLM chooses best tools

# API Keys
SHODAN_API_KEY = "GOcpJ7gEk2IKfLr8N9500eyXjJ7vva2G"

# Security Settings
REQUIRE_AUTHORIZATION_PROMPT = True  

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "logs/security_agent.log"

# Database Settings (Data Persistence Layer)
import os
DATABASE_URL = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'data', 'pentest.db')}"
ENABLE_DATABASE = True  # Enable database persistence for scan results
AUTO_PARSE_RESULTS = True  # Automatically parse and store tool outputs

# Mock Database Settings (for integrated_security_agent.py)
CMDB_DATABASE = {
    "192.168.1.100": {"asset_name": "DC-01-PROD", "criticality": "High", "owner": "IT"},
    "10.0.0.5": {"asset_name": "Dev-Workstation-12", "criticality": "Low", "owner": "Ivan"}
}

CTI_DATABASE = {
    "1.2.3.4": {"status": "malicious", "type": "Known C2 Server", "confidence": "95%"}
}
