"""
Configuration file for SNODE AI - Wireless Security Scanning Framework
Centralized settings for all agents and tools

SNODE AI uses LOCAL Ollama LLM (no cloud/OpenAI dependencies)

Active Tools:
- Nmap: Network scanning and service detection
- Masscan: Fast port scanning for batch operations
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
TIMEOUT_NMAP = 1800  # 30 minutes (was 20, increased for comprehensive scans)
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

# ============================================================================
# Phoenix Tracing & Observability (SNODE Integration)
# Works with LOCAL Ollama LLM - no OpenAI instrumentation needed
# ============================================================================
ENABLE_TRACING = True  # Enable Phoenix/OpenTelemetry tracing
PHOENIX_HOST = "127.0.0.1"
PHOENIX_PORT = 6006  # Phoenix dashboard at http://localhost:6006

# ============================================================================
# Guardrails & Security (SNODE Integration)
# ============================================================================
ENABLE_GUARDRAILS = True  # Enable input/output validation
STRICT_INPUT_VALIDATION = True  # Strict mode for prompt injection detection
ALLOW_DESTRUCTIVE_COMMANDS = False  # Allow potentially dangerous commands (⚠️ use with caution)

# Guardrail Settings
PROMPT_INJECTION_DETECTION = True  # Detect prompt injection attempts
DANGEROUS_COMMAND_FILTER = True  # Filter dangerous commands before execution
AUTO_SANITIZE_COMMANDS = True  # Attempt to sanitize dangerous commands

