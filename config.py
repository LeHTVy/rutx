"""
Configuration file for SNODE AI - Wireless Security Scanning Framework
Centralized settings for all agents and tools

SNODE AI supports multiple LLM providers:
- Ollama (Local, FREE, PRIVATE)
- OpenAI GPT (Cloud, PAID)
- Anthropic Claude (Cloud, PAID)
- Google Gemini (Cloud, FREE tier)
- Groq (Cloud, FREE tier, FAST)

Active Tools:
- Nmap: Network scanning and service detection
- Masscan: Fast port scanning for batch operations
- Shodan: Threat intelligence and vulnerability data
- Amass: OWASP subdomain enumeration and attack surface mapping
- BBOT: Recursive internet scanner for advanced reconnaissance
- Output Manager: Handles large scan outputs efficiently
"""

# LLM Configuration (Dynamic - loaded from llm_configs/)
# Use llm_configs/ for interactive setup
try:
    from llm_configs import get_llm_config
    _llm_config = get_llm_config().get_config()
    OLLAMA_ENDPOINT = _llm_config.get("endpoint", "http://localhost:11434/api/chat")
    MODEL_NAME = _llm_config.get("model", "deepseek-r1:latest")
    LLM_PROVIDER = _llm_config.get("provider", "ollama")
    TIMEOUT_OLLAMA = _llm_config.get("timeout", 1800)
except Exception as e:
    # Fallback to defaults if config not found
    print(f"⚠️  LLM config not loaded: {e}. Using defaults.")
    OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
    MODEL_NAME = "deepseek-r1:latest"
    LLM_PROVIDER = "ollama"
    TIMEOUT_OLLAMA = 1800

OLLAMA_LIST_ENDPOINT = "http://localhost:11434/api/tags"

# Timeout Settings (in seconds)
TIMEOUT_NMAP = 1800  # 30 minutes (was 20, increased for comprehensive scans) 
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

# API Keys (loaded from .env file - NEVER hardcode secrets here)
import os
from dotenv import load_dotenv
load_dotenv()  # Load .env file

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")  # https://securitytrails.com/app/signup
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Security Settings
REQUIRE_AUTHORIZATION_PROMPT = True  

# SNODE Integration Settings
ENABLE_TRACING = False  # Set to True to enable Phoenix tracing
PHOENIX_HOST = "localhost"
PHOENIX_PORT = 6006

ENABLE_GUARDRAILS = True    
STRICT_INPUT_VALIDATION = True  # Strict prompt injection detection
ALLOW_DESTRUCTIVE_COMMANDS = False  # Block dangerous commands (rm -rf, etc.)

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "logs/security_agent.log"

# ============================================================================
# LOCAL STORAGE PATHS (SENSITIVE DATA - NOT COMMITTED TO GIT)
# ============================================================================
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Data directory (databases, configurations)
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Audit logs directory (crash recovery, session tracking)
AUDIT_LOG_DIR = BASE_DIR / "audit_logs"
AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)

# Application logs directory (debug, info, error logs)
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Scan results directories (temporary storage)
SCAN_RESULTS_DIR = BASE_DIR / "scan_results"
SCAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Database Settings (Data Persistence Layer)
DATABASE_URL = f"sqlite:///{DATA_DIR / 'pentest.db'}"
ENABLE_DATABASE = True  # Enable database persistence for scan results
AUTO_PARSE_RESULTS = True  # Automatically parse and store tool outputs


PROMPT_INJECTION_DETECTION = True  # Detect prompt injection attempts
DANGEROUS_COMMAND_FILTER = True  # Filter dangerous commands before execution
AUTO_SANITIZE_COMMANDS = True  # Attempt to sanitize dangerous commands

