# app/core/ Module

Core utilities, configuration, and security guardrails for SNODE.

## Modules

### `config.py` - Configuration Management

Centralized application configuration with environment variable support.

**Features:**
- Environment variable support (via `.env` file or system env vars)
- Configurable paths, timeouts, and scan settings
- Automatic directory creation

**Environment Variables:**
- `SNODE_DEFAULT_PORTS` - Comma-separated port list (default: "22,80,443,3389,8080,8443")
- `SNODE_DEFAULT_TIMEOUT` - Default timeout in seconds (default: 300)
- `SNODE_SCAN_RATE` - Scan rate in packets per second (default: 1000)
- `SNODE_MAX_TARGETS` - Maximum targets per scan (default: 100)
- `SNODE_DATA_DIR` - Data directory path (default: project_root / "data")
- `SNODE_RESULTS_DIR` - Results directory path (default: project_root / "results")
- `SNODE_DISCOVERIES_DIR` - Discoveries directory path (default: project_root / "discoveries")

**Note:** LLM configuration is managed separately in `app/llm/config.py`. Do not use `app/core/config.py` for LLM settings.

**Usage:**
```python
from app.core.config import get_config

config = get_config()
print(config.default_ports)  # "22,80,443,3389,8080,8443"
print(config.data_dir)  # Path to data directory
```

### `state.py` - State Management

File-based subdomain discovery state persistence.

**Features:**
- Save/load subdomains to/from files
- Automatic symlink management for latest files
- Domain-specific file organization

**Usage:**
```python
from app.core.state import save_subdomains, get_subdomain_file, load_subdomains

# Save subdomains
save_subdomains(["sub1.example.com", "sub2.example.com"], "example.com")

# Get latest file
file_path = get_subdomain_file("example.com")

# Load subdomains
subdomains = load_subdomains("example.com")
```

### `input_filter.py` - Input Guardrail

Detects and blocks prompt injection attacks in user input.

**Features:**
- Pattern-based detection
- Unicode homograph detection
- Base64/base32 encoded payload detection

**Usage:**
```python
from app.core.input_filter import detect_prompt_injection

is_safe, reason = detect_prompt_injection(user_input)
if not is_safe:
    print(f"Blocked: {reason}")
```

### `output_filter.py` - Output Guardrail

Validates commands before execution to prevent dangerous operations.

**Features:**
- Dangerous command pattern detection
- Fork bomb detection
- Reverse shell detection
- Data exfiltration detection

**Usage:**
```python
from app.core.output_filter import validate_command_safety

is_safe, reason = validate_command_safety(command)
if not is_safe:
    print(f"Blocked: {reason}")
```

## Removed Modules

The following modules were removed as part of cleanup:

- `logger.py` - Not used (all code uses `app/ui/logger.py`)
- `validators.py` - DEPRECATED wrapper (use `InputGuardrail` and `OutputGuardrail` directly)

## Configuration Priority

1. Environment variables (highest priority)
2. `.env` file (if `python-dotenv` is installed)
3. Default values (lowest priority)

## Integration with Other Systems

- **LLM Config**: Use `app/llm/config.py` for LLM model settings
- **State Management**: `SubdomainState` is file-based. For ChromaDB integration, use `app/rag/unified_memory.py`
- **Logging**: Use `app/ui/logger.py` for UI-aware logging
