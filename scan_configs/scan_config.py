"""
Snode Security Framework - Scan Configuration System

YAML-based configuration with JSON Schema validation for reproducible scans.
"""

import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from jsonschema import validate, ValidationError, Draft7Validator


# JSON Schema for scan configuration
SCAN_CONFIG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["session", "scanning"],
    "properties": {
        "session": {
            "type": "object",
            "required": ["target", "type"],
            "properties": {
                "id": {"type": "string"},
                "target": {"type": "string"},
                "type": {
                    "type": "string",
                    "enum": ["full_assessment", "port_scan", "subdomain_enum", "vuln_scan", "osint"]
                },
                "description": {"type": "string"}
            }
        },
        "scanning": {
            "type": "object",
            "properties": {
                "reconnaissance": {
                    "type": "object",
                    "properties": {
                        "subdomains": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "tools": {
                                    "type": "array",
                                    "items": {"type": "string", "enum": ["amass", "bbot"]}
                                },
                                "passive_only": {"type": "boolean"},
                                "max_subdomains": {"type": "integer", "minimum": 1}
                            }
                        }
                    }
                },
                "port_scanning": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "strategy": {
                            "type": "string",
                            "enum": ["two-phase", "single-pass", "adaptive"]
                        },
                        "phase1": {
                            "type": "object",
                            "properties": {
                                "tool": {"type": "string", "enum": ["masscan", "naabu", "nmap"]},
                                "ports": {"type": "string"},
                                "rate": {"type": "integer", "minimum": 1}
                            }
                        },
                        "phase2": {
                            "type": "object",
                            "properties": {
                                "tool": {"type": "string", "enum": ["nmap"]},
                                "service_detection": {"type": "boolean"},
                                "version_detection": {"type": "boolean"},
                                "nse_scripts": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                }
                            }
                        },
                        "parallel": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "batch_size": {"type": "integer", "minimum": 1},
                                "max_workers": {"type": "integer", "minimum": 1, "maximum": 20}
                            }
                        }
                    }
                },
                "osint": {
                    "type": "object",
                    "properties": {
                        "shodan": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "api_key_env": {"type": "string"}
                            }
                        }
                    }
                },
                "timeouts": {
                    "type": "object",
                    "properties": {
                        "per_tool": {"type": "integer", "minimum": 1},
                        "total_scan": {"type": "integer", "minimum": 1}
                    }
                }
            }
        },
        "rules": {
            "type": "object",
            "properties": {
                "avoid": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                            "type": {"type": "string", "enum": ["ip_range", "domain", "port"]},
                            "value": {}
                        }
                    }
                },
                "focus": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                            "type": {"type": "string", "enum": ["ports", "services", "subdomains"]},
                            "value": {}
                        }
                    }
                }
            }
        },
        "reporting": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["markdown", "json", "html", "pdf"]},
                "include_raw_scans": {"type": "boolean"},
                "include_timing": {"type": "boolean"},
                "risk_scoring": {"type": "boolean"},
                "output_dir": {"type": "string"}
            }
        }
    }
}


@dataclass
class ScanConfig:
    """Dataclass representing a scan configuration"""

    # Session info
    session_id: Optional[str]
    target: str
    scan_type: str
    description: Optional[str] = None

    # Scanning parameters
    reconnaissance_enabled: bool = False
    subdomain_tools: List[str] = None
    subdomain_passive_only: bool = False
    max_subdomains: int = 500

    port_scanning_enabled: bool = True
    port_scan_strategy: str = "single-pass"
    port_scan_tool: str = "nmap"
    ports: str = "1-65535"
    scan_rate: int = 1000

    # Phase 2 (detailed)
    service_detection: bool = True
    version_detection: bool = True
    nse_scripts: List[str] = None

    # Parallel scanning
    parallel_enabled: bool = False
    parallel_batch_size: int = 50
    parallel_max_workers: int = 5

    # OSINT
    shodan_enabled: bool = False
    shodan_api_key_env: str = "SHODAN_API_KEY"

    # Timeouts
    timeout_per_tool: int = 300
    timeout_total: int = 3600

    # Rules
    avoid_rules: List[Dict[str, Any]] = None
    focus_rules: List[Dict[str, Any]] = None

    # Reporting
    report_format: str = "markdown"
    include_raw_scans: bool = False
    include_timing: bool = True
    risk_scoring: bool = True
    output_dir: str = "reports"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanConfig':
        """Create ScanConfig from dictionary"""
        # Extract session info
        session = data.get('session', {})
        scanning = data.get('scanning', {})
        rules = data.get('rules', {})
        reporting = data.get('reporting', {})

        # Extract reconnaissance config
        recon = scanning.get('reconnaissance', {})
        subdomains = recon.get('subdomains', {})

        # Extract port scanning config
        port_scan = scanning.get('port_scanning', {})
        phase1 = port_scan.get('phase1', {})
        phase2 = port_scan.get('phase2', {})
        parallel = port_scan.get('parallel', {})

        # Extract OSINT config
        osint = scanning.get('osint', {})
        shodan = osint.get('shodan', {})

        # Extract timeouts
        timeouts = scanning.get('timeouts', {})

        return cls(
            session_id=session.get('id'),
            target=session.get('target'),
            scan_type=session.get('type'),
            description=session.get('description'),

            reconnaissance_enabled=subdomains.get('enabled', False),
            subdomain_tools=subdomains.get('tools', []),
            subdomain_passive_only=subdomains.get('passive_only', False),
            max_subdomains=subdomains.get('max_subdomains', 500),

            port_scanning_enabled=port_scan.get('enabled', True),
            port_scan_strategy=port_scan.get('strategy', 'single-pass'),
            port_scan_tool=phase1.get('tool', 'nmap'),
            ports=phase1.get('ports', '1-65535'),
            scan_rate=phase1.get('rate', 1000),

            service_detection=phase2.get('service_detection', True),
            version_detection=phase2.get('version_detection', True),
            nse_scripts=phase2.get('nse_scripts', []),

            parallel_enabled=parallel.get('enabled', False),
            parallel_batch_size=parallel.get('batch_size', 50),
            parallel_max_workers=parallel.get('max_workers', 5),

            shodan_enabled=shodan.get('enabled', False),
            shodan_api_key_env=shodan.get('api_key_env', 'SHODAN_API_KEY'),

            timeout_per_tool=timeouts.get('per_tool', 300),
            timeout_total=timeouts.get('total_scan', 3600),

            avoid_rules=rules.get('avoid', []),
            focus_rules=rules.get('focus', []),

            report_format=reporting.get('format', 'markdown'),
            include_raw_scans=reporting.get('include_raw_scans', False),
            include_timing=reporting.get('include_timing', True),
            risk_scoring=reporting.get('risk_scoring', True),
            output_dir=reporting.get('output_dir', 'reports')
        )


def validate_scan_config(config_dict: Dict[str, Any]) -> bool:
    """
    Validate scan configuration against JSON Schema

    Args:
        config_dict: Configuration dictionary

    Returns:
        True if valid

    Raises:
        ValidationError: If configuration is invalid
    """
    try:
        validate(instance=config_dict, schema=SCAN_CONFIG_SCHEMA)
        return True
    except ValidationError as e:
        raise ValueError(f"Invalid scan configuration: {e.message}")


def load_scan_config(config_path: str) -> ScanConfig:
    """
    Load and validate scan configuration from YAML file

    Args:
        config_path: Path to YAML configuration file

    Returns:
        ScanConfig object

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    # Load YAML
    with open(config_file, 'r', encoding='utf-8') as f:
        config_dict = yaml.safe_load(f)

    # Validate against schema
    validate_scan_config(config_dict)

    # Convert to ScanConfig object
    config = ScanConfig.from_dict(config_dict)

    print(f"[SUCCESS] Loaded configuration from {config_path}")
    print(f"  Target: {config.target}")
    print(f"  Scan type: {config.scan_type}")
    print(f"  Parallel: {config.parallel_enabled}")

    return config


def save_scan_config(config: ScanConfig, output_path: str) -> str:
    """
    Save scan configuration to YAML file

    Args:
        config: ScanConfig object
        output_path: Path to save YAML file

    Returns:
        Path to saved file
    """
    config_dict = config.to_dict()

    # Convert to YAML format
    yaml_config = {
        'session': {
            'id': config.session_id,
            'target': config.target,
            'type': config.scan_type,
            'description': config.description
        },
        'scanning': {
            'reconnaissance': {
                'subdomains': {
                    'enabled': config.reconnaissance_enabled,
                    'tools': config.subdomain_tools or [],
                    'passive_only': config.subdomain_passive_only,
                    'max_subdomains': config.max_subdomains
                }
            },
            'port_scanning': {
                'enabled': config.port_scanning_enabled,
                'strategy': config.port_scan_strategy,
                'phase1': {
                    'tool': config.port_scan_tool,
                    'ports': config.ports,
                    'rate': config.scan_rate
                },
                'phase2': {
                    'tool': 'nmap',
                    'service_detection': config.service_detection,
                    'version_detection': config.version_detection,
                    'nse_scripts': config.nse_scripts or []
                },
                'parallel': {
                    'enabled': config.parallel_enabled,
                    'batch_size': config.parallel_batch_size,
                    'max_workers': config.parallel_max_workers
                }
            },
            'osint': {
                'shodan': {
                    'enabled': config.shodan_enabled,
                    'api_key_env': config.shodan_api_key_env
                }
            },
            'timeouts': {
                'per_tool': config.timeout_per_tool,
                'total_scan': config.timeout_total
            }
        },
        'rules': {
            'avoid': config.avoid_rules or [],
            'focus': config.focus_rules or []
        },
        'reporting': {
            'format': config.report_format,
            'include_raw_scans': config.include_raw_scans,
            'include_timing': config.include_timing,
            'risk_scoring': config.risk_scoring,
            'output_dir': config.output_dir
        }
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(yaml_config, f, default_flow_style=False, sort_keys=False)

    print(f"[SUCCESS] Saved configuration to {output_path}")

    return str(output_file)


# Example usage
if __name__ == "__main__":
    print("="*60)
    print("SCAN CONFIGURATION TEST")
    print("="*60)

    # Create example configuration
    example_config = ScanConfig(
        session_id="test-config-001",
        target="example.com",
        scan_type="full_assessment",
        description="Full security assessment of example.com",

        reconnaissance_enabled=True,
        subdomain_tools=["amass", "bbot"],
        subdomain_passive_only=False,

        port_scanning_enabled=True,
        port_scan_strategy="two-phase",
        port_scan_tool="masscan",
        ports="80,443,8080,8443,22,21,25,3389",
        scan_rate=10000,

        parallel_enabled=True,
        parallel_batch_size=50,
        parallel_max_workers=5,

        shodan_enabled=True
    )

    # Save to YAML
    config_path = "configs/example_scan.yaml"
    save_scan_config(example_config, config_path)

    # Load and validate
    try:
        loaded_config = load_scan_config(config_path)
        print(f"\n[SUCCESS] Configuration loaded successfully")
        print(f"  Reconnaissance: {loaded_config.reconnaissance_enabled}")
        print(f"  Port scanning: {loaded_config.port_scanning_enabled}")
        print(f"  Parallel: {loaded_config.parallel_enabled} ({loaded_config.parallel_max_workers} workers)")
        print(f"  Shodan: {loaded_config.shodan_enabled}")

    except Exception as e:
        print(f"\n[ERROR] Configuration validation failed: {e}")
