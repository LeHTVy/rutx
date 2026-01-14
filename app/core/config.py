"""
Configuration - Centralized config management

Supports environment variables and .env file loading.
Priority: Environment variables > .env file > Defaults

Environment variables:
- SNODE_DEFAULT_PORTS: Comma-separated port list (default: "22,80,443,3389,8080,8443")
- SNODE_DEFAULT_TIMEOUT: Default timeout in seconds (default: 300)
- SNODE_SCAN_RATE: Scan rate in packets per second (default: 1000)
- SNODE_MAX_TARGETS: Maximum targets per scan (default: 100)
- SNODE_DATA_DIR: Data directory path (default: project_root / "data")
- SNODE_RESULTS_DIR: Results directory path (default: project_root / "results")
- SNODE_DISCOVERIES_DIR: Discoveries directory path (default: project_root / "discoveries")
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# Try to load python-dotenv for .env file support
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file if it exists
except ImportError:
    # python-dotenv not installed, skip .env loading
    pass


def _get_env_str(key: str, default: str) -> str:
    """Get environment variable as string with default."""
    return os.getenv(key, default)


def _get_env_int(key: str, default: int) -> int:
    """Get environment variable as integer with default."""
    value = os.getenv(key)
    if value:
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _get_env_path(key: str, default: Path) -> Path:
    """Get environment variable as Path with default."""
    value = os.getenv(key)
    if value:
        return Path(value)
    return default


@dataclass
class Config:
    """Application configuration"""
    
    # Paths (configurable via environment variables)
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    data_dir: Path = field(default=None)
    results_dir: Path = field(default=None)
    discoveries_dir: Path = field(default=None)
    
    # ChromaDB
    chroma_persist_dir: Path = field(default=None)
    
    # Tool Settings (configurable via environment variables)
    default_timeout: int = field(default=None)
    max_targets: int = field(default=None)
    
    # Scan Settings (configurable via environment variables)
    default_ports: str = field(default=None)
    scan_rate: int = field(default=None)
    
    def __post_init__(self):
        """Initialize config with environment variables or defaults."""
        # Paths - load from env or use defaults
        if self.data_dir is None:
            self.data_dir = _get_env_path(
                "SNODE_DATA_DIR",
                self.project_root / "data"
            )
        
        if self.results_dir is None:
            self.results_dir = _get_env_path(
                "SNODE_RESULTS_DIR",
                self.project_root / "results"
            )
        
        if self.discoveries_dir is None:
            self.discoveries_dir = _get_env_path(
                "SNODE_DISCOVERIES_DIR",
                self.project_root / "discoveries"
            )
        
        # ChromaDB path
        if self.chroma_persist_dir is None:
            self.chroma_persist_dir = self.data_dir / "chroma"
        
        # Tool Settings - load from env or use defaults
        if self.default_timeout is None:
            self.default_timeout = _get_env_int("SNODE_DEFAULT_TIMEOUT", 300)
        
        if self.max_targets is None:
            self.max_targets = _get_env_int("SNODE_MAX_TARGETS", 100)
        
        # Scan Settings - load from env or use defaults
        if self.default_ports is None:
            self.default_ports = _get_env_str(
                "SNODE_DEFAULT_PORTS",
                "22,80,443,3389,8080,8443"
            )
        
        if self.scan_rate is None:
            self.scan_rate = _get_env_int("SNODE_SCAN_RATE", 1000)
        
        # Ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.discoveries_dir.mkdir(parents=True, exist_ok=True)
        self.chroma_persist_dir.mkdir(parents=True, exist_ok=True)


# Global singleton
_config: Optional[Config] = None

def get_config() -> Config:
    """Get global config instance"""
    global _config
    if _config is None:
        _config = Config()
    return _config
