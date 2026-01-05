"""
Configuration - Centralized config management
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    """Application configuration"""
    
    # LLM Settings
    llm_model: str = "deepseek-r1:latest"
    llm_temperature: float = 0.0
    llm_base_url: str = "http://localhost:11434"
    
    # Paths
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data")
    results_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "results")
    discoveries_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "discoveries")
    
    # ChromaDB
    chroma_persist_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data" / "chroma")
    
    # Tool Settings
    default_timeout: int = 300  # 5 minutes
    max_targets: int = 100
    
    # Scan Settings
    default_ports: str = "22,80,443,3389,8080,8443"
    scan_rate: int = 1000  # packets per second
    
    def __post_init__(self):
        """Ensure directories exist"""
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
