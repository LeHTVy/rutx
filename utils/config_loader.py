"""
Config Loader - Unified configuration file handling

Consolidates duplicate JSON/YAML loading/saving patterns across the codebase.
Provides atomic file writes and consistent error handling.
"""

import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
import logging

# Optional YAML support - gracefully degrade if not installed
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False

logger = logging.getLogger(__name__)



class ConfigLoader:
    """
    Unified configuration file loader/saver

    Features:
    - Load/save JSON and YAML files
    - Atomic file writes (temp file + rename)
    - Consistent error handling
    - Default value support
    - Path creation for parent directories
    """

    @staticmethod
    def load_json(
        filepath: str,
        defaults: Optional[Dict] = None,
        create_if_missing: bool = False
    ) -> Dict:
        """
        Load JSON configuration file

        Args:
            filepath: Path to JSON file
            defaults: Default values to return if file doesn't exist or fails to load
            create_if_missing: If True and file doesn't exist, create it with defaults

        Returns:
            Configuration dictionary

        Raises:
            FileNotFoundError: If file doesn't exist and no defaults provided
            ValueError: If JSON is invalid
        """
        file_path = Path(filepath)
        has_defaults = defaults is not None
        defaults = defaults if defaults is not None else {}

        # If file doesn't exist
        if not file_path.exists():
            if create_if_missing and has_defaults:
                logger.info(f"Creating new config file: {filepath}")
                ConfigLoader.save_json(filepath, defaults)
                return defaults
            elif has_defaults:
                logger.warning(f"Config file not found: {filepath}, using defaults")
                return defaults
            else:
                raise FileNotFoundError(f"Configuration file not found: {filepath}")


        # Load existing file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.debug(f"Loaded JSON config from: {filepath}")
                return config

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {filepath}: {e}")
            if defaults:
                logger.warning("Returning defaults due to invalid JSON")
                return defaults
            raise ValueError(f"Invalid JSON in {filepath}: {e}")

        except Exception as e:
            logger.error(f"Failed to load {filepath}: {e}")
            if defaults:
                logger.warning("Returning defaults due to load error")
                return defaults
            raise

    @staticmethod
    def load_yaml(
        filepath: str,
        defaults: Optional[Dict] = None,
        create_if_missing: bool = False
    ) -> Dict:
        """
        Load YAML configuration file

        Args:
            filepath: Path to YAML file
            defaults: Default values to return if file doesn't exist or fails to load
            create_if_missing: If True and file doesn't exist, create it with defaults

        Returns:
            Configuration dictionary

        Raises:
            FileNotFoundError: If file doesn't exist and no defaults provided
            ValueError: If YAML is invalid
            ImportError: If PyYAML is not installed
        """
        if not YAML_AVAILABLE:
            logger.warning("PyYAML not installed. Install with: pip install PyYAML")
            if defaults:
                return defaults
            raise ImportError("PyYAML is required for YAML config files. Install with: pip install PyYAML")
        
        file_path = Path(filepath)
        defaults = defaults or {}

        # If file doesn't exist
        if not file_path.exists():
            if create_if_missing and defaults:
                logger.info(f"Creating new config file: {filepath}")
                ConfigLoader.save_yaml(filepath, defaults)
                return defaults
            elif defaults:
                logger.warning(f"Config file not found: {filepath}, using defaults")
                return defaults
            else:
                raise FileNotFoundError(f"Configuration file not found: {filepath}")


        # Load existing file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                logger.debug(f"Loaded YAML config from: {filepath}")
                return config if config else {}

        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in {filepath}: {e}")
            if defaults:
                logger.warning("Returning defaults due to invalid YAML")
                return defaults
            raise ValueError(f"Invalid YAML in {filepath}: {e}")

        except Exception as e:
            logger.error(f"Failed to load {filepath}: {e}")
            if defaults:
                logger.warning("Returning defaults due to load error")
                return defaults
            raise

    @staticmethod
    def save_json(
        filepath: str,
        data: Dict,
        indent: int = 2,
        atomic: bool = True
    ) -> None:
        """
        Save data to JSON file

        Args:
            filepath: Path to save JSON file
            data: Dictionary to save
            indent: JSON indentation (default: 2 spaces)
            atomic: Use atomic write (temp file + rename) for safety

        Raises:
            Exception: If save fails
        """
        file_path = Path(filepath)

        # Create parent directories if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)

        if atomic:
            # Atomic write: write to temp file, then rename
            # This prevents corruption if write is interrupted
            try:
                # Create temp file in same directory (ensures same filesystem)
                with tempfile.NamedTemporaryFile(
                    mode='w',
                    encoding='utf-8',
                    dir=file_path.parent,
                    delete=False,
                    suffix='.tmp'
                ) as tmp_file:
                    json.dump(data, tmp_file, indent=indent)
                    tmp_path = tmp_file.name

                # Atomic rename
                shutil.move(tmp_path, file_path)
                logger.debug(f"Saved JSON config to: {filepath} (atomic)")

            except Exception as e:
                # Clean up temp file if it exists
                if 'tmp_path' in locals() and Path(tmp_path).exists():
                    Path(tmp_path).unlink()
                logger.error(f"Failed to save JSON config to {filepath}: {e}")
                raise

        else:
            # Direct write (non-atomic)
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=indent)
                logger.debug(f"Saved JSON config to: {filepath}")

            except Exception as e:
                logger.error(f"Failed to save JSON config to {filepath}: {e}")
                raise

    @staticmethod
    def save_yaml(
        filepath: str,
        data: Dict,
        atomic: bool = True,
        sort_keys: bool = False
    ) -> None:
        """
        Save data to YAML file

        Args:
            filepath: Path to save YAML file
            data: Dictionary to save
            atomic: Use atomic write (temp file + rename) for safety
            sort_keys: Sort keys alphabetically (default: False, preserve order)

        Raises:
            ImportError: If PyYAML is not installed
            Exception: If save fails
        """
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required for YAML config files. Install with: pip install PyYAML")

        file_path = Path(filepath)

        # Create parent directories if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)

        if atomic:
            # Atomic write: write to temp file, then rename
            try:
                # Create temp file in same directory
                with tempfile.NamedTemporaryFile(
                    mode='w',
                    encoding='utf-8',
                    dir=file_path.parent,
                    delete=False,
                    suffix='.tmp'
                ) as tmp_file:
                    yaml.dump(
                        data,
                        tmp_file,
                        default_flow_style=False,
                        sort_keys=sort_keys,
                        allow_unicode=True
                    )
                    tmp_path = tmp_file.name

                # Atomic rename
                shutil.move(tmp_path, file_path)
                logger.debug(f"Saved YAML config to: {filepath} (atomic)")

            except Exception as e:
                # Clean up temp file if it exists
                if 'tmp_path' in locals() and Path(tmp_path).exists():
                    Path(tmp_path).unlink()
                logger.error(f"Failed to save YAML config to {filepath}: {e}")
                raise

        else:
            # Direct write (non-atomic)
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(
                        data,
                        f,
                        default_flow_style=False,
                        sort_keys=sort_keys,
                        allow_unicode=True
                    )
                logger.debug(f"Saved YAML config to: {filepath}")

            except Exception as e:
                logger.error(f"Failed to save YAML config to {filepath}: {e}")
                raise

    @staticmethod
    def merge_with_defaults(config: Dict, defaults: Dict) -> Dict:
        """
        Merge configuration with defaults (defaults for missing keys)

        Args:
            config: User configuration
            defaults: Default values

        Returns:
            Merged configuration
        """
        merged = defaults.copy()
        merged.update(config)
        return merged


# Convenience functions for backward compatibility
def load_json(filepath: str, defaults: Optional[Dict] = None) -> Dict:
    """Load JSON file (convenience function)"""
    return ConfigLoader.load_json(filepath, defaults)


def load_yaml(filepath: str, defaults: Optional[Dict] = None) -> Dict:
    """Load YAML file (convenience function)"""
    return ConfigLoader.load_yaml(filepath, defaults)


def save_json(filepath: str, data: Dict, indent: int = 2) -> None:
    """Save JSON file (convenience function)"""
    ConfigLoader.save_json(filepath, data, indent)


def save_yaml(filepath: str, data: Dict) -> None:
    """Save YAML file (convenience function)"""
    ConfigLoader.save_yaml(filepath, data)
