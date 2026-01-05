"""
Logger - Centralized logging
"""
import logging
import sys
from pathlib import Path
from typing import Optional


def get_logger(name: str = "snode", level: int = logging.INFO) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name
        level: Log level
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Console handler with colors
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(level)
        
        # Format with emoji prefixes
        formatter = logging.Formatter(
            "%(asctime)s │ %(levelname)s │ %(message)s",
            datefmt="%H:%M:%S"
        )
        console.setFormatter(formatter)
        logger.addHandler(console)
        logger.setLevel(level)
    
    return logger


# Convenience functions
def debug(msg: str):
    get_logger().debug(msg)

def info(msg: str):
    get_logger().info(msg)

def warning(msg: str):
    get_logger().warning(msg)

def error(msg: str):
    get_logger().error(msg)
