# Backup Folder

This folder contains components that have been removed from the active codebase.

## Files Backed Up

### nikto_tools.py
- **Date**: 2025-11-21
- **Reason**: Removed Nikto web scanning functionality from core framework
- **Current Configuration**: Using Nmap + Shodan only
- **Purpose**: The system now focuses on:
  1. Nmap for network scanning and service detection
  2. Shodan for threat intelligence and vulnerability data
  3. LLM analysis of raw data to identify vulnerabilities

### Other Files
- `agent.py`: Previous version of agent implementation
- `ollama_agents.py`: Earlier Ollama integration attempt

## Why Nikto Was Removed

The framework has been streamlined to use:
- **Nmap**: Comprehensive network scanning, port detection, service enumeration
- **Shodan**: Threat intelligence, historical vulnerability data, CVE information
- **LLM Analysis**: AI-powered vulnerability assessment based on raw scan data

This approach provides:
1. Raw data output first (for transparency)
2. AI-powered vulnerability analysis second (with severity ratings)
3. Simpler architecture with fewer dependencies
4. Faster scans focused on reconnaissance and intelligence gathering

## Restoration

If you need to restore Nikto functionality:
1. Copy `nikto_tools.py` back to the parent directory
2. Set `ENABLE_NIKTO = True` in `config.py`
3. Update `intelligent_agent.py` to import Nikto tools
4. Update `prompts.py` to add Nikto tool descriptions
