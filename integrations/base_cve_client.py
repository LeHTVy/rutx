"""
Base CVE Client - Common patterns for CVE data sources

This module provides a base class that consolidates common HTTP request
handling, error handling, and batch query patterns shared across all CVE clients.
"""

import requests
import logging
from typing import List, Dict, Optional, Any
from abc import ABC, abstractmethod
from datetime import datetime

logger = logging.getLogger(__name__)


class BaseCVEClient(ABC):
    """
    Abstract base class for CVE data source clients

    Provides common functionality:
    - HTTP request handling with timeout/error handling
    - Standardized error responses
    - Batch query pattern
    - CVSS score conversion utilities
    """

    def __init__(self, base_url: str, timeout: int = 10):
        """
        Initialize CVE client

        Args:
            base_url: Base URL for the API
            timeout: Default request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self._configure_session()

    def _configure_session(self):
        """Configure the requests session (can be overridden by subclasses)"""
        self.session.headers.update({
            "User-Agent": "SNODE-AI-CVE-Scanner"
        })

    def _make_http_request(
        self,
        url: str,
        method: str = "GET",
        payload: Optional[Dict] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict] = None,
        provider_name: Optional[str] = None
    ) -> Dict:
        """
        Common HTTP request handler with standardized error handling

        Similar to llm_client._make_http_request, consolidates duplicate
        request patterns across CVE clients.

        Args:
            url: Request URL
            method: HTTP method (GET or POST)
            payload: JSON payload for POST requests
            timeout: Request timeout (uses self.timeout if not specified)
            headers: Optional additional headers
            provider_name: Provider name for error messages

        Returns:
            Dict with either:
                {"success": True, "data": <response_json>}
            or:
                {"success": False, "error": <error_message>, "status_code": <code>}
        """
        timeout = timeout or self.timeout
        provider_name = provider_name or self.__class__.__name__

        # Merge headers
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)

        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=timeout, headers=request_headers)
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=timeout,
                    headers=request_headers
                )
            else:
                return {
                    "success": False,
                    "error": f"Unsupported HTTP method: {method}"
                }

            # Handle different status codes
            if response.status_code == 200:
                return {"success": True, "data": response.json()}
            elif response.status_code == 404:
                return {
                    "success": False,
                    "error": "Resource not found",
                    "status_code": 404
                }
            else:
                logger.error(
                    f"{provider_name} request failed with status {response.status_code}"
                )
                return {
                    "success": False,
                    "error": f"{provider_name} request failed",
                    "status_code": response.status_code,
                    "details": response.text
                }

        except requests.exceptions.Timeout:
            logger.error(f"{provider_name} request timed out after {timeout} seconds")
            return {
                "success": False,
                "error": f"Request timed out after {timeout} seconds",
                "timeout": timeout
            }

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Cannot connect to {provider_name}: {e}")
            return {
                "success": False,
                "error": f"Cannot connect to {provider_name}",
                "details": str(e)
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"{provider_name} request error: {e}")
            return {
                "success": False,
                "error": f"{provider_name} request failed",
                "details": str(e)
            }

        except Exception as e:
            logger.error(f"{provider_name} unexpected error: {e}")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }

    @abstractmethod
    def query_by_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Query for a single CVE

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            Parsed CVE data dict or None if not found
        """
        pass

    @abstractmethod
    def _parse_vulnerability(self, raw_data: Dict) -> Dict:
        """
        Parse provider-specific vulnerability data into standardized format

        Args:
            raw_data: Raw API response data

        Returns:
            Standardized vulnerability dict with fields:
                - cve_id
                - description
                - published_date
                - cvss_v3_score
                - cvss_v3_severity
                - cvss_v3_vector
                - references
                - data_source
                - last_synced
        """
        pass

    def batch_query(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Query multiple CVEs

        Default implementation queries one at a time.
        Subclasses can override for provider-specific batch endpoints.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE ID to parsed data
        """
        results = {}

        for cve_id in cve_ids:
            try:
                result = self.query_by_cve(cve_id)
                if result:
                    results[cve_id] = result
            except Exception as e:
                logger.error(f"Error querying {cve_id}: {e}")
                continue

        return results

    def _cvss_to_severity(self, score: Optional[float]) -> Optional[str]:
        """
        Convert CVSS score to severity label

        Based on CVSS v3.0 specification:
        - 0.0: None
        - 0.1-3.9: Low
        - 4.0-6.9: Medium
        - 7.0-8.9: High
        - 9.0-10.0: Critical

        Args:
            score: CVSS score (0.0-10.0)

        Returns:
            Severity label string
        """
        if score is None:
            return None
        elif score == 0.0:
            return "NONE"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"

    def _extract_cvss_score(self, vector: str) -> Optional[float]:
        """
        Extract or calculate CVSS score from vector string

        Note: CVSS vectors don't contain the score directly.
        Real implementation would use a CVSS library.

        Args:
            vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")

        Returns:
            CVSS score or None
        """
        # Placeholder - real implementation would use cvss library
        # or make additional API calls
        return None

    def _standardize_cve_data(
        self,
        cve_id: str,
        description: str,
        published_date: Optional[str] = None,
        modified_date: Optional[str] = None,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        references: Optional[List[str]] = None,
        affected_packages: Optional[List[str]] = None,
        additional_data: Optional[Dict] = None
    ) -> Dict:
        """
        Create standardized CVE data structure

        Args:
            cve_id: CVE identifier
            description: Vulnerability description
            published_date: Publication date
            modified_date: Last modified date
            cvss_score: CVSS v3 score
            cvss_vector: CVSS v3 vector string
            references: List of reference URLs
            affected_packages: List of affected packages
            additional_data: Provider-specific additional data

        Returns:
            Standardized CVE data dict
        """
        return {
            "cve_id": cve_id,
            "description": description[:500] if description else "",
            "published_date": published_date,
            "modified_date": modified_date,
            "cvss_v3_score": cvss_score,
            "cvss_v3_severity": self._cvss_to_severity(cvss_score),
            "cvss_v3_vector": cvss_vector,
            "affected_packages": (affected_packages or [])[:20],
            "references": (references or [])[:10],
            "data_source": self.__class__.__name__.replace("Client", "").lower(),
            "last_synced": datetime.now().isoformat(),
            "additional_data": additional_data or {}
        }

    def close(self):
        """Close the session (cleanup)"""
        if hasattr(self, 'session'):
            self.session.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
