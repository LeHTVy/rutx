"""
Error Handler - Standardized error handling patterns

Provides consistent error handling for API calls, file operations,
and other common error scenarios across the codebase.
"""

import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ErrorHandler:
    """Centralized error handling utilities"""

    @staticmethod
    def handle_api_error(
        response: Any,
        provider_name: str,
        context: Optional[str] = None
    ) -> Dict:
        """
        Handle API response errors with standardized format

        Args:
            response: HTTP response object (requests.Response or similar)
            provider_name: Name of the API provider
            context: Additional context (e.g., "CVE query", "subdomain lookup")

        Returns:
            Standardized error dictionary
        """
        error_msg = f"{provider_name} API error"
        if context:
            error_msg = f"{provider_name} {context} error"

        # Extract status code
        status_code = getattr(response, 'status_code', None)

        # Build error details
        error_details = {
            "success": False,
            "error": error_msg,
            "provider": provider_name,
            "status_code": status_code
        }

        # Add context if provided
        if context:
            error_details["context"] = context

        # Add response text if available
        try:
            error_details["details"] = response.text[:500]  # Limit length
        except:
            pass

        # Log the error
        logger.error(
            f"{error_msg}: status={status_code}"
        )

        return error_details

    @staticmethod
    def handle_file_error(
        error: Exception,
        filepath: str,
        operation: str = "read"
    ) -> Dict:
        """
        Handle file operation errors with standardized format

        Args:
            error: The exception that occurred
            filepath: Path to the file
            operation: Type of operation (read, write, delete, etc.)

        Returns:
            Standardized error dictionary
        """
        error_type = type(error).__name__
        error_msg = f"File {operation} error: {filepath}"

        error_details = {
            "success": False,
            "error": error_msg,
            "filepath": filepath,
            "operation": operation,
            "error_type": error_type,
            "details": str(error)
        }

        # Log the error
        logger.error(
            f"{error_msg} - {error_type}: {error}"
        )

        return error_details

    @staticmethod
    def handle_timeout_error(
        timeout: int,
        operation: str,
        context: Optional[str] = None
    ) -> Dict:
        """
        Handle timeout errors with standardized format

        Args:
            timeout: Timeout duration in seconds
            operation: Operation that timed out
            context: Additional context

        Returns:
            Standardized error dictionary
        """
        error_msg = f"{operation} timed out after {timeout} seconds"

        error_details = {
            "success": False,
            "error": error_msg,
            "timeout": timeout,
            "operation": operation,
            "error_type": "TimeoutError"
        }

        if context:
            error_details["context"] = context

        # Log the error
        logger.error(error_msg)

        return error_details

    @staticmethod
    def handle_connection_error(
        host: str,
        port: Optional[int] = None,
        service: Optional[str] = None
    ) -> Dict:
        """
        Handle connection errors with standardized format

        Args:
            host: Host/endpoint that failed to connect
            port: Port number (if applicable)
            service: Service name (e.g., "Ollama", "Database")

        Returns:
            Standardized error dictionary
        """
        if port:
            endpoint = f"{host}:{port}"
        else:
            endpoint = host

        error_msg = f"Cannot connect to {endpoint}"
        if service:
            error_msg = f"Cannot connect to {service} at {endpoint}"

        error_details = {
            "success": False,
            "error": error_msg,
            "host": host,
            "error_type": "ConnectionError"
        }

        if port:
            error_details["port"] = port

        if service:
            error_details["service"] = service

        # Log the error
        logger.error(error_msg)

        return error_details

    @staticmethod
    def handle_validation_error(
        field: str,
        value: Any,
        reason: str,
        context: Optional[str] = None
    ) -> Dict:
        """
        Handle validation errors with standardized format

        Args:
            field: Field name that failed validation
            value: The invalid value
            reason: Why validation failed
            context: Additional context

        Returns:
            Standardized error dictionary
        """
        error_msg = f"Validation failed for '{field}': {reason}"

        error_details = {
            "success": False,
            "error": error_msg,
            "field": field,
            "value": str(value)[:100],  # Limit length
            "reason": reason,
            "error_type": "ValidationError"
        }

        if context:
            error_details["context"] = context

        # Log the error
        logger.warning(error_msg)

        return error_details

    @staticmethod
    def handle_not_found_error(
        resource: str,
        identifier: str,
        resource_type: str = "Resource"
    ) -> Dict:
        """
        Handle not found errors with standardized format

        Args:
            resource: Resource that was not found
            identifier: Identifier used to search
            resource_type: Type of resource

        Returns:
            Standardized error dictionary
        """
        error_msg = f"{resource_type} not found: {resource}"

        error_details = {
            "success": False,
            "error": error_msg,
            "resource": resource,
            "identifier": identifier,
            "resource_type": resource_type,
            "error_type": "NotFoundError",
            "status_code": 404
        }

        # Log the error (info level for not found)
        logger.info(error_msg)

        return error_details

    @staticmethod
    def handle_generic_error(
        error: Exception,
        operation: str,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Handle generic errors with standardized format

        Args:
            error: The exception that occurred
            operation: Operation that failed
            context: Additional context dictionary

        Returns:
            Standardized error dictionary
        """
        error_type = type(error).__name__
        error_msg = f"{operation} failed: {error_type}"

        error_details = {
            "success": False,
            "error": error_msg,
            "operation": operation,
            "error_type": error_type,
            "details": str(error)
        }

        if context:
            error_details["context"] = context

        # Log the error
        logger.error(f"{error_msg} - {error}")

        return error_details


# Convenience functions
def api_error(response: Any, provider: str, context: Optional[str] = None) -> Dict:
    """Handle API error (convenience function)"""
    return ErrorHandler.handle_api_error(response, provider, context)


def file_error(error: Exception, filepath: str, operation: str = "read") -> Dict:
    """Handle file error (convenience function)"""
    return ErrorHandler.handle_file_error(error, filepath, operation)


def timeout_error(timeout: int, operation: str, context: Optional[str] = None) -> Dict:
    """Handle timeout error (convenience function)"""
    return ErrorHandler.handle_timeout_error(timeout, operation, context)


def connection_error(host: str, port: Optional[int] = None, service: Optional[str] = None) -> Dict:
    """Handle connection error (convenience function)"""
    return ErrorHandler.handle_connection_error(host, port, service)


def validation_error(field: str, value: Any, reason: str, context: Optional[str] = None) -> Dict:
    """Handle validation error (convenience function)"""
    return ErrorHandler.handle_validation_error(field, value, reason, context)


def not_found_error(resource: str, identifier: str, resource_type: str = "Resource") -> Dict:
    """Handle not found error (convenience function)"""
    return ErrorHandler.handle_not_found_error(resource, identifier, resource_type)


if __name__ == "__main__":
    # Test error handlers
    print("Testing ErrorHandler:\n")

    # API error
    print("1. API Error:")
    class MockResponse:
        status_code = 500
        text = "Internal server error"

    err = ErrorHandler.handle_api_error(MockResponse(), "ExampleAPI", "data fetch")
    print(f"   {err}\n")

    # File error
    print("2. File Error:")
    try:
        raise FileNotFoundError("File not found")
    except Exception as e:
        err = ErrorHandler.handle_file_error(e, "/tmp/missing.txt", "read")
        print(f"   {err}\n")

    # Timeout error
    print("3. Timeout Error:")
    err = ErrorHandler.handle_timeout_error(30, "Nmap scan", "192.168.1.1")
    print(f"   {err}\n")

    # Connection error
    print("4. Connection Error:")
    err = ErrorHandler.handle_connection_error("localhost", 11434, "Ollama")
    print(f"   {err}\n")

    # Validation error
    print("5. Validation Error:")
    err = ErrorHandler.handle_validation_error("target", "invalid!@#", "Invalid characters")
    print(f"   {err}\n")

    # Not found error
    print("6. Not Found Error:")
    err = ErrorHandler.handle_not_found_error("CVE-2021-44228", "CVE-2021-44228", "CVE")
    print(f"   {err}")
