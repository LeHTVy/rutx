"""
SNODE OSINT - Phone Functions
==============================

Phone number lookup and validation.
Based on clatscope phone_info functionality.
"""
from typing import Dict, Any, Optional


def phone_info(phone_number: str) -> Dict[str, Any]:
    """
    Get information about a phone number.
    
    Uses phonenumbers library for parsing and validation.
    Same functionality as clatscope's phone_info.
    
    Args:
        phone_number: Phone number in international format (e.g., +1-555-555-5555)
        
    Returns:
        {
            "phone_number": original input,
            "valid": bool,
            "country": country name,
            "region": region/city,
            "carrier": carrier/operator name,
            "number_type": mobile/fixed/voip/etc,
            "formatted": formatted number,
            "error": None or error message
        }
    """
    result = {
        "phone_number": phone_number,
        "valid": False,
        "country": None,
        "region": None,
        "carrier": None,
        "number_type": None,
        "formatted": None,
        "error": None
    }
    
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, phonenumberutil
        
        # Parse the number
        parsed = phonenumbers.parse(phone_number)
        
        # Check validity
        result["valid"] = phonenumbers.is_valid_number(parsed)
        
        # Get country
        result["country"] = geocoder.country_name_for_number(parsed, "en")
        
        # Get region
        result["region"] = geocoder.description_for_number(parsed, "en")
        
        # Get carrier
        result["carrier"] = carrier.name_for_number(parsed, "en")
        
        # Get number type
        number_type = phonenumbers.number_type(parsed)
        type_map = {
            phonenumberutil.PhoneNumberType.MOBILE: "mobile",
            phonenumberutil.PhoneNumberType.FIXED_LINE: "fixed_line",
            phonenumberutil.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
            phonenumberutil.PhoneNumberType.TOLL_FREE: "toll_free",
            phonenumberutil.PhoneNumberType.PREMIUM_RATE: "premium_rate",
            phonenumberutil.PhoneNumberType.VOIP: "voip",
            phonenumberutil.PhoneNumberType.PERSONAL_NUMBER: "personal",
        }
        result["number_type"] = type_map.get(number_type, "unknown")
        
        # Format the number
        result["formatted"] = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
        
    except ImportError:
        result["error"] = "phonenumbers library not installed"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def validate_phone(phone_number: str) -> bool:
    """
    Quick validation check for a phone number.
    
    Returns True if valid, False otherwise.
    """
    try:
        import phonenumbers
        parsed = phonenumbers.parse(phone_number)
        return phonenumbers.is_valid_number(parsed)
    except Exception:
        return False


def format_phone(phone_number: str, format_type: str = "international") -> Optional[str]:
    """
    Format a phone number.
    
    Args:
        phone_number: Phone number to format
        format_type: "international", "national", or "e164"
        
    Returns:
        Formatted phone number or None if invalid
    """
    try:
        import phonenumbers
        parsed = phonenumbers.parse(phone_number)
        
        format_map = {
            "international": phonenumbers.PhoneNumberFormat.INTERNATIONAL,
            "national": phonenumbers.PhoneNumberFormat.NATIONAL,
            "e164": phonenumbers.PhoneNumberFormat.E164,
        }
        
        fmt = format_map.get(format_type, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        return phonenumbers.format_number(parsed, fmt)
        
    except Exception:
        return None


def is_mobile(phone_number: str) -> bool:
    """Check if phone number is a mobile number."""
    try:
        import phonenumbers
        from phonenumbers import phonenumberutil
        
        parsed = phonenumbers.parse(phone_number)
        number_type = phonenumbers.number_type(parsed)
        
        return number_type in [
            phonenumberutil.PhoneNumberType.MOBILE,
            phonenumberutil.PhoneNumberType.FIXED_LINE_OR_MOBILE
        ]
    except Exception:
        return False


def get_country_code(phone_number: str) -> Optional[int]:
    """Extract country code from phone number."""
    try:
        import phonenumbers
        parsed = phonenumbers.parse(phone_number)
        return parsed.country_code
    except Exception:
        return None
