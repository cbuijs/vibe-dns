#!/usr/bin/env python3
# filename: validation.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.0.0 (Optimized - Removed Single-Use Functions)
# -----------------------------------------------------------------------------
"""
Validation utilities - consolidated and optimized.
"""

import ipaddress


def is_valid_ip(ip_str: str) -> bool:
    """
    Validate IP address (handles [IPv6] notation).
    
    Args:
        ip_str: IP address string, optionally with brackets for IPv6
        
    Returns:
        True if valid IP address
    """
    cleaned = ip_str.strip('[]')
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr_str: str) -> bool:
    """
    Validate CIDR notation (handles [IPv6] notation).
    
    Args:
        cidr_str: CIDR string, optionally with brackets for IPv6
        
    Returns:
        True if valid CIDR
    """
    cleaned = cidr_str.strip('[]')
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str, allow_underscores: bool = False) -> bool:
    """
    Validate domain format.
    
    Args:
        domain: Domain name to validate
        allow_underscores: If True, allow underscores in labels (non-RFC compliant)
        
    Returns:
        True if valid domain
    """
    if not domain or len(domain) > 253:
        return False
    
    # Check for invalid characters
    if any(c in domain for c in [' ', '\t', '\n', '\r', '|', '\\', '/']):
        return False
    
    # Split into labels
    labels = domain.split('.')
    
    # Allow single-label domains (localhost, router, TLDs)
    if len(labels) < 1:
        return False
    
    # Validate each label
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        
        # Check for valid characters
        if allow_underscores:
            if not all(c.isalnum() or c in ('-', '_') for c in label):
                return False
        else:
            if not all(c.isalnum() or c == '-' for c in label):
                return False
    
    return True

