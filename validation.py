#!/usr/bin/env python3
# filename: validation.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
Validation utilities - consolidated from multiple modules.
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


def is_valid_port(port: int) -> bool:
    """
    Validate port number.
    
    Args:
        port: Port number
        
    Returns:
        True if valid port (1-65535)
    """
    return isinstance(port, int) and 1 <= port <= 65535


def is_valid_mac(mac_str: str) -> bool:
    """
    Validate MAC address format.
    
    Args:
        mac_str: MAC address string (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
        
    Returns:
        True if valid MAC address
    """
    import re
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac_str))


def extract_ip_from_string(s: str) -> str:
    """
    Extract IP address from various formats.
    
    Handles:
    - 8.8.8.8
    - 8.8.8.8:53
    - [2001:db8::1]
    - [2001:db8::1]:53
    - udp://8.8.8.8:53
    - udp://[2001:db8::1]:53
    
    Args:
        s: String containing IP address
        
    Returns:
        Extracted IP address
    """
    # Remove protocol if present
    if '://' in s:
        s = s.split('://', 1)[1]
    
    # Handle [IPv6]:port format
    if s.startswith('['):
        bracket_end = s.find(']')
        if bracket_end > 0:
            return s[1:bracket_end]
        return s[1:]  # Malformed but try anyway
    
    # Handle IPv4:port or bare IPv4
    if '.' in s:
        return s.split(':')[0]
    
    # Bare IPv6 (might have port at the end)
    # IPv6 has multiple colons, port has one
    if s.count(':') > 1:
        return s  # Likely bare IPv6
    
    # Fallback: take everything before last colon (port)
    return s.rsplit(':', 1)[0]

