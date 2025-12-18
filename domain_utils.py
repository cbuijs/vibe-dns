#!/usr/bin/env python3
# filename: domain_utils.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
Domain name normalization utilities.
Centralizes domain processing to avoid duplicate work.
"""


def normalize_domain(domain: str) -> str:
    """
    Normalize domain name to canonical form.
    
    - Converts to lowercase
    - Strips trailing dot
    - Strips whitespace
    
    Args:
        domain: Raw domain name
        
    Returns:
        Normalized domain name
        
    Examples:
        >>> normalize_domain("Example.COM.")
        'example.com'
        >>> normalize_domain("  GOOGLE.com  ")
        'google.com'
    """
    if not domain:
        return ""
    
    return domain.strip().lower().rstrip('.')

