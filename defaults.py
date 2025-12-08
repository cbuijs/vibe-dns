#!/usr/bin/env python3
# filename: defaults.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
Default configuration values - single source of truth.
"""

DEFAULT_CONFIG = {
    'server': {
        'port_udp': [53],
        'port_tcp': [53],
        'use_ecs': True,
        'use_edns_mac': True,
        'forward_ecs_mode': 'none',
        'forward_mac_mode': 'none'
    },
    'upstream': {
        'startup_check_enabled': True,
        'fallback_enabled': False,
        'allow_underscores': False,
        'mode': 'fastest',
        'monitor_interval': 60,
        'monitor_on_query': True,
        'test_domain': 'www.google.com',
        'bootstrap': ['8.8.8.8', '8.8.4.4'],
        'circuit_breaker_enabled': True,
        'circuit_failure_threshold': 3,
        'circuit_recovery_timeout': 30,
        'connection_limit': 20
    },
    'cache': {
        'size': 10000,
        'gc_interval': 300,
        'negative_ttl': 60,
        'prefetch_margin': 0,
        'prefetch_min_hits': 3
    },
    'decision_cache': {
        'size': 50000,
        'ttl': 300
    },
    'rate_limit': {
        'enabled': True,
        'window_seconds': 60,
        'udp_threshold': 100,
        'total_threshold': 200,
        'ipv4_mask': 32,
        'ipv6_mask': 128
    },
    'response': {
        'block_rcode': 'REFUSED',
        'block_ttl': 60,
        'block_ip': None,
        'ip_block_mode': 'filter',
        'round_robin_enabled': False,
        'match_answers_globally': False,
        'cname_collapse': True,
        'cname_empty_rcode': 'NXDOMAIN',
        'minimize_response': False,
        'min_ttl': 0,
        'max_ttl': 86400,
        'ttl_sync_mode': 'none'
    },
    'logging': {
        'level': 'INFO',
        'enable_console': True,
        'console_timestamp': True,
        'enable_file': False,
        'file_path': './dns_server.log',
        'enable_syslog': False,
        'syslog_address': '/dev/log',
        'syslog_protocol': 'UDP'
    },
    'categorization_enabled': True,
    'categories_file': 'categories.json',
    'mac_cache_refresh_interval': 300,
    'list_refresh_interval': 86400
}


def get_config_value(config: dict, path: str, default=None):
    """
    Get nested config value with dot notation.
    
    Args:
        config: Configuration dictionary
        path: Dot-separated path (e.g., 'upstream.mode')
        default: Default value if not found
        
    Returns:
        Configuration value or default
        
    Examples:
        >>> get_config_value(config, 'upstream.mode', 'fastest')
        'loadbalance'
        >>> get_config_value(config, 'missing.key', 'default')
        'default'
    """
    keys = path.split('.')
    value = config
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    
    return value


def merge_with_defaults(config: dict) -> dict:
    """
    Merge user configuration with defaults.
    
    Args:
        config: User configuration dictionary
        
    Returns:
        Merged configuration with defaults filled in
    """
    import copy
    
    merged = copy.deepcopy(DEFAULT_CONFIG)
    
    def deep_merge(base, updates):
        """Recursively merge updates into base"""
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                deep_merge(base[key], value)
            else:
                base[key] = value
    
    deep_merge(merged, config)
    return merged

