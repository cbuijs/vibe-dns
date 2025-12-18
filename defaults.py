#!/usr/bin/env python3
# filename: defaults.py
# Version: 2.2.0 (DoH/DoT Support)
"""
Default configuration values - single source of truth.
"""

DEFAULT_CONFIG = {
    'server': {
        'port_udp': [53],
        'port_tcp': [53],
        'udp_concurrency': 1000,
        'use_ecs': True,
        'use_edns_mac': True,
        'forward_ecs_mode': 'none',
        'forward_mac_mode': 'none',
        'ecs_ipv4_mask': 24,
        'ecs_ipv6_mask': 56,
        'ecs_override_ipv4': None,
        'ecs_override_ipv6': None,
        'tls': {
            'enabled': False,
            'enable_dot': True,
            'enable_doh': True,
            'port_dot': [853],
            'port_doh': [443],
            'cert_file': None,
            'key_file': None,
            'ca_file': None,
            'doh_paths': ['/dns-query'],
            'doh_strict_paths': False
        }
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
        'bootstrap_resolution_mode': 'auto',
        'circuit_breaker_enabled': True,
        'circuit_failure_threshold': 3,
        'circuit_recovery_timeout': 30,
        'connection_limit': 20,
        'connection_reuse': False,
        'recursive': {
            'enabled': False,
            'qname_minimization': "relaxed",
            'prefer_ipv6': False,
            'query_timeout': 5,
            'ns_cache_size': 10000,
            'ns_cache_ttl': 86400,
            'root_hints': {
                'source': 'builtin',
                'url': 'https://www.internic.net/domain/named.root',
                'file': None,
                'refresh_interval': 86400,
            },
            'trust_anchors': {
                'source': 'builtin',
                'url': 'https://data.iana.org/root-anchors/root-anchors.xml',
                'file': None,
                'refresh_interval': 86400,
            },
            'dnssec': {
                'mode': 'none',
                'validation_failure_rcode': 'SERVFAIL',
                'unsigned_zone_rcode': 'SERVFAIL',
                'cache_validated': True,
                'cache_ttl': 300,
                'disabled_algorithms': [],
            },
        },
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
        'enabled': False,
        'window_seconds': 60,
        'udp_threshold': 100,
        'total_threshold': 200,
        'ipv4_mask': 24,
        'ipv6_mask': 64
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
    'filtering': {
        'ptr_check': 'none',
        'ptr_check_rcode': 'FORMERR'
    },
    'heuristics': {
        'enabled': False,
        'block_threshold': 4,
        'typosquat_file': 'typosquat_targets.list',
        'entropy_threshold_high': 3.8,
        'entropy_threshold_suspicious': 3.2,
        'topn_file': None,
        'topn_reduction': 2
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


def merge_with_defaults(config: dict) -> dict:
    """
    Merge user configuration with defaults (optimized).
    
    Args:
        config: User configuration dictionary
        
    Returns:
        Merged configuration with defaults filled in
    """
    import copy
    
    # Start with defaults
    merged = copy.deepcopy(DEFAULT_CONFIG)
    
    # Shallow merge top-level keys
    for key, value in config.items():
        if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
            # Deep merge for nested dicts
            merged[key] = _deep_merge(merged[key], value)
        else:
            # Direct replacement for non-dicts
            merged[key] = value
    
    return merged


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge overlay into base"""
    result = base.copy()
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

