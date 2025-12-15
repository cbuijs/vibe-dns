#!/usr/bin/env python3
# filename: config_validator.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 3.3.0 (Added Connection Reuse Validation)
# -----------------------------------------------------------------------------
"""
Configuration Validation Module - Complete coverage for all config options.
Now supports connection reuse validation.
"""

import re
import os
import ipaddress
from typing import Dict, List, Tuple, Any, Optional
from utils import get_logger
from validation import is_valid_ip, is_valid_cidr, is_valid_domain

logger = get_logger("ConfigValidator")


class ConfigValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


class ConfigValidator:
    """Validates DNS server configuration for common errors and inconsistencies"""

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        """
        Validate entire configuration.

        Returns:
            (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []

        if not isinstance(config, dict):
            self.errors.append("Configuration must be a dictionary")
            return False, self.errors, self.warnings

        # Validate each section
        self._validate_logging(config.get('logging', {}))
        self._validate_server(config.get('server', {}))
        self._validate_geoip(config.get('geoip', {}))
        self._validate_upstream(config.get('upstream', {}))
        self._validate_cache(config.get('cache', {}))
        self._validate_decision_cache(config.get('decision_cache', {}))
        self._validate_deduplication(config.get('deduplication', {}))
        self._validate_rate_limit(config.get('rate_limit', {}))
        self._validate_response(config.get('response', {}))
        self._validate_filtering(config.get('filtering', {}))
        self._validate_categorization(config)
        self._validate_groups(config.get('groups', {}))
        self._validate_group_files(config.get('group_files', {}))
        self._validate_schedules(config.get('schedules', {}))
        self._validate_lists(config.get('lists', {}))
        self._validate_policies(config.get('policies', {}), config.get('lists', {}), config.get('upstream', {}))
        self._validate_assignments(config.get('assignments', {}), config.get('policies', {}), config.get('schedules', {}), config.get('groups', {}))
        self._validate_top_level_options(config)
        self._validate_heuristics(config.get('heuristics', {}))

        is_valid = len(self.errors) == 0

        if self.errors:
            print("\n❌ CONFIGURATION ERRORS:")
            for i, err in enumerate(self.errors, 1):
                print(f"  {i}. {err}")

        if self.warnings:
            print("\n⚠️  CONFIGURATION WARNINGS:")
            for i, warn in enumerate(self.warnings, 1):
                print(f"  {i}. {warn}")

        if is_valid:
            logger.info("Configuration validation PASSED")
        else:
            logger.error(f"Configuration validation FAILED with {len(self.errors)} error(s)")

        if self.warnings:
            logger.warning(f"Configuration has {len(self.warnings)} warning(s)")

        return is_valid, self.errors, self.warnings

    # =========================================================================
    # LOGGING SECTION
    # =========================================================================
    def _validate_logging(self, log_cfg: Dict[str, Any]):
        """Validate logging configuration"""
        if not isinstance(log_cfg, dict):
            if log_cfg is not None:
                self.errors.append("logging: Must be a dictionary")
            return

        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        level = log_cfg.get('level', 'INFO')
        if isinstance(level, str):
            if level.upper() not in valid_levels:
                self.errors.append(f"logging.level: Invalid level '{level}', must be one of {valid_levels}")
        else:
            self.errors.append(f"logging.level: Must be a string, got {type(level).__name__}")

        for bool_key in ['enable_console', 'console_timestamp', 'enable_file', 'enable_syslog']:
            val = log_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"logging.{bool_key}: Must be boolean, got {type(val).__name__}")

        file_path = log_cfg.get('file_path')
        if file_path is not None:
            if not isinstance(file_path, str):
                self.errors.append(f"logging.file_path: Must be string")
            elif log_cfg.get('enable_file', False):
                parent_dir = os.path.dirname(file_path) or '.'
                if not os.path.isdir(parent_dir):
                    self.warnings.append(f"logging.file_path: Directory '{parent_dir}' does not exist")

        syslog_addr = log_cfg.get('syslog_address')
        if syslog_addr is not None and not isinstance(syslog_addr, str):
            self.errors.append("logging.syslog_address: Must be string")

        syslog_proto = log_cfg.get('syslog_protocol', 'UDP')
        if syslog_proto and syslog_proto.upper() not in ['UDP', 'TCP']:
            self.errors.append(f"logging.syslog_protocol: Must be 'UDP' or 'TCP', got '{syslog_proto}'")

    # =========================================================================
    # SERVER SECTION
    # =========================================================================
    def _validate_server(self, server_cfg: Dict[str, Any]):
        """Validate server networking configuration"""
        if not isinstance(server_cfg, dict):
            if server_cfg is not None:
                self.errors.append("server: Must be a dictionary")
            return

        # Check bind_ip
        bind_ips = server_cfg.get('bind_ip', [])
        if bind_ips:
            if isinstance(bind_ips, str):
                bind_ips = [bind_ips]
            if not isinstance(bind_ips, list):
                self.errors.append("server.bind_ip: Must be a string or list")
            else:
                for ip in bind_ips:
                    if not is_valid_ip(ip):
                        self.errors.append(f"server.bind_ip: Invalid IP address '{ip}'")

        # Check bind_interfaces
        bind_ifaces = server_cfg.get('bind_interfaces')
        if bind_ifaces is not None:
            if isinstance(bind_ifaces, str):
                bind_ifaces = [bind_ifaces]
            if not isinstance(bind_ifaces, list):
                self.errors.append("server.bind_interfaces: Must be a string or list")
            else:
                for iface in bind_ifaces:
                    if not isinstance(iface, str):
                        self.errors.append(f"server.bind_interfaces: Invalid entry '{iface}' (must be string)")

        # Check ports
        for port_key in ['port_udp', 'port_tcp']:
            ports = server_cfg.get(port_key)
            if ports is not None:
                if isinstance(ports, int):
                    ports = [ports]
                if not isinstance(ports, list):
                    self.errors.append(f"server.{port_key}: Must be an integer or list")
                else:
                    for port in ports:
                        if not isinstance(port, int) or port < 1 or port > 65535:
                            self.errors.append(f"server.{port_key}: Invalid port {port}")

        # Check concurrency
        udp_concurrency = server_cfg.get('udp_concurrency')
        if udp_concurrency is not None:
            if not isinstance(udp_concurrency, int) or udp_concurrency < 1:
                self.errors.append(f"server.udp_concurrency: Must be integer >= 1, got {udp_concurrency}")

        # Check ECS masks
        for mask_key, max_val in [('ecs_mask_ipv4', 32), ('ecs_mask_ipv6', 128)]:
            val = server_cfg.get(mask_key)
            if val is not None:
                if not isinstance(val, int) or val < 0 or val > max_val:
                    self.errors.append(f"server.{mask_key}: Must be integer 0-{max_val}, got {val}")

        # Check ECS Overrides
        for override_key in ['ecs_override_ipv4', 'ecs_override_ipv6']:
            val = server_cfg.get(override_key)
            if val is not None:
                if not isinstance(val, str) or not is_valid_ip(val):
                    self.errors.append(f"server.{override_key}: Invalid IP address '{val}'")

    # =========================================================================
    # GEOIP SECTION
    # =========================================================================
    def _validate_geoip(self, geoip_cfg: Dict[str, Any]):
        """Validate GeoIP configuration"""
        if not isinstance(geoip_cfg, dict):
            if geoip_cfg is not None:
                self.errors.append("geoip: Must be a dictionary")
            return

        enabled = geoip_cfg.get('enabled')
        if enabled is not None and not isinstance(enabled, bool):
            self.errors.append("geoip.enabled: Must be boolean")

        db_path = geoip_cfg.get('unified_database')
        if db_path is not None:
            if not isinstance(db_path, str):
                self.errors.append("geoip.unified_database: Must be string")
            elif geoip_cfg.get('enabled', True) and not os.path.isfile(db_path):
                self.warnings.append(f"geoip.unified_database: File '{db_path}' not found")

        valid_cctld_modes = ['geoip_only', 'cctld_first', 'cctld_geoip']
        cctld_mode = geoip_cfg.get('cctld_mode')
        if cctld_mode is not None:
            if not isinstance(cctld_mode, str) or cctld_mode not in valid_cctld_modes:
                self.errors.append(f"geoip.cctld_mode: Must be one of {valid_cctld_modes}, got '{cctld_mode}'")

    # =========================================================================
    # UPSTREAM SECTION
    # =========================================================================
    def _validate_upstream(self, upstream_cfg: Dict[str, Any]):
        """Validate upstream resolver configuration"""
        if not isinstance(upstream_cfg, dict):
            if upstream_cfg is not None:
                self.errors.append("upstream: Must be a dictionary")
            return

        # Check mode
        valid_modes = ['none', 'random', 'roundrobin', 'fastest', 'failover', 'sticky', 'loadbalance']
        mode = upstream_cfg.get('mode', 'fastest')
        if mode not in valid_modes:
            self.errors.append(f"upstream.mode: Invalid mode '{mode}', must be one of {valid_modes}")

        # Boolean options
        for bool_key in ['startup_check_enabled', 'fallback_enabled', 'allow_underscores', 
                         'circuit_breaker_enabled', 'monitor_on_query', 'connection_reuse']:
            val = upstream_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"upstream.{bool_key}: Must be boolean")

        # Numeric options
        for num_key in ['monitor_interval', 'connection_limit', 'circuit_failure_threshold', 'circuit_recovery_timeout']:
            val = upstream_cfg.get(num_key)
            if val is not None:
                if not isinstance(val, (int, float)) or val < 1:
                    self.errors.append(f"upstream.{num_key}: Must be a number >= 1, got {val}")

        # Test domain
        test_domain = upstream_cfg.get('test_domain')
        if test_domain is not None and not isinstance(test_domain, str):
            self.errors.append("upstream.test_domain: Must be string")

        # Check bootstrap servers
        bootstrap = upstream_cfg.get('bootstrap', [])
        if bootstrap:
            if not isinstance(bootstrap, list):
                self.errors.append("upstream.bootstrap: Must be a list")
            else:
                for server in bootstrap:
                    if not isinstance(server, str):
                        self.errors.append(f"upstream.bootstrap: Invalid entry '{server}' (must be string)")
                        continue
                    self._validate_bootstrap_server(server)

        # Check groups
        groups = upstream_cfg.get('groups', {})
        if not isinstance(groups, dict):
            self.errors.append("upstream.groups: Must be a dictionary")
        else:
            if not groups:
                self.warnings.append("upstream.groups: No upstream groups configured")
            for group_name, group_data in groups.items():
                self._validate_upstream_group(group_name, group_data)

    def _validate_bootstrap_server(self, server: str):
        """Validate bootstrap server entry"""
        if '://' in server:
            proto = server.split('://')[0]
            if proto not in ['udp', 'tcp']:
                self.errors.append(f"upstream.bootstrap: Invalid protocol '{proto}' in '{server}'")

        # Extract IP
        ip_part = server
        if '://' in ip_part:
            ip_part = ip_part.split('://', 1)[1]
        if ip_part.startswith('['):
            bracket_end = ip_part.find(']')
            if bracket_end > 0:
                ip_part = ip_part[1:bracket_end]
            else:
                ip_part = ip_part[1:]
        elif ':' in ip_part and ip_part.count(':') == 1:
            ip_part = ip_part.split(':')[0]
        elif '.' in ip_part and ':' in ip_part:
            ip_part = ip_part.rsplit(':', 1)[0]

        if not is_valid_ip(ip_part):
            self.errors.append(f"upstream.bootstrap: Invalid IP '{ip_part}' in '{server}'")

    def _validate_upstream_group(self, group_name: str, group_data: Any):
        """Validate upstream group configuration"""
        if not isinstance(group_data, dict):
            self.errors.append(f"upstream.groups.{group_name}: Must be a dictionary")
            return

        servers = group_data.get('servers', [])
        if not isinstance(servers, list):
            self.errors.append(f"upstream.groups.{group_name}.servers: Must be a list")
        elif not servers:
            self.warnings.append(f"upstream.groups.{group_name}: No servers configured")
        else:
            for server in servers:
                # Handle both string and dict formats (dict for priority support)
                if isinstance(server, dict):
                    server_url = server.get('url')
                    priority = server.get('priority')
                    
                    if not server_url:
                        self.errors.append(f"upstream.groups.{group_name}: Server dict missing 'url' key")
                        continue
                    
                    if priority is not None:
                        if not isinstance(priority, (int, float)) or priority < 0:
                            self.errors.append(f"upstream.groups.{group_name}: priority must be non-negative number, got {priority}")
                    
                    self._validate_upstream_server_url(group_name, server_url)
                else:
                    self._validate_upstream_server_url(group_name, server)

    def _validate_upstream_server_url(self, group_name: str, server: str):
        """Validate upstream server URL syntax: protocol://host:port/path#forced_ip"""
        if not isinstance(server, str):
            self.errors.append(f"upstream.groups.{group_name}: Server entry must be string, got {type(server).__name__}")
            return

        valid_protocols = ['udp', 'tcp', 'tls', 'https']
        
        # Parse protocol
        if '://' not in server:
            self.errors.append(f"upstream.groups.{group_name}: Missing protocol in '{server}'")
            return

        proto, remainder = server.split('://', 1)
        if proto not in valid_protocols:
            self.errors.append(f"upstream.groups.{group_name}: Invalid protocol '{proto}' in '{server}', must be one of {valid_protocols}")
            return

        # Parse forced IP if present
        forced_ip = None
        if '#' in remainder:
            remainder, forced_ip = remainder.rsplit('#', 1)
            if forced_ip and not is_valid_ip(forced_ip):
                self.errors.append(f"upstream.groups.{group_name}: Invalid forced IP '{forced_ip}' in '{server}'")

        # Parse path for https
        path = ''
        if '/' in remainder:
            host_port, path = remainder.split('/', 1)
            path = '/' + path
        else:
            host_port = remainder

        # Parse host and port
        host = None
        if host_port.startswith('['):
            # IPv6 with brackets
            bracket_end = host_port.find(']')
            if bracket_end < 0:
                self.errors.append(f"upstream.groups.{group_name}: Malformed IPv6 in '{server}'")
                return
            host = host_port[1:bracket_end]
            port_part = host_port[bracket_end + 1:]
            if port_part.startswith(':'):
                try:
                    port = int(port_part[1:])
                    if port < 1 or port > 65535:
                        self.errors.append(f"upstream.groups.{group_name}: Invalid port in '{server}'")
                except ValueError:
                    self.errors.append(f"upstream.groups.{group_name}: Invalid port in '{server}'")
        else:
            if ':' in host_port:
                host, port_str = host_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                    if port < 1 or port > 65535:
                        self.errors.append(f"upstream.groups.{group_name}: Invalid port {port} in '{server}'")
                except ValueError:
                    self.errors.append(f"upstream.groups.{group_name}: Invalid port '{port_str}' in '{server}'")
            else:
                host = host_port

        # Validate host (can be IP or hostname)
        if host and not is_valid_ip(host) and not self._is_valid_hostname(host):
            self.warnings.append(f"upstream.groups.{group_name}: Host '{host}' may not be resolvable")

        # DoH should have path
        if proto == 'https' and not path:
            self.warnings.append(f"upstream.groups.{group_name}: DoH server '{server}' missing path (typically /dns-query)")

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Check if string is a valid hostname"""
        if not hostname or len(hostname) > 253:
            return False
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        labels = hostname.split('.')
        pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
        return all(pattern.match(label) for label in labels)

    # =========================================================================
    # CACHE SECTION
    # =========================================================================
    def _validate_cache(self, cache_cfg: Dict[str, Any]):
        """Validate cache configuration"""
        if not isinstance(cache_cfg, dict):
            if cache_cfg is not None:
                self.errors.append("cache: Must be a dictionary")
            return

        size = cache_cfg.get('size', 10000)
        if not isinstance(size, int) or size < 0:
            self.errors.append(f"cache.size: Must be non-negative integer, got {size}")
        elif size == 0:
            self.warnings.append("cache.size: Cache disabled (size = 0)")
        elif size < 100:
            self.warnings.append(f"cache.size: Very small cache ({size}), consider increasing")

        for num_key in ['gc_interval', 'negative_ttl', 'prefetch_margin']:
            val = cache_cfg.get(num_key)
            if val is not None:
                if not isinstance(val, (int, float)) or val < 0:
                    self.errors.append(f"cache.{num_key}: Must be non-negative number, got {val}")

        prefetch_min_hits = cache_cfg.get('prefetch_min_hits')
        if prefetch_min_hits is not None:
            if not isinstance(prefetch_min_hits, int) or prefetch_min_hits < 0:
                self.errors.append(f"cache.prefetch_min_hits: Must be non-negative integer, got {prefetch_min_hits}")

    # =========================================================================
    # DECISION CACHE SECTION
    # =========================================================================
    def _validate_decision_cache(self, dc_cfg: Dict[str, Any]):
        """Validate decision cache configuration"""
        if not isinstance(dc_cfg, dict):
            if dc_cfg is not None:
                self.errors.append("decision_cache: Must be a dictionary")
            return

        size = dc_cfg.get('size')
        if size is not None:
            if not isinstance(size, int) or size < 0:
                self.errors.append(f"decision_cache.size: Must be non-negative integer, got {size}")

        ttl = dc_cfg.get('ttl')
        if ttl is not None:
            if not isinstance(ttl, (int, float)) or ttl < 0:
                self.errors.append(f"decision_cache.ttl: Must be non-negative number, got {ttl}")

    # =========================================================================
    # DEDUPLICATION SECTION
    # =========================================================================
    def _validate_deduplication(self, dedup_cfg: Dict[str, Any]):
        """Validate deduplication configuration"""
        if not isinstance(dedup_cfg, dict):
            if dedup_cfg is not None:
                self.errors.append("deduplication: Must be a dictionary")
            return

        enabled = dedup_cfg.get('enabled')
        if enabled is not None and not isinstance(enabled, bool):
            self.errors.append("deduplication.enabled: Must be boolean")

    # =========================================================================
    # RATE LIMIT SECTION
    # =========================================================================
    def _validate_rate_limit(self, rate_cfg: Dict[str, Any]):
        """Validate rate limiting configuration"""
        if not isinstance(rate_cfg, dict):
            if rate_cfg is not None:
                self.errors.append("rate_limit: Must be a dictionary")
            return

        enabled = rate_cfg.get('enabled')
        if enabled is not None and not isinstance(enabled, bool):
            self.errors.append("rate_limit.enabled: Must be boolean")
        elif enabled is False:
            self.warnings.append("rate_limit: Rate limiting is disabled")

        window = rate_cfg.get('window_seconds')
        if window is not None:
            if not isinstance(window, (int, float)) or window < 1:
                self.errors.append(f"rate_limit.window_seconds: Must be number >= 1, got {window}")

        for key, max_mask in [('ipv4_mask', 32), ('ipv6_mask', 128)]:
            mask = rate_cfg.get(key)
            if mask is not None:
                if not isinstance(mask, int) or mask < 0 or mask > max_mask:
                    self.errors.append(f"rate_limit.{key}: Must be 0-{max_mask}, got {mask}")

        for key in ['udp_threshold', 'total_threshold']:
            threshold = rate_cfg.get(key)
            if threshold is not None:
                if not isinstance(threshold, int) or threshold < 1:
                    self.errors.append(f"rate_limit.{key}: Must be integer >= 1, got {threshold}")

    # =========================================================================
    # RESPONSE SECTION
    # =========================================================================
    def _validate_response(self, response_cfg: Dict[str, Any]):
        """Validate response shaping configuration"""
        if not isinstance(response_cfg, dict):
            if response_cfg is not None:
                self.errors.append("response: Must be a dictionary")
            return

        # Boolean options
        for bool_key in ['shuffle_answers', 'strip_authority', 'strip_additional', 'collapse_cnames']:
            val = response_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"response.{bool_key}: Must be boolean")

        # TTL options
        for key in ['min_ttl', 'max_ttl']:
            ttl = response_cfg.get(key)
            if ttl is not None:
                if not isinstance(ttl, int) or ttl < 0:
                    self.errors.append(f"response.{key}: Must be non-negative integer, got {ttl}")

        min_ttl = response_cfg.get('min_ttl', 0)
        max_ttl = response_cfg.get('max_ttl', 86400)
        if isinstance(min_ttl, int) and isinstance(max_ttl, int) and min_ttl > max_ttl:
            self.errors.append(f"response: min_ttl ({min_ttl}) cannot be greater than max_ttl ({max_ttl})")

        # Check sync mode
        valid_sync_modes = ['none', 'first', 'last', 'highest', 'lowest', 'average']
        sync_mode = response_cfg.get('ttl_sync_mode', 'none')
        if sync_mode not in valid_sync_modes:
            self.errors.append(f"response.ttl_sync_mode: Invalid mode '{sync_mode}', must be one of {valid_sync_modes}")

        # Check block mode
        valid_block_modes = ['filter', 'block']
        block_mode = response_cfg.get('ip_block_mode', 'filter')
        if block_mode not in valid_block_modes:
            self.errors.append(f"response.ip_block_mode: Invalid mode '{block_mode}', must be one of {valid_block_modes}")

    # =========================================================================
    # FILTERING SECTION
    # =========================================================================
    def _validate_filtering(self, filtering_cfg: Dict[str, Any]):
        """Validate filtering configuration"""
        if not isinstance(filtering_cfg, dict):
            if filtering_cfg is not None:
                self.errors.append("filtering: Must be a dictionary")
            return

        # Check PTR check mode
        valid_ptr_modes = ['none', 'strict']
        ptr_check = filtering_cfg.get('ptr_check', 'none')
        if ptr_check not in valid_ptr_modes:
            self.errors.append(f"filtering.ptr_check: Invalid mode '{ptr_check}', must be one of {valid_ptr_modes}")

    # =========================================================================
    # CATEGORIZATION OPTIONS
    # =========================================================================
    def _validate_categorization(self, config: Dict[str, Any]):
        """Validate categorization options"""
        enabled = config.get('categorization_enabled')
        if enabled is not None and not isinstance(enabled, bool):
            self.errors.append("categorization_enabled: Must be boolean")

        cat_file = config.get('categories_file')
        if cat_file is not None:
            if not isinstance(cat_file, str):
                self.errors.append("categories_file: Must be string")
            elif config.get('categorization_enabled', True) and not os.path.isfile(cat_file):
                self.warnings.append(f"categories_file: File '{cat_file}' not found")

    # =========================================================================
    # GROUPS SECTION
    # =========================================================================
    def _validate_groups(self, groups_cfg: Dict[str, Any]):
        """Validate client groups configuration"""
        if not isinstance(groups_cfg, dict):
            if groups_cfg is not None:
                self.errors.append("groups: Must be a dictionary")
            return

        for group_name, identifiers in groups_cfg.items():
            if not isinstance(identifiers, list):
                self.errors.append(f"groups.{group_name}: Must be a list")
                continue

            start_idx = 0
            if identifiers and isinstance(identifiers[0], dict):
                action_dict = identifiers[0]
                if 'default_action' in action_dict:
                    action = action_dict['default_action']
                    if action not in ['ALLOW', 'BLOCK', 'DROP']:
                        self.errors.append(f"groups.{group_name}: default_action must be 'ALLOW', 'BLOCK', or 'DROP', got '{action}'")
                    start_idx = 1
                else:
                    self.errors.append(f"groups.{group_name}: First dict item must contain 'default_action' key")
                    continue

            for ident in identifiers[start_idx:]:
                if not isinstance(ident, str):
                    self.errors.append(f"groups.{group_name}: Invalid identifier '{ident}' (must be string)")
                    continue
                self._validate_group_identifier(group_name, ident)

    def _validate_group_identifier(self, group_name: str, ident: str):
        """Validate a single group identifier"""
        ident_lower = ident.lower().strip()

        # Special prefixes
        if ident_lower.startswith('server_ip:'):
            ip = ident_lower[10:]
            if not is_valid_ip(ip):
                self.errors.append(f"groups.{group_name}: Invalid server_ip '{ip}'")
            return

        if ident_lower.startswith('server_port:'):
            try:
                port = int(ident_lower[12:])
                if port < 1 or port > 65535:
                    self.errors.append(f"groups.{group_name}: Invalid server_port {port}")
            except ValueError:
                self.errors.append(f"groups.{group_name}: Invalid server_port format '{ident}'")
            return

        if ident_lower.startswith('geoip:'):
            geo_tag = ident_lower[6:].upper()
            if len(geo_tag) < 2:
                self.warnings.append(f"groups.{group_name}: GeoIP tag '{geo_tag}' seems too short")
            return

        if ident_lower.startswith('path:'):
            # Path identifier - just needs to be a string
            return

        # CIDR notation
        if '/' in ident and not ident.startswith('path:'):
            if not is_valid_cidr(ident):
                self.errors.append(f"groups.{group_name}: Invalid CIDR '{ident}'")
            return

        # MAC or IPv6 detection
        if ':' in ident and len(ident.split(':')) >= 5:
            if self._is_valid_mac(ident):
                return
            elif is_valid_ip(ident):
                return
            else:
                self.warnings.append(f"groups.{group_name}: Ambiguous identifier '{ident}' (MAC or IPv6?)")
            return

        # Bare IP
        if '.' in ident or ':' in ident:
            if not is_valid_ip(ident):
                self.errors.append(f"groups.{group_name}: Invalid IP address '{ident}'")
            return

        # MAC with dashes or other format
        if self._is_valid_mac(ident):
            return

        # Assume it's a valid identifier (hostname, etc.)
        pass

    def _is_valid_mac(self, mac_str: str) -> bool:
        """Validate MAC address format"""
        patterns = [
            re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'),  # AA:BB:CC:DD:EE:FF
            re.compile(r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$'),    # AABB.CCDD.EEFF
        ]
        return any(p.match(mac_str) for p in patterns)

    # =========================================================================
    # GROUP FILES SECTION
    # =========================================================================
    def _validate_group_files(self, gf_cfg: Dict[str, Any]):
        """Validate group_files configuration"""
        if not isinstance(gf_cfg, dict):
            if gf_cfg is not None:
                self.errors.append("group_files: Must be a dictionary")
            return

        refresh = gf_cfg.get('refresh_interval')
        if refresh is not None:
            if not isinstance(refresh, (int, float)) or refresh < 1:
                self.errors.append(f"group_files.refresh_interval: Must be number >= 1, got {refresh}")

        for key, val in gf_cfg.items():
            if key == 'refresh_interval':
                continue
            if not isinstance(val, str):
                self.errors.append(f"group_files.{key}: Must be string path")
            elif not os.path.isfile(val):
                self.warnings.append(f"group_files.{key}: File '{val}' not found")

    # =========================================================================
    # SCHEDULES SECTION
    # =========================================================================
    def _validate_schedules(self, schedules_cfg: Dict[str, Any]):
        """Validate schedule configuration"""
        if not isinstance(schedules_cfg, dict):
            if schedules_cfg is not None:
                self.errors.append("schedules: Must be a dictionary")
            return

        valid_days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        time_pattern = re.compile(r'^([01]?\d|2[0-3]):[0-5]\d$')

        for schedule_name, schedule_data in schedules_cfg.items():
            if isinstance(schedule_data, dict):
                schedule_data = [schedule_data]

            if not isinstance(schedule_data, list):
                self.errors.append(f"schedules.{schedule_name}: Must be a dictionary or list")
                continue

            for block in schedule_data:
                if not isinstance(block, dict):
                    self.errors.append(f"schedules.{schedule_name}: Schedule block must be a dictionary")
                    continue

                days = block.get('days', [])
                if days:
                    if not isinstance(days, list):
                        self.errors.append(f"schedules.{schedule_name}: 'days' must be a list")
                    else:
                        for day in days:
                            if day not in valid_days:
                                self.errors.append(f"schedules.{schedule_name}: Invalid day '{day}', must be one of {valid_days}")

                for time_key in ['start', 'end']:
                    time_val = block.get(time_key)
                    if time_val:
                        if not isinstance(time_val, str) or not time_pattern.match(time_val):
                            self.errors.append(f"schedules.{schedule_name}: Invalid {time_key} time '{time_val}', must be HH:MM format")

    # =========================================================================
    # LISTS SECTION
    # =========================================================================
    def _validate_lists(self, lists_cfg: Dict[str, Any]):
        """Validate filter lists configuration"""
        if not isinstance(lists_cfg, dict):
            if lists_cfg is not None:
                self.errors.append("lists: Must be a dictionary")
            return

        for list_name, sources in lists_cfg.items():
            if not isinstance(sources, list):
                self.errors.append(f"lists.{list_name}: Must be a list")
                continue

            if not sources:
                self.warnings.append(f"lists.{list_name}: No sources configured")

            for source in sources:
                if isinstance(source, dict):
                    source_url = source.get('source')
                    domain_type = source.get('hosts_domain_type', 'exact')

                    if not source_url:
                        self.errors.append(f"lists.{list_name}: Source entry missing 'source' field")
                    elif not isinstance(source_url, str):
                        self.errors.append(f"lists.{list_name}: Source must be string")

                    valid_types = ['exact', 'inclusive', 'exclusive']
                    if domain_type not in valid_types:
                        self.errors.append(f"lists.{list_name}: Invalid hosts_domain_type '{domain_type}', must be one of {valid_types}")

                elif isinstance(source, str):
                    pass  # Simple string source - valid
                else:
                    self.errors.append(f"lists.{list_name}: Source must be string or dictionary")

    # =========================================================================
    # POLICIES SECTION
    # =========================================================================
    def _validate_policies(self, policies_cfg: Dict[str, Any], lists_cfg: Dict[str, Any], upstream_cfg: Dict[str, Any]):
        """Validate policy definitions"""
        if not isinstance(policies_cfg, dict):
            if policies_cfg is not None:
                self.errors.append("policies: Must be a dictionary")
            return

        if not policies_cfg:
            self.warnings.append("policies: No policies configured")

        valid_qtypes = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT',
            'SRV', 'HTTPS', 'SVCB', 'CAA', 'DNSKEY', 'RRSIG', 'NSEC',
            'DS', 'TLSA', 'ANY', 'AXFR', 'IXFR', 'NULL', 'HINFO'
        ]

        upstream_groups = set(upstream_cfg.get('groups', {}).keys()) if isinstance(upstream_cfg, dict) else set()

        for policy_name, policy_data in policies_cfg.items():
            if not isinstance(policy_data, dict):
                self.errors.append(f"policies.{policy_name}: Must be a dictionary")
                continue

            # Check upstream_group reference
            upstream_group = policy_data.get('upstream_group')
            if upstream_group is not None:
                if not isinstance(upstream_group, str):
                    self.errors.append(f"policies.{policy_name}.upstream_group: Must be string")
                elif upstream_group not in upstream_groups:
                    self.errors.append(f"policies.{policy_name}: References non-existent upstream group '{upstream_group}'")

            # Check list references (allow, block, drop)
            lists_dict = lists_cfg if isinstance(lists_cfg, dict) else {}
            for list_type in ['allow', 'block', 'drop']:
                list_names = policy_data.get(list_type, [])
                if not isinstance(list_names, list):
                    self.errors.append(f"policies.{policy_name}.{list_type}: Must be a list")
                else:
                    for list_name in list_names:
                        if list_name not in lists_dict:
                            self.errors.append(f"policies.{policy_name}: References non-existent list '{list_name}'")

            # Check query types
            for type_list in ['allowed_types', 'blocked_types', 'dropped_types']:
                qtypes = policy_data.get(type_list, [])
                if not isinstance(qtypes, list):
                    self.errors.append(f"policies.{policy_name}.{type_list}: Must be a list")
                else:
                    for qtype in qtypes:
                        if qtype.upper() not in valid_qtypes:
                            self.warnings.append(f"policies.{policy_name}.{type_list}: Unknown query type '{qtype}'")

            # Check category rules
            category_rules = policy_data.get('category_rules', {})
            if not isinstance(category_rules, dict):
                self.errors.append(f"policies.{policy_name}.category_rules: Must be a dictionary")
            else:
                valid_actions = ['ALLOW', 'BLOCK', 'DROP']
                for cat_name, cat_rule in category_rules.items():
                    if not isinstance(cat_rule, dict):
                        self.errors.append(f"policies.{policy_name}.category_rules.{cat_name}: Must be a dictionary")
                        continue

                    min_conf = cat_rule.get('min_confidence', 0)
                    if not isinstance(min_conf, (int, float)) or min_conf < 0 or min_conf > 100:
                        self.errors.append(f"policies.{policy_name}.category_rules.{cat_name}: min_confidence must be 0-100")

                    action = cat_rule.get('action', 'ALLOW')
                    if action not in valid_actions:
                        self.errors.append(f"policies.{policy_name}.category_rules.{cat_name}: action must be one of {valid_actions}")

    # =========================================================================
    # ASSIGNMENTS SECTION
    # =========================================================================
    def _validate_assignments(self, assignments_cfg: Dict[str, Any], policies_cfg: Dict[str, Any], 
                              schedules_cfg: Dict[str, Any], groups_cfg: Dict[str, Any]):
        """Validate policy assignments"""
        if not isinstance(assignments_cfg, dict):
            if assignments_cfg is not None:
                self.errors.append("assignments: Must be a dictionary")
            return

        builtin_policies = {'BLOCK', 'ALLOW', 'DROP'}
        policies_dict = policies_cfg if isinstance(policies_cfg, dict) else {}
        schedules_dict = schedules_cfg if isinstance(schedules_cfg, dict) else {}
        groups_dict = groups_cfg if isinstance(groups_cfg, dict) else {}

        for group_name, assignment in assignments_cfg.items():
            if not isinstance(assignment, dict):
                self.errors.append(f"assignments.{group_name}: Must be a dictionary")
                continue

            # Check group exists
            if group_name not in groups_dict:
                self.warnings.append(f"assignments.{group_name}: References non-existent group")

            # Check policy exists
            policy_name = assignment.get('policy')
            if policy_name:
                if policy_name not in builtin_policies and policy_name not in policies_dict:
                    self.errors.append(f"assignments.{group_name}: References non-existent policy '{policy_name}'")

            # Check schedule exists
            schedule_name = assignment.get('schedule')
            if schedule_name and schedule_name not in schedules_dict:
                self.errors.append(f"assignments.{group_name}: References non-existent schedule '{schedule_name}'")

            # Check schedule_policy
            schedule_policy = assignment.get('schedule_policy')
            if schedule_policy:
                if schedule_policy not in builtin_policies and schedule_policy not in policies_dict:
                    self.errors.append(f"assignments.{group_name}: schedule_policy references non-existent policy '{schedule_policy}'")

    # =========================================================================
    # TOP-LEVEL OPTIONS
    # =========================================================================
    def _validate_top_level_options(self, config: Dict[str, Any]):
        """Validate miscellaneous top-level options"""
        # mac_cache_refresh_interval
        mac_refresh = config.get('mac_cache_refresh_interval')
        if mac_refresh is not None:
            if not isinstance(mac_refresh, (int, float)) or mac_refresh < 1:
                self.errors.append(f"mac_cache_refresh_interval: Must be number >= 1, got {mac_refresh}")

        # list_refresh_interval
        list_refresh = config.get('list_refresh_interval')
        if list_refresh is not None:
            if not isinstance(list_refresh, (int, float)) or list_refresh < 1:
                self.errors.append(f"list_refresh_interval: Must be number >= 1, got {list_refresh}")

    def _validate_heuristics(self, heur_cfg: Dict[str, Any]):
        """Validate heuristics configuration"""
        if not isinstance(heur_cfg, dict):
            if heur_cfg is not None:
                self.errors.append("heuristics: Must be a dictionary")
            return

        enabled = heur_cfg.get('enabled')
        if enabled is not None and not isinstance(enabled, bool):
            self.errors.append("heuristics.enabled: Must be boolean")

        threshold = heur_cfg.get('block_threshold')
        if threshold is not None:
            if not isinstance(threshold, int) or not (1 <= threshold <= 5):
                self.errors.append(f"heuristics.block_threshold: Must be integer between 1 and 5, got {threshold}")

        ts_file = heur_cfg.get('typosquat_file')
        if ts_file:
            if not isinstance(ts_file, str):
                self.errors.append("heuristics.typosquat_file: Must be a string")
            elif heur_cfg.get('enabled', False) and not os.path.isfile(ts_file):
                self.warnings.append(f"heuristics.typosquat_file: File '{ts_file}' not found. Using defaults only.")

        # NEW: Validate Entropy Thresholds
        e_high = heur_cfg.get('entropy_threshold_high')
        e_susp = heur_cfg.get('entropy_threshold_suspicious')

        if e_high is not None and not isinstance(e_high, (int, float)):
             self.errors.append("heuristics.entropy_threshold_high: Must be a number")
        
        if e_susp is not None and not isinstance(e_susp, (int, float)):
             self.errors.append("heuristics.entropy_threshold_suspicious: Must be a number")

        if isinstance(e_high, (int, float)) and isinstance(e_susp, (int, float)):
            if e_high <= e_susp:
                self.errors.append("heuristics: entropy_threshold_high must be greater than entropy_threshold_suspicious")

def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
    """
    Convenience function to validate configuration.

    Returns:
        (is_valid, errors, warnings)
    """
    validator = ConfigValidator()
    return validator.validate(config)

