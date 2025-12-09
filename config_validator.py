#!/usr/bin/env python3
# filename: config_validator.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.2.0 (Optimized - Inlined Helper Functions)
# -----------------------------------------------------------------------------
"""
Configuration Validation Module - Optimized version.
"""

import re
import ipaddress
from typing import Dict, List, Tuple, Any
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
        self._validate_server(config.get('server', {}))
        self._validate_upstream(config.get('upstream', {}))
        self._validate_cache(config.get('cache', {}))
        self._validate_rate_limit(config.get('rate_limit', {}))
        self._validate_response(config.get('response', {}))
        self._validate_groups(config.get('groups', {}))
        self._validate_schedules(config.get('schedules', {}))
        self._validate_assignments(config.get('assignments', {}), config.get('policies', {}), config.get('schedules', {}))
        self._validate_policies(config.get('policies', {}), config.get('lists', {}))
        self._validate_lists(config.get('lists', {}))
        
        is_valid = len(self.errors) == 0
        
        if is_valid:
            logger.info("Configuration validation PASSED")
        else:
            logger.error(f"Configuration validation FAILED with {len(self.errors)} error(s)")
        
        if self.warnings:
            logger.warning(f"Configuration has {len(self.warnings)} warning(s)")
        
        return is_valid, self.errors, self.warnings
    
    def _validate_server(self, server_cfg: Dict[str, Any]):
        """Validate server networking configuration"""
        if not isinstance(server_cfg, dict):
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
                            self.errors.append(f"server.{port_key}: Invalid port {port} (must be 1-65535)")
                        elif port < 1024:
                            self.warnings.append(f"server.{port_key}: Port {port} requires root/admin privileges")
        
        # Check modes
        valid_ecs_modes = ['none', 'preserve', 'add']
        ecs_mode = server_cfg.get('forward_ecs_mode', 'none')
        if ecs_mode not in valid_ecs_modes:
            self.errors.append(f"server.forward_ecs_mode: Invalid mode '{ecs_mode}', must be one of {valid_ecs_modes}")
        
        valid_mac_modes = ['none', 'preserve', 'add']
        mac_mode = server_cfg.get('forward_mac_mode', 'none')
        if mac_mode not in valid_mac_modes:
            self.errors.append(f"server.forward_mac_mode: Invalid mode '{mac_mode}', must be one of {valid_mac_modes}")
    
    def _validate_upstream(self, upstream_cfg: Dict[str, Any]):
        """Validate upstream resolver configuration"""
        if not isinstance(upstream_cfg, dict):
            self.errors.append("upstream: Must be a dictionary")
            return
        
        # Check mode
        valid_modes = ['none', 'random', 'roundrobin', 'fastest', 'failover', 'sticky', 'loadbalance']
        mode = upstream_cfg.get('mode', 'fastest')
        if mode not in valid_modes:
            self.errors.append(f"upstream.mode: Invalid mode '{mode}', must be one of {valid_modes}")
        
        # Check intervals
        monitor_interval = upstream_cfg.get('monitor_interval')
        if monitor_interval is not None:
            if not isinstance(monitor_interval, (int, float)) or monitor_interval < 1:
                self.errors.append(f"upstream.monitor_interval: Must be a number >= 1, got {monitor_interval}")
        
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
                    
                    # Check protocol if specified
                    if '://' in server:
                        proto = server.split('://')[0]
                        if proto not in ['udp', 'tcp']:
                            self.errors.append(f"upstream.bootstrap: Invalid protocol '{proto}' in '{server}'")
                    
                    # Extract and validate IP (inline)
                    ip_part = server
                    if '://' in ip_part:
                        ip_part = ip_part.split('://', 1)[1]
                    if ip_part.startswith('['):
                        bracket_end = ip_part.find(']')
                        if bracket_end > 0:
                            ip_part = ip_part[1:bracket_end]
                        else:
                            ip_part = ip_part[1:]
                    elif '.' in ip_part:
                        ip_part = ip_part.split(':')[0]
                    elif ip_part.count(':') > 1:
                        pass  # Bare IPv6
                    else:
                        ip_part = ip_part.rsplit(':', 1)[0]
                    
                    if not is_valid_ip(ip_part):
                        self.errors.append(f"upstream.bootstrap: Invalid IP '{ip_part}' in '{server}'")
        
        # Check groups
        groups = upstream_cfg.get('groups', {})
        if not isinstance(groups, dict):
            self.errors.append("upstream.groups: Must be a dictionary")
        else:
            if not groups:
                self.warnings.append("upstream.groups: No upstream groups configured")
            
            for group_name, group_data in groups.items():
                if not isinstance(group_data, dict):
                    self.errors.append(f"upstream.groups.{group_name}: Must be a dictionary")
                    continue
                
                servers = group_data.get('servers', [])
                if not isinstance(servers, list):
                    self.errors.append(f"upstream.groups.{group_name}.servers: Must be a list")
                elif not servers:
                    self.warnings.append(f"upstream.groups.{group_name}: No servers configured")
        
        # Circuit breaker settings
        if upstream_cfg.get('circuit_breaker_enabled', True):
            threshold = upstream_cfg.get('circuit_failure_threshold', 3)
            if not isinstance(threshold, int) or threshold < 1:
                self.errors.append(f"upstream.circuit_failure_threshold: Must be integer >= 1, got {threshold}")
            
            timeout = upstream_cfg.get('circuit_recovery_timeout', 30)
            if not isinstance(timeout, (int, float)) or timeout < 1:
                self.errors.append(f"upstream.circuit_recovery_timeout: Must be number >= 1, got {timeout}")
    
    def _validate_cache(self, cache_cfg: Dict[str, Any]):
        """Validate cache configuration"""
        if not isinstance(cache_cfg, dict):
            self.errors.append("cache: Must be a dictionary")
            return
        
        size = cache_cfg.get('size', 10000)
        if not isinstance(size, int) or size < 0:
            self.errors.append(f"cache.size: Must be non-negative integer, got {size}")
        
        if size == 0:
            self.warnings.append("cache.size: Cache disabled (size = 0)")
        elif size < 100:
            self.warnings.append(f"cache.size: Very small cache ({size}), consider increasing")
        
        gc_interval = cache_cfg.get('gc_interval', 300)
        if not isinstance(gc_interval, (int, float)) or gc_interval < 1:
            self.errors.append(f"cache.gc_interval: Must be number >= 1, got {gc_interval}")
        
        negative_ttl = cache_cfg.get('negative_ttl', 60)
        if not isinstance(negative_ttl, (int, float)) or negative_ttl < 0:
            self.errors.append(f"cache.negative_ttl: Must be non-negative number, got {negative_ttl}")
        
        prefetch_margin = cache_cfg.get('prefetch_margin', 0)
        if not isinstance(prefetch_margin, (int, float)) or prefetch_margin < 0:
            self.errors.append(f"cache.prefetch_margin: Must be non-negative number, got {prefetch_margin}")
    
    def _validate_rate_limit(self, rate_cfg: Dict[str, Any]):
        """Validate rate limiting configuration"""
        if not isinstance(rate_cfg, dict):
            self.errors.append("rate_limit: Must be a dictionary")
            return
        
        if not rate_cfg.get('enabled', True):
            self.warnings.append("rate_limit: Rate limiting is disabled")
        
        window = rate_cfg.get('window_seconds', 60)
        if not isinstance(window, (int, float)) or window < 1:
            self.errors.append(f"rate_limit.window_seconds: Must be number >= 1, got {window}")
        
        for key in ['ipv4_mask', 'ipv6_mask']:
            mask = rate_cfg.get(key)
            if mask is not None:
                max_mask = 32 if key == 'ipv4_mask' else 128
                if not isinstance(mask, int) or mask < 0 or mask > max_mask:
                    self.errors.append(f"rate_limit.{key}: Must be 0-{max_mask}, got {mask}")
        
        for key in ['udp_threshold', 'total_threshold']:
            threshold = rate_cfg.get(key)
            if threshold is not None:
                if not isinstance(threshold, int) or threshold < 1:
                    self.errors.append(f"rate_limit.{key}: Must be integer >= 1, got {threshold}")
    
    def _validate_response(self, response_cfg: Dict[str, Any]):
        """Validate response modification configuration"""
        if not isinstance(response_cfg, dict):
            self.errors.append("response: Must be a dictionary")
            return
        
        # Check rcode
        valid_rcodes = ['REFUSED', 'NXDOMAIN', 'NOERROR', 'SERVFAIL']
        rcode = response_cfg.get('block_rcode', 'REFUSED')
        if rcode not in valid_rcodes:
            self.errors.append(f"response.block_rcode: Invalid rcode '{rcode}', must be one of {valid_rcodes}")
        
        # Check block_ip
        block_ip = response_cfg.get('block_ip')
        if block_ip and block_ip != 'NULL':
            if not is_valid_ip(block_ip):
                self.errors.append(f"response.block_ip: Invalid IP address '{block_ip}'")
        
        # Check TTL values
        for key in ['block_ttl', 'min_ttl', 'max_ttl']:
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
            
        # Check cname empty rcode
        valid_empty_rcodes = ['NXDOMAIN', 'NOERROR']
        empty_rcode = response_cfg.get('cname_empty_rcode', 'NXDOMAIN')
        if empty_rcode not in valid_empty_rcodes:
             self.errors.append(f"response.cname_empty_rcode: Invalid rcode '{empty_rcode}', must be one of {valid_empty_rcodes}")
    
    def _is_valid_mac(self, mac_str: str) -> bool:
        """Validate MAC address format (inlined)"""
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac_str))
    
    def _validate_groups(self, groups_cfg: Dict[str, Any]):
        """Validate client groups configuration"""
        if not isinstance(groups_cfg, dict):
            self.errors.append("groups: Must be a dictionary")
            return
        
        for group_name, identifiers in groups_cfg.items():
            if not isinstance(identifiers, list):
                self.errors.append(f"groups.{group_name}: Must be a list")
                continue
            
            for ident in identifiers:
                if not isinstance(ident, str):
                    self.errors.append(f"groups.{group_name}: Invalid identifier '{ident}' (must be string)")
                    continue
                
                ident_lower = ident.lower()
                
                # Check special identifiers
                if ident_lower.startswith('server_ip:'):
                    ip = ident_lower[10:]
                    if not is_valid_ip(ip):
                        self.errors.append(f"groups.{group_name}: Invalid server_ip '{ip}'")
                
                elif ident_lower.startswith('server_port:'):
                    try:
                        port = int(ident_lower[12:])
                        if port < 1 or port > 65535:
                            self.errors.append(f"groups.{group_name}: Invalid server_port {port}")
                    except ValueError:
                        self.errors.append(f"groups.{group_name}: Invalid server_port format '{ident}'")
                
                elif '/' in ident and not ident.startswith('path:'):
                    # CIDR notation
                    if not is_valid_cidr(ident):
                        self.errors.append(f"groups.{group_name}: Invalid CIDR '{ident}'")
                
                elif ':' in ident and len(ident.split(':')) >= 5:
                    # Could be MAC address or IPv6
                    if self._is_valid_mac(ident):
                        continue  # Valid MAC
                    elif is_valid_ip(ident):
                        continue  # Valid IPv6
                    else:
                        self.warnings.append(f"groups.{group_name}: Ambiguous identifier '{ident}' (MAC or IPv6?)")
                
                else:
                    # Could be bare IP or other identifier
                    if '.' in ident or ':' in ident:
                        if not is_valid_ip(ident):
                            self.errors.append(f"groups.{group_name}: Invalid IP address '{ident}'")
    
    def _validate_schedules(self, schedules_cfg: Dict[str, Any]):
        """Validate schedule configuration"""
        if not isinstance(schedules_cfg, dict):
            self.errors.append("schedules: Must be a dictionary")
            return
        
        valid_days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        time_pattern = re.compile(r'^([01]?\d|2[0-3]):[0-5]\d$')
        
        for schedule_name, schedule_data in schedules_cfg.items():
            # Handle both dict and list formats
            if isinstance(schedule_data, dict):
                schedule_data = [schedule_data]
            
            if not isinstance(schedule_data, list):
                self.errors.append(f"schedules.{schedule_name}: Must be a dictionary or list")
                continue
            
            for block in schedule_data:
                if not isinstance(block, dict):
                    self.errors.append(f"schedules.{schedule_name}: Schedule block must be a dictionary")
                    continue
                
                # Check days
                days = block.get('days', [])
                if days:
                    if not isinstance(days, list):
                        self.errors.append(f"schedules.{schedule_name}: 'days' must be a list")
                    else:
                        for day in days:
                            if day not in valid_days:
                                self.errors.append(f"schedules.{schedule_name}: Invalid day '{day}', must be one of {valid_days}")
                
                # Check times
                for time_key in ['start', 'end']:
                    time_val = block.get(time_key)
                    if time_val:
                        if not isinstance(time_val, str) or not time_pattern.match(time_val):
                            self.errors.append(f"schedules.{schedule_name}: Invalid {time_key} time '{time_val}', must be HH:MM format")
    
    def _validate_assignments(self, assignments_cfg: Dict[str, Any], policies_cfg: Dict[str, Any], schedules_cfg: Dict[str, Any]):
        """Validate policy assignments"""
        if not isinstance(assignments_cfg, dict):
            self.errors.append("assignments: Must be a dictionary")
            return
        
        for group_name, assignment in assignments_cfg.items():
            if not isinstance(assignment, dict):
                self.errors.append(f"assignments.{group_name}: Must be a dictionary")
                continue
            
            # Check policy exists
            policy_name = assignment.get('policy')
            if policy_name:
                if policy_name != 'BLOCK' and policy_name not in policies_cfg:
                    self.errors.append(f"assignments.{group_name}: References non-existent policy '{policy_name}'")
            
            # Check schedule exists
            schedule_name = assignment.get('schedule')
            if schedule_name and schedule_name not in schedules_cfg:
                self.errors.append(f"assignments.{group_name}: References non-existent schedule '{schedule_name}'")
            
            # Check schedule_policy
            schedule_policy = assignment.get('schedule_policy')
            if schedule_policy:
                if schedule_policy != 'BLOCK' and schedule_policy not in policies_cfg:
                    self.errors.append(f"assignments.{group_name}: schedule_policy references non-existent policy '{schedule_policy}'")
    
    def _validate_policies(self, policies_cfg: Dict[str, Any], lists_cfg: Dict[str, Any]):
        """Validate policy definitions"""
        if not isinstance(policies_cfg, dict):
            self.errors.append("policies: Must be a dictionary")
            return
        
        if not policies_cfg:
            self.warnings.append("policies: No policies configured")
        
        valid_qtypes = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT', 
            'SRV', 'HTTPS', 'SVCB', 'CAA', 'DNSKEY', 'RRSIG', 'NSEC', 
            'DS', 'TLSA', 'ANY', 'AXFR', 'IXFR', 'NULL', 'HINFO'
        ]
        
        for policy_name, policy_data in policies_cfg.items():
            if not isinstance(policy_data, dict):
                self.errors.append(f"policies.{policy_name}: Must be a dictionary")
                continue
            
            # Check list references
            for list_type in ['allow', 'block']:
                list_names = policy_data.get(list_type, [])
                if not isinstance(list_names, list):
                    self.errors.append(f"policies.{policy_name}.{list_type}: Must be a list")
                else:
                    for list_name in list_names:
                        if list_name not in lists_cfg:
                            self.errors.append(f"policies.{policy_name}: References non-existent list '{list_name}'")
            
            # Check query types
            for type_list in ['allowed_types', 'blocked_types']:
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
                for cat_name, cat_rule in category_rules.items():
                    if not isinstance(cat_rule, dict):
                        self.errors.append(f"policies.{policy_name}.category_rules.{cat_name}: Must be a dictionary")
                        continue
                    
                    min_conf = cat_rule.get('min_confidence', 0)
                    if not isinstance(min_conf, (int, float)) or min_conf < 0 or min_conf > 100:
                        self.errors.append(f"policies.{policy_name}.category_rules.{cat_name}: min_confidence must be 0-100")
                    
                    action = cat_rule.get('action', 'ALLOW')
                    if action not in ['ALLOW', 'BLOCK']:
                        self.errors.append(f"policies.{policy_name}.category_rules.{cat_name}: action must be 'ALLOW' or 'BLOCK'")
    
    def _validate_lists(self, lists_cfg: Dict[str, Any]):
        """Validate filter lists configuration"""
        if not isinstance(lists_cfg, dict):
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
                    
                    valid_types = ['exact', 'inclusive', 'exclusive']
                    if domain_type not in valid_types:
                        self.errors.append(f"lists.{list_name}: Invalid hosts_domain_type '{domain_type}', must be one of {valid_types}")
                
                elif not isinstance(source, str):
                    self.errors.append(f"lists.{list_name}: Source must be string or dictionary")


def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
    """
    Convenience function to validate configuration.
    
    Returns:
        (is_valid, errors, warnings)
    """
    validator = ConfigValidator()
    return validator.validate(config)

