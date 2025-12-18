#!/usr/bin/env python3
# filename: config_validator.py
# Version: 4.1.0 (Added QNAME Minimization Support)
"""
Configuration Validation Module with DoH/DoT and Recursive/DNSSEC support
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
                self.errors.append("logging.file_path: Must be string")
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

        bind_ifaces = server_cfg.get('bind_interfaces')
        if bind_ifaces is not None:
            if isinstance(bind_ifaces, str):
                bind_ifaces = [bind_ifaces]
            if not isinstance(bind_ifaces, list):
                self.errors.append("server.bind_interfaces: Must be a string or list")

        for port_key in ['port_udp', 'port_tcp']:
            ports = server_cfg.get(port_key)
            if ports is not None:
                if isinstance(ports, int):
                    ports = [ports]
                if not isinstance(ports, list):
                    self.errors.append(f"server.{port_key}: Must be integer or list")
                else:
                    for port in ports:
                        if not isinstance(port, int) or port < 1 or port > 65535:
                            self.errors.append(f"server.{port_key}: Invalid port {port} (must be 1-65535)")

        udp_conc = server_cfg.get('udp_concurrency')
        if udp_conc is not None:
            if not isinstance(udp_conc, int) or udp_conc < 1:
                self.errors.append(f"server.udp_concurrency: Must be positive integer")

        for bool_key in ['use_ecs', 'use_edns_mac']:
            val = server_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"server.{bool_key}: Must be boolean")

        valid_ecs_modes = ['none', 'preserve', 'add', 'privacy', 'override']
        ecs_mode = server_cfg.get('forward_ecs_mode', 'none')
        if ecs_mode not in valid_ecs_modes:
            self.errors.append(f"server.forward_ecs_mode: Must be one of {valid_ecs_modes}")

        valid_mac_modes = ['none', 'preserve', 'add']
        mac_mode = server_cfg.get('forward_mac_mode', 'none')
        if mac_mode not in valid_mac_modes:
            self.errors.append(f"server.forward_mac_mode: Must be one of {valid_mac_modes}")

        self._validate_tls(server_cfg.get('tls', {}))

    def _validate_tls(self, tls_cfg: Dict[str, Any]):
        """Validate TLS configuration for DoH/DoT"""
        if not isinstance(tls_cfg, dict):
            if tls_cfg is not None:
                self.errors.append("server.tls: Must be a dictionary")
            return

        for bool_key in ['enabled', 'enable_dot', 'enable_doh']:
            val = tls_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"server.tls.{bool_key}: Must be boolean")

        for port_key in ['port_dot', 'port_doh']:
            ports = tls_cfg.get(port_key)
            if ports is not None:
                if isinstance(ports, int):
                    ports = [ports]
                if not isinstance(ports, list):
                    self.errors.append(f"server.tls.{port_key}: Must be integer or list")
                else:
                    for port in ports:
                        if not isinstance(port, int) or port < 1 or port > 65535:
                            self.errors.append(f"server.tls.{port_key}: Invalid port {port}")

        enabled = tls_cfg.get('enabled', False)
        if enabled:
            cert_file = tls_cfg.get('cert_file')
            key_file = tls_cfg.get('key_file')

            if not cert_file:
                self.errors.append("server.tls.cert_file: Required when TLS is enabled")
            elif not isinstance(cert_file, str):
                self.errors.append("server.tls.cert_file: Must be string")
            elif not os.path.isfile(cert_file):
                self.errors.append(f"server.tls.cert_file: File '{cert_file}' not found")

            if not key_file:
                self.errors.append("server.tls.key_file: Required when TLS is enabled")
            elif not isinstance(key_file, str):
                self.errors.append("server.tls.key_file: Must be string")
            elif not os.path.isfile(key_file):
                self.errors.append(f"server.tls.key_file: File '{key_file}' not found")

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

    # =========================================================================
    # UPSTREAM SECTION
    # =========================================================================
    def _validate_upstream(self, upstream_cfg: Dict[str, Any]):
        """Validate upstream resolver configuration"""
        if not isinstance(upstream_cfg, dict):
            if upstream_cfg is not None:
                self.errors.append("upstream: Must be a dictionary")
            return

        valid_modes = ['none', 'random', 'roundrobin', 'fastest', 'failover', 'sticky', 'loadbalance', 'distributed']
        mode = upstream_cfg.get('mode', 'fastest')
        if mode not in valid_modes:
            self.errors.append(f"upstream.mode: Invalid mode '{mode}', must be one of {valid_modes}")

        # Validate recursive configuration
        self._validate_recursive(upstream_cfg.get('recursive', {}))

    def _validate_recursive(self, recursive_cfg: Dict[str, Any]):
        """Validate recursive resolution configuration"""
        if not isinstance(recursive_cfg, dict):
            if recursive_cfg is not None:
                self.errors.append("upstream.recursive: Must be a dictionary")
            return

        enabled = recursive_cfg.get('enabled')
        if enabled is not None and not isinstance(enabled, bool):
            self.errors.append("upstream.recursive.enabled: Must be boolean")

        # Validate QNAME minimization and IPv6 preference
        for bool_key in ['prefer_ipv6', 'qname_minimization']:
            val = recursive_cfg.get(bool_key)
            if val is not None and not isinstance(val, bool):
                self.errors.append(f"upstream.recursive.{bool_key}: Must be boolean")

        for int_key in ['query_timeout', 'ns_cache_size', 'ns_cache_ttl']:
            val = recursive_cfg.get(int_key)
            if val is not None:
                if not isinstance(val, int) or val < 1:
                    self.errors.append(f"upstream.recursive.{int_key}: Must be positive integer")

        self._validate_root_hints(recursive_cfg.get('root_hints', {}))
        self._validate_trust_anchors(recursive_cfg.get('trust_anchors', {}))
        self._validate_dnssec(recursive_cfg.get('dnssec', {}))

    def _validate_root_hints(self, root_hints_cfg: Dict[str, Any]):
        """Validate root hints configuration"""
        if not isinstance(root_hints_cfg, dict):
            if root_hints_cfg is not None:
                self.errors.append("upstream.recursive.root_hints: Must be a dictionary")
            return

        valid_sources = ['builtin', 'url', 'file']
        source = root_hints_cfg.get('source', 'builtin')
        if source not in valid_sources:
            self.errors.append(f"upstream.recursive.root_hints.source: Must be one of {valid_sources}")

        if source == 'url':
            url = root_hints_cfg.get('url')
            if not url:
                self.errors.append("upstream.recursive.root_hints.url: Required when source is 'url'")
            elif not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                self.errors.append("upstream.recursive.root_hints.url: Must be valid HTTP(S) URL")

        if source == 'file':
            file_path = root_hints_cfg.get('file')
            if not file_path:
                self.errors.append("upstream.recursive.root_hints.file: Required when source is 'file'")
            elif not isinstance(file_path, str):
                self.errors.append("upstream.recursive.root_hints.file: Must be string")
            elif not os.path.isfile(file_path):
                self.warnings.append(f"upstream.recursive.root_hints.file: File '{file_path}' not found")

    def _validate_trust_anchors(self, trust_anchors_cfg: Dict[str, Any]):
        """Validate trust anchors configuration"""
        if not isinstance(trust_anchors_cfg, dict):
            if trust_anchors_cfg is not None:
                self.errors.append("upstream.recursive.trust_anchors: Must be a dictionary")
            return

        valid_sources = ['builtin', 'url', 'file']
        source = trust_anchors_cfg.get('source', 'builtin')
        if source not in valid_sources:
            self.errors.append(f"upstream.recursive.trust_anchors.source: Must be one of {valid_sources}")

        if source == 'url':
            url = trust_anchors_cfg.get('url')
            if not url:
                self.errors.append("upstream.recursive.trust_anchors.url: Required when source is 'url'")
            elif not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                self.errors.append("upstream.recursive.trust_anchors.url: Must be valid HTTP(S) URL")

        if source == 'file':
            file_path = trust_anchors_cfg.get('file')
            if not file_path:
                self.errors.append("upstream.recursive.trust_anchors.file: Required when source is 'file'")
            elif not isinstance(file_path, str):
                self.errors.append("upstream.recursive.trust_anchors.file: Must be string")
            elif not os.path.isfile(file_path):
                self.warnings.append(f"upstream.recursive.trust_anchors.file: File '{file_path}' not found")

    def _validate_dnssec(self, dnssec_cfg: Dict[str, Any]):
        """Validate DNSSEC configuration"""
        if not isinstance(dnssec_cfg, dict):
            if dnssec_cfg is not None:
                self.errors.append("upstream.recursive.dnssec: Must be a dictionary")
            return

        valid_modes = ['none', 'log', 'standard', 'strict']
        mode = dnssec_cfg.get('mode', 'none')
        if mode not in valid_modes:
            self.errors.append(f"upstream.recursive.dnssec.mode: Must be one of {valid_modes}, got '{mode}'")

        valid_rcodes = ['SERVFAIL', 'REFUSED', 'NXDOMAIN', 'FORMERR', 'NOERROR']
        for rcode_key in ['validation_failure_rcode', 'unsigned_zone_rcode']:
            val = dnssec_cfg.get(rcode_key)
            if val is not None:
                if not isinstance(val, str) or val.upper() not in valid_rcodes:
                    self.errors.append(f"upstream.recursive.dnssec.{rcode_key}: Must be one of {valid_rcodes}")

        cache_validated = dnssec_cfg.get('cache_validated')
        if cache_validated is not None and not isinstance(cache_validated, bool):
            self.errors.append("upstream.recursive.dnssec.cache_validated: Must be boolean")

        cache_ttl = dnssec_cfg.get('cache_ttl')
        if cache_ttl is not None and (not isinstance(cache_ttl, int) or cache_ttl < 0):
            self.errors.append("upstream.recursive.dnssec.cache_ttl: Must be non-negative integer")

        disabled_algos = dnssec_cfg.get('disabled_algorithms')
        if disabled_algos is not None:
            if not isinstance(disabled_algos, list):
                self.errors.append("upstream.recursive.dnssec.disabled_algorithms: Must be list")
            else:
                for algo in disabled_algos:
                    if not isinstance(algo, int) or algo < 0 or algo > 255:
                        self.errors.append(f"upstream.recursive.dnssec.disabled_algorithms: Invalid '{algo}'")

    # =========================================================================
    # CACHE SECTION
    # =========================================================================
    def _validate_cache(self, cache_cfg: Dict[str, Any]):
        """Validate cache configuration"""
        if not isinstance(cache_cfg, dict):
            if cache_cfg is not None:
                self.errors.append("cache: Must be a dictionary")
            return

        for int_key in ['size', 'gc_interval', 'negative_ttl', 'prefetch_margin', 'prefetch_min_hits']:
            val = cache_cfg.get(int_key)
            if val is not None and (not isinstance(val, int) or val < 0):
                self.errors.append(f"cache.{int_key}: Must be non-negative integer")

    def _validate_decision_cache(self, dc_cfg: Dict[str, Any]):
        """Validate decision cache configuration"""
        if not isinstance(dc_cfg, dict):
            if dc_cfg is not None:
                self.errors.append("decision_cache: Must be a dictionary")
            return

    def _validate_deduplication(self, dedup_cfg: Dict[str, Any]):
        """Validate deduplication configuration"""
        if not isinstance(dedup_cfg, dict):
            if dedup_cfg is not None:
                self.errors.append("deduplication: Must be a dictionary")
            return

    def _validate_rate_limit(self, rate_cfg: Dict[str, Any]):
        """Validate rate limiting configuration"""
        if not isinstance(rate_cfg, dict):
            if rate_cfg is not None:
                self.errors.append("rate_limit: Must be a dictionary")
            return

    def _validate_response(self, resp_cfg: Dict[str, Any]):
        """Validate response configuration"""
        if not isinstance(resp_cfg, dict):
            if resp_cfg is not None:
                self.errors.append("response: Must be a dictionary")
            return

    def _validate_filtering(self, filtering_cfg: Dict[str, Any]):
        """Validate filtering configuration"""
        if not isinstance(filtering_cfg, dict):
            if filtering_cfg is not None:
                self.errors.append("filtering: Must be a dictionary")
            return

        valid_ptr_modes = ['none', 'strict']
        ptr_check = filtering_cfg.get('ptr_check')
        if ptr_check is not None and ptr_check not in valid_ptr_modes:
            self.errors.append(f"filtering.ptr_check: Must be one of {valid_ptr_modes}")

    def _validate_categorization(self, config: Dict[str, Any]):
        """Validate categorization options"""
        pass

    def _validate_groups(self, groups_cfg: Dict[str, Any]):
        """Validate client groups configuration"""
        if not isinstance(groups_cfg, dict):
            if groups_cfg is not None:
                self.errors.append("groups: Must be a dictionary")
            return

    def _validate_group_files(self, gf_cfg: Dict[str, Any]):
        """Validate group files configuration"""
        pass

    def _validate_schedules(self, schedules_cfg: Dict[str, Any]):
        """Validate schedule configuration"""
        pass

    def _validate_lists(self, lists_cfg: Dict[str, Any]):
        """Validate filter lists configuration"""
        pass

    def _validate_policies(self, policies_cfg: Dict[str, Any], lists_cfg: Dict[str, Any], upstream_cfg: Dict[str, Any]):
        """Validate policies configuration"""
        if not isinstance(policies_cfg, dict):
            if policies_cfg is not None:
                self.errors.append("policies: Must be a dictionary")
            return

        for pol_name, pol_cfg in policies_cfg.items():
            if not isinstance(pol_cfg, dict):
                self.errors.append(f"policies.{pol_name}: Must be a dictionary")
                continue

            # Validate resolution_mode
            valid_res_modes = ['forward', 'recursive']
            res_mode = pol_cfg.get('resolution_mode')
            if res_mode is not None and res_mode not in valid_res_modes:
                self.errors.append(f"policies.{pol_name}.resolution_mode: Must be one of {valid_res_modes}")

            # Validate dnssec_mode override
            valid_dnssec_modes = ['none', 'log', 'standard', 'strict']
            dnssec_mode = pol_cfg.get('dnssec_mode')
            if dnssec_mode is not None and dnssec_mode not in valid_dnssec_modes:
                self.errors.append(f"policies.{pol_name}.dnssec_mode: Must be one of {valid_dnssec_modes}")

    def _validate_assignments(self, assignments_cfg: Dict[str, Any], policies_cfg: Dict[str, Any],
                              schedules_cfg: Dict[str, Any], groups_cfg: Dict[str, Any]):
        """Validate policy assignments"""
        pass

    def _validate_top_level_options(self, config: Dict[str, Any]):
        """Validate top-level options"""
        pass

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
        if threshold is not None and (not isinstance(threshold, int) or threshold < 1 or threshold > 5):
            self.errors.append("heuristics.block_threshold: Must be integer 1-5")

        # Entropy thresholds
        for entropy_key in ['entropy_threshold_high', 'entropy_threshold_suspicious']:
            val = heur_cfg.get(entropy_key)
            if val is not None:
                if not isinstance(val, (int, float)) or val < 0 or val > 6:
                    self.errors.append(f"heuristics.{entropy_key}: Must be float 0.0-6.0")

        # Typosquat file
        typosquat_file = heur_cfg.get('typosquat_file')
        if typosquat_file is not None:
            if not isinstance(typosquat_file, str):
                self.errors.append("heuristics.typosquat_file: Must be string path")
            elif typosquat_file and not os.path.exists(typosquat_file):
                self.warnings.append(f"heuristics.typosquat_file: File not found '{typosquat_file}'")

        # TOP-N file
        topn_file = heur_cfg.get('topn_file')
        if topn_file is not None:
            if not isinstance(topn_file, str):
                self.errors.append("heuristics.topn_file: Must be string path")
            elif topn_file and not os.path.exists(topn_file):
                self.warnings.append(f"heuristics.topn_file: File not found '{topn_file}'")

        # TOP-N reduction
        topn_reduction = heur_cfg.get('topn_reduction')
        if topn_reduction is not None:
            if not isinstance(topn_reduction, int) or topn_reduction < 0 or topn_reduction > 5:
                self.errors.append("heuristics.topn_reduction: Must be integer 0-5")

def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
    """
    Convenience function to validate configuration.

    Returns:
        (is_valid, errors, warnings)
    """
    validator = ConfigValidator()
    return validator.validate(config)

