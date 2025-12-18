#!/usr/bin/env python3
# filename: heuristics.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.1.0 (RR-Type Aware Heuristics + TOP-N Whitelist)
# -----------------------------------------------------------------------------
"""
Heuristic analysis for identifying suspicious domains based on:
- Shannon Entropy (randomness)
- DGA patterns (Linguistic anomalies)
- Typosquatting (Levenshtein distance)
- Length and character composition
- TOP-N popular domains (score reduction for known-good domains)

Now includes RR-type awareness to prevent false positives for:
- PTR records (reverse DNS)
- SRV records (service discovery)
- DNSSEC records
- Other special record types
"""

import math
import os
import logging
import re
from typing import List, Tuple, Optional, Set
from utils import get_logger

logger = get_logger("Heuristics")

# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_TARGETS = [
    "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin",
    "paypal", "dropbox", "github", "gitlab", "salesforce"
]

HIGH_RISK_TLDS = {
    'xyz', 'top', 'club', 'work', 'loan', 'win', 'click', 'country',
    'kim', 'men', 'mom', 'party', 'review', 'science', 'stream',
    'trade', 'gdn', 'racing', 'jetzt', 'download', 'accountant',
    'bid', 'date', 'faith', 'pro', 'site', 'space', 'website', 'online',
    'zip', 'mov',
    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'sur', 'ci', 'sz'
}

# Domains that are structurally exempt from heuristics
EXEMPT_SUFFIXES = {
    'in-addr.arpa', 'ip6.arpa', 'local', 'localhost', 'home.arpa',
    'internal', 'private', 'corp', 'lan', 'home', 'onion', 'test',
    'example', 'invalid',
}

EXEMPT_PATTERNS = {
    '_tcp.', '_udp.', '_tls.', '_sctp.', '_domainkey.', '_dkim.',
    '_dmarc.', '_spf.', '_dsset.', '_sip.', '_sips.',
    '_xmpp-client.', '_xmpp-server.', '_http.', '_https.',
}

RELAXED_QTYPES = {
    'PTR', 'SRV', 'NAPTR', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'NSEC3PARAM',
    'RRSIG', 'CDNSKEY', 'CDS', 'TLSA', 'SSHFP', 'CAA', 'SMIMEA',
    'OPENPGPKEY', 'SVCB', 'HTTPS', 'TXT', 'ANY', 'AXFR', 'IXFR',
}


class DomainHeuristics:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        self.block_threshold = self.config.get('block_threshold', 4)

        # Entropy Config
        self.entropy_high = self.config.get('entropy_threshold_high', 3.8)
        self.entropy_suspicious = self.config.get('entropy_threshold_suspicious', 3.2)

        # Initialize Targets for typosquatting
        self.targets = set(DEFAULT_TARGETS)
        target_file = self.config.get('typosquat_file')
        if target_file:
            self._load_targets(target_file)

        # TOP-N Popular Domains (whitelist)
        self.topn_domains: Set[str] = set()
        self.topn_reduction = self.config.get('topn_reduction', 2)
        topn_file = self.config.get('topn_file')
        if topn_file:
            self._load_topn(topn_file)

        if self.enabled:
            logger.info(f"Heuristics enabled: threshold={self.block_threshold}, "
                       f"entropy_high={self.entropy_high}, entropy_suspicious={self.entropy_suspicious}, "
                       f"topn_domains={len(self.topn_domains)}, topn_reduction={self.topn_reduction}")

    def _load_targets(self, filepath: str):
        """Load typosquatting targets from file."""
        if not os.path.exists(filepath):
            if self.enabled:
                logger.warning(f"Typosquat file '{filepath}' not found. Using internal defaults.")
            return
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        self.targets.add(line)
            logger.info(f"Loaded {len(self.targets)} typosquat targets from '{filepath}'")
        except Exception as e:
            logger.error(f"Error loading typosquat file '{filepath}': {e}")

    def _load_topn(self, filepath: str):
        """
        Load TOP-N popular domains from file.
        
        File format: one 2LD domain per line (e.g. 'google.com', 'facebook.com')
        Lines starting with # are comments.
        """
        if not os.path.exists(filepath):
            if self.enabled:
                logger.warning(f"TOP-N file '{filepath}' not found. Feature disabled.")
            return
        try:
            count = 0
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        # Normalize: remove trailing dot if present
                        domain = line.rstrip('.')
                        self.topn_domains.add(domain)
                        count += 1
            logger.info(f"Loaded {count} TOP-N domains from '{filepath}'")
        except Exception as e:
            logger.error(f"Error loading TOP-N file '{filepath}': {e}")

    def _is_topn_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if domain is in TOP-N list or is a subdomain of one.
        
        Args:
            domain: Normalized domain name (lowercase, no trailing dot)
            
        Returns:
            Tuple of (is_match, matched_domain)
        """
        if not self.topn_domains:
            return False, None

        # Direct match
        if domain in self.topn_domains:
            return True, domain

        # Check if it's a subdomain of a TOP-N domain
        parts = domain.split('.')
        # Build progressively longer suffixes: a.b.c.com -> b.c.com -> c.com
        for i in range(1, len(parts)):
            suffix = '.'.join(parts[i:])
            if suffix in self.topn_domains:
                return True, suffix

        return False, None

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def _is_typosquat(self, label: str) -> bool:
        """Check if label is potential typosquat of a known target."""
        for target in self.targets:
            distance = self._levenshtein(label, target)
            threshold = max(1, len(target) // 4)
            if 0 < distance <= threshold:
                return True
        return False

    def _check_dga(self, label: str) -> Tuple[int, str]:
        """
        Check for DGA (Domain Generation Algorithm) patterns.
        Returns: (Score Penalty, Reason)
        """
        if len(label) < 5:
            return 0, ""
        if label.isdigit():
            return 0, ""

        score = 0
        reasons = []

        # Consonant streak analysis
        consonants = "bcdfghjklmnpqrstvwxz"
        max_streak = 0
        current_streak = 0
        for char in label:
            if char in consonants:
                current_streak += 1
                max_streak = max(max_streak, current_streak)
            else:
                current_streak = 0
        if max_streak >= 5:
            score += 2
            reasons.append(f"Consonant streak ({max_streak})")

        # Vowel ratio analysis
        vowels = "aeiouy"
        vowel_count = sum(1 for c in label if c in vowels)
        ratio = vowel_count / len(label)
        if ratio < 0.15:
            score += 1
            reasons.append(f"Low vowel ratio ({ratio:.0%})")

        # Repeated character analysis
        if re.search(r'(.)\1\1\1', label):
            score += 1
            reasons.append("Repeated chars")

        return score, ", ".join(reasons)

    def is_exempt(self, domain: str, qtype_str: Optional[str] = None) -> Tuple[bool, str]:
        """Check if domain/qtype combination is exempt from heuristics."""
        if qtype_str and qtype_str.upper() in RELAXED_QTYPES:
            return True, f"qtype={qtype_str}"

        clean = domain.rstrip('.').lower()
        parts = clean.split('.')

        if parts:
            tld = parts[-1]
            if tld in EXEMPT_SUFFIXES:
                return True, f"exempt TLD .{tld}"

        if len(parts) >= 2:
            suffix = f"{parts[-2]}.{parts[-1]}"
            if suffix in EXEMPT_SUFFIXES:
                return True, f"exempt suffix .{suffix}"

        for pattern in EXEMPT_PATTERNS:
            if pattern in clean:
                return True, f"exempt pattern {pattern}"

        for part in parts:
            if part.startswith('_'):
                return True, f"service label _{part[1:]}"

        return False, ""

    def analyze(self, domain: str, qtype_str: Optional[str] = None) -> Tuple[int, List[str]]:
        """
        Analyze domain for suspicious patterns.
        
        Args:
            domain: The domain name to analyze
            qtype_str: Optional query type for context-aware analysis
        
        Returns:
            Tuple of (score, list of reasons)
        """
        if not self.enabled or not domain:
            return 0, []

        clean_domain = domain.rstrip('.').lower()
        debug_on = logger.isEnabledFor(logging.DEBUG)

        # Check exemptions first
        is_exempt, exempt_reason = self.is_exempt(clean_domain, qtype_str)
        if is_exempt:
            if debug_on:
                logger.debug(f"Heuristics skipped for {clean_domain} ({exempt_reason})")
            return 0, []

        score = 0
        reasons = []
        parts = clean_domain.split('.')

        if debug_on:
            logger.debug(f"Analyzing heuristics for: {clean_domain}")

        # --- TOP-N Check (early, applies score reduction) ---
        is_topn, topn_match = self._is_topn_domain(clean_domain)
        topn_applied = False

        # 1. High-Risk TLD
        if parts:
            tld = parts[-1].lower()
            if tld in HIGH_RISK_TLDS:
                score += 2
                reasons.append(f"High-risk TLD (.{tld})")
                if debug_on:
                    logger.debug(f"  [+] Penalty: High-risk TLD '.{tld}' -> Score: {score}")

        # 2. Label Count
        if len(parts) > 4:
            score += 1
            reasons.append(f"High label count ({len(parts)})")
            if debug_on:
                logger.debug(f"  [+] Penalty: High label count ({len(parts)}) -> Score: {score}")

        total_len = len(clean_domain)

        # 3. Total Length
        if total_len > 80:
            score += 1
            reasons.append(f"Excessive total length ({total_len})")
            if debug_on:
                logger.debug(f"  [+] Penalty: Excessive length ({total_len}) -> Score: {score}")

        max_entropy = 0.0
        max_hyphens = 0
        digit_count = sum(c.isdigit() for c in clean_domain)

        for part in parts:
            if not part:
                continue
            if part.startswith('_'):
                continue

            # 4. Entropy
            entropy = self._shannon_entropy(part)
            max_entropy = max(max_entropy, entropy)

            # 5. Hyphens
            hyphens = part.count('-')
            max_hyphens = max(max_hyphens, hyphens)

            # 6. Long label
            if len(part) > 30:
                score += 1
                reasons.append(f"Very long label: {part[:10]}...")
                if debug_on:
                    logger.debug(f"  [+] Penalty: Long label '{part[:15]}...' -> Score: {score}")

            # 7. Typosquatting
            if len(part) > 3 and self._is_typosquat(part):
                score += 4
                reasons.append(f"Possible typosquatting: {part}")
                if debug_on:
                    logger.debug(f"  [+] Penalty: Typosquatting '{part}' -> Score: {score}")

            # 8. Numeric Label
            if part.isdigit():
                score += 1
                reasons.append(f"Numeric label '{part}'")
                if debug_on:
                    logger.debug(f"  [+] Penalty: Numeric label '{part}' -> Score: {score}")

            # 9. DGA Check
            dga_score, dga_reason = self._check_dga(part)
            if dga_score > 0:
                score += dga_score
                reasons.append(f"DGA: {part} ({dga_reason})")
                if debug_on:
                    logger.debug(f"  [+] Penalty: DGA '{part}' ({dga_reason}) -> Score: {score}")

        # Evaluate Aggregates
        if max_entropy > self.entropy_high:
            score += 3
            reasons.append(f"High entropy ({max_entropy:.2f})")
            if debug_on:
                logger.debug(f"  [+] Penalty: High entropy ({max_entropy:.2f}) -> Score: {score}")
        elif max_entropy > self.entropy_suspicious:
            score += 1
            reasons.append(f"Suspicious entropy ({max_entropy:.2f})")
            if debug_on:
                logger.debug(f"  [+] Penalty: Suspicious entropy ({max_entropy:.2f}) -> Score: {score}")

        if max_hyphens > 1:
            score += 1
            reasons.append(f"Excessive hyphens ({max_hyphens})")
            if debug_on:
                logger.debug(f"  [+] Penalty: Excessive hyphens ({max_hyphens}) -> Score: {score}")

        if total_len > 0 and (digit_count / total_len) > 0.30:
            score += 1
            reasons.append(f"High numeric volume ({digit_count}/{total_len})")
            if debug_on:
                logger.debug(f"  [+] Penalty: High numeric volume ({digit_count}/{total_len}) -> Score: {score}")

        # --- Apply TOP-N reduction at the end ---
        if is_topn and score > 0:
            old_score = score
            score = max(0, score - self.topn_reduction)
            topn_applied = True
            reasons.append(f"TOP-N domain ({topn_match}) -{self.topn_reduction}")
            if debug_on:
                logger.debug(f"  [-] TOP-N reduction: {topn_match} -> Score: {old_score} - {self.topn_reduction} = {score}")

        final_score = min(5, score)
        if debug_on and (final_score > 0 or topn_applied):
            logger.debug(f"  = Final Score: {final_score}/5 | Reasons: {reasons}")

        return final_score, reasons

