#!/usr/bin/env python3
# filename: heuristics.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.5.0 (Added High-Risk TLD Check)
# -----------------------------------------------------------------------------
"""
Heuristic analysis for identifying suspicious domains based on:
- Shannon Entropy (randomness)
- DGA patterns (Consonant/Vowel ratio)
- Typosquatting (Levenshtein distance)
- Length and character composition abnormalities
- Numeric-only labels
- High-Risk TLDs
"""

import math
import os
import logging
from typing import List, Tuple
from utils import get_logger

logger = get_logger("Heuristics")

# Internal Fallback Defaults for Typosquatting
DEFAULT_TARGETS = [
    "google", "facebook", "amazon", "apple", "microsoft", 
    "netflix", "instagram", "whatsapp", "twitter", "linkedin",
    "paypal", "dropbox", "github", "gitlab", "salesforce"
]

# TLDs frequently associated with abuse, phishing, or malware.
# Sources: Spamhaus, abuse.ch, and recent security research (e.g. .zip/.mov)
HIGH_RISK_TLDS = {
    # Risky gTLDs (Cheap/Spammy)
    'xyz', 'top', 'club', 'work', 'loan', 'win', 'click', 'country', 
    'kim', 'men', 'mom', 'party', 'review', 'science', 'stream', 
    'trade', 'gdn', 'racing', 'jetzt', 'download', 'accountant', 
    'bid', 'date', 'faith', 'pro', 'site', 'space', 'website', 'online',
    
    # Deceptive gTLDs (File extensions)
    'zip', 'mov',
    
    # Often abused ccTLDs (Freenom/Free domains)
    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'sur', 'ci', 'sz'
}

class DomainHeuristics:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        self.block_threshold = self.config.get('block_threshold', 4)
        
        # Initialize with defaults using a Set for performance/deduplication
        self.targets = set(DEFAULT_TARGETS)
        
        # Load external targets if configured
        target_file = self.config.get('typosquat_file')
        if target_file:
            self._load_targets(target_file)
            
    def _load_targets(self, filepath: str):
        """Load targets from file and merge with defaults."""
        if not os.path.exists(filepath):
            if self.enabled:
                logger.warning(f"Typosquat file '{filepath}' not found. Using internal defaults.")
            return

        try:
            count = 0
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        self.targets.add(line)
                        count += 1
            logger.info(f"Loaded {count} typosquat targets from {filepath}")
        except Exception as e:
            logger.error(f"Error loading typosquat targets: {e}")

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        length = len(text)
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    def _is_typosquat(self, label: str) -> bool:
        """Check if label is 1 edit distance away from a target."""
        label_len = len(label)
        
        for target in self.targets:
            # Optimization: Only check if lengths are close
            if abs(label_len - len(target)) > 1:
                continue
            
            # Skip exact matches (valid domains)
            if label == target:
                continue
            
            dist = self._levenshtein(label, target)
            if dist == 1:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"    - Typosquat match: '{label}' ~= '{target}'")
                return True
        return False

    def analyze(self, domain: str) -> Tuple[int, List[str]]:
        """
        Analyze domain and return a score (0-5) and list of reasons.
        """
        if not self.enabled or not domain:
            return 0, []

        score = 0
        reasons = []
        
        clean_domain = domain.rstrip('.')
        parts = clean_domain.split('.')
        
        # Debug: Start Analysis
        debug_on = logger.isEnabledFor(logging.DEBUG)
        if debug_on:
            logger.debug(f"Analyzing heuristics for: {clean_domain}")
        
        # 1. High-Risk TLD Check (New)
        if parts:
            tld = parts[-1].lower()
            if tld in HIGH_RISK_TLDS:
                score += 2
                reasons.append(f"High-risk TLD (.{tld})")
                if debug_on: logger.debug(f"  [+] Penalty: High-risk TLD '.{tld}' -> Score: {score}")

        # 2. Label Count (Increased sensitivity: > 4)
        if len(parts) > 4:
            score += 1
            reasons.append(f"High label count ({len(parts)})")
            if debug_on: logger.debug(f"  [+] Penalty: High label count ({len(parts)}) -> Score: {score}")
            
        total_len = len(clean_domain)
        
        # 3. Total Length (Increased sensitivity: > 80 chars)
        if total_len > 80:
            score += 1
            reasons.append(f"Excessive total length ({total_len})")
            if debug_on: logger.debug(f"  [+] Penalty: Excessive length ({total_len}) -> Score: {score}")

        max_entropy = 0.0
        max_hyphens = 0
        digit_count = sum(c.isdigit() for c in clean_domain)
        
        for part in parts:
            if not part: continue
            
            # 4. Entropy Check
            entropy = self._shannon_entropy(part)
            max_entropy = max(max_entropy, entropy)
            
            # 5. Hyphen Check
            hyphens = part.count('-')
            max_hyphens = max(max_hyphens, hyphens)
            
            # 6. Length Check (Label) (Increased sensitivity: > 30 chars)
            if len(part) > 30:
                score += 1
                reasons.append(f"Very long label: {part[:10]}...")
                if debug_on: logger.debug(f"  [+] Penalty: Long label '{part[:15]}...' -> Score: {score}")
                
            # 7. Typosquatting (Length check > 3 to avoid false positives on short words)
            if len(part) > 3 and self._is_typosquat(part):
                score += 4 # High penalty
                reasons.append(f"Possible typosquatting: {part}")
                if debug_on: logger.debug(f"  [+] Penalty: Typosquatting '{part}' -> Score: {score}")

            # 8. Numeric Label Check
            if part.isdigit():
                score += 1
                reasons.append(f"Numeric label '{part}'")
                if debug_on: logger.debug(f"  [+] Penalty: Numeric label '{part}' -> Score: {score}")

            # 9. DGA Pattern (Consonant to Vowel Ratio)
            # Increased sensitivity: Check labels > 6 chars
            if len(part) > 6 and not any(char in 'aeiou' for char in part):
                if not part.isdigit():
                    score += 2
                    reasons.append(f"DGA pattern (No vowels): {part}")
                    if debug_on: logger.debug(f"  [+] Penalty: DGA pattern (no vowels) '{part}' -> Score: {score}")

        # Evaluate aggregates (Sensitivity Increased)
        if max_entropy > 3.8: # Was 4.2
            score += 3
            reasons.append(f"High entropy ({max_entropy:.2f})")
            if debug_on: logger.debug(f"  [+] Penalty: High entropy ({max_entropy:.2f}) -> Score: {score}")
        elif max_entropy > 3.2: # Was 3.6
            score += 1
            reasons.append(f"Suspicious entropy ({max_entropy:.2f})")
            if debug_on: logger.debug(f"  [+] Penalty: Suspicious entropy ({max_entropy:.2f}) -> Score: {score}")
            
        if max_hyphens > 1: # Was 3
            score += 1
            reasons.append(f"Excessive hyphens ({max_hyphens})")
            if debug_on: logger.debug(f"  [+] Penalty: Excessive hyphens ({max_hyphens}) -> Score: {score}")
            
        if total_len > 0 and (digit_count / total_len) > 0.30: # Was 0.40
            score += 1
            reasons.append(f"High numeric volume ({digit_count}/{total_len})")
            if debug_on: logger.debug(f"  [+] Penalty: High numeric volume ({digit_count}/{total_len}) -> Score: {score}")

        final_score = min(5, score)
        
        if debug_on and final_score > 0:
            logger.debug(f"  = Final Score: {final_score}/5 | Reasons: {reasons}")

        return final_score, reasons

