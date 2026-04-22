"""
ScriptX Payload Success Tracker
Tracks which payloads work on which sites/WAFs for future reference
"""

import json
import os
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from utils.logger import logger


@dataclass
class PayloadSuccess:
    """Record of a successful payload"""
    payload: str
    domain: str
    waf_type: str
    context: str  # html_body, attribute, javascript, etc.
    param: str
    vuln_type: str  # reflected, stored, dom
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class PayloadTracker:
    """
    Tracks successful payloads across scans.
    
    Saves to JSON file for persistence and future use.
    Helps prioritize payloads that have worked before.
    """
    
    DEFAULT_PATH = ".scriptx_payload_history.json"
    
    def __init__(self, history_path: str = None):
        self.history_path = history_path or self.DEFAULT_PATH
        self.successes: List[PayloadSuccess] = []
        self.payload_scores: Dict[str, int] = {}  # payload hash -> success count
        self.domain_payloads: Dict[str, Set[str]] = {}  # domain -> set of working payloads
        self.waf_payloads: Dict[str, Set[str]] = {}  # waf_type -> set of working payloads
        
        # Load existing history
        self._load_history()
    
    def _load_history(self):
        """Load payload history from file"""
        if not os.path.exists(self.history_path):
            return
        
        try:
            with open(self.history_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for record in data.get('successes', []):
                success = PayloadSuccess(**record)
                self.successes.append(success)
                self._update_scores(success)
            
            logger.debug(f"Loaded {len(self.successes)} payload success records")
        except Exception as e:
            logger.debug(f"Could not load payload history: {e}")
    
    def _save_history(self):
        """Save payload history to file"""
        try:
            data = {
                'version': '1.0',
                'last_updated': datetime.now().isoformat(),
                'total_successes': len(self.successes),
                'successes': [asdict(s) for s in self.successes[-1000:]]  # Keep last 1000
            }
            
            with open(self.history_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"Could not save payload history: {e}")
    
    def _update_scores(self, success: PayloadSuccess):
        """Update internal scoring after a success"""
        payload = success.payload
        domain = success.domain
        waf = success.waf_type
        
        # Update payload score
        self.payload_scores[payload] = self.payload_scores.get(payload, 0) + 1
        
        # Update domain mapping
        if domain not in self.domain_payloads:
            self.domain_payloads[domain] = set()
        self.domain_payloads[domain].add(payload)
        
        # Update WAF mapping
        if waf not in self.waf_payloads:
            self.waf_payloads[waf] = set()
        self.waf_payloads[waf].add(payload)
    
    def record_success(self, 
                       payload: str, 
                       domain: str, 
                       waf_type: str = "unknown",
                       context: str = "unknown",
                       param: str = "",
                       vuln_type: str = "reflected"):
        """
        Record a successful payload.
        
        Args:
            payload: The payload that worked
            domain: Target domain
            waf_type: Detected WAF type
            context: Injection context
            param: Parameter name
            vuln_type: Type of XSS (reflected, stored, dom)
        """
        success = PayloadSuccess(
            payload=payload,
            domain=domain,
            waf_type=waf_type,
            context=context,
            param=param,
            vuln_type=vuln_type
        )
        
        self.successes.append(success)
        self._update_scores(success)
        self._save_history()
        
        logger.debug(f"Recorded payload success for {domain} (WAF: {waf_type})")
    
    def get_recommended_payloads(self, 
                                  domain: str = None, 
                                  waf_type: str = None,
                                  max_payloads: int = 20) -> List[str]:
        """
        Get recommended payloads based on history.
        
        Prioritizes payloads that have worked before on similar targets.
        
        Args:
            domain: Target domain (optional, for domain-specific recommendations)
            waf_type: Detected WAF type (optional)
            max_payloads: Maximum number of payloads to return
            
        Returns:
            List of recommended payloads, sorted by success score
        """
        recommendations = []
        seen = set()
        
        # First: payloads that worked on this exact domain
        if domain and domain in self.domain_payloads:
            for payload in self.domain_payloads[domain]:
                if payload not in seen:
                    recommendations.append(payload)
                    seen.add(payload)
        
        # Second: payloads that worked on this WAF type
        if waf_type and waf_type in self.waf_payloads:
            for payload in self.waf_payloads[waf_type]:
                if payload not in seen:
                    recommendations.append(payload)
                    seen.add(payload)
        
        # Third: all-time top performers
        top_payloads = sorted(
            self.payload_scores.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        for payload, score in top_payloads:
            if payload not in seen:
                recommendations.append(payload)
                seen.add(payload)
        
        return recommendations[:max_payloads]
    
    def get_stats(self) -> Dict:
        """Get tracking statistics"""
        return {
            'total_successes': len(self.successes),
            'unique_payloads': len(self.payload_scores),
            'domains_tested': len(self.domain_payloads),
            'waf_types_bypassed': len(self.waf_payloads),
            'top_payloads': sorted(
                self.payload_scores.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
    
    def get_waf_bypass_stats(self) -> Dict[str, int]:
        """Get count of successful bypasses per WAF type"""
        stats = {}
        for waf, payloads in self.waf_payloads.items():
            stats[waf] = len(payloads)
        return stats
    
    def clear_history(self):
        """Clear all history"""
        self.successes = []
        self.payload_scores = {}
        self.domain_payloads = {}
        self.waf_payloads = {}
        
        if os.path.exists(self.history_path):
            os.remove(self.history_path)
        
        logger.info("Payload history cleared")


# Singleton instance
payload_tracker = PayloadTracker()
