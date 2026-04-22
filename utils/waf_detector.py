"""
ScriptX WAF Detector
Fingerprint and identify Web Application Firewalls
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class WAFType(Enum):
    """Known WAF types"""
    UNKNOWN = "unknown"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    IMPERVA = "imperva"
    F5_BIG_IP = "f5_bigip"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    CITRIX = "citrix"
    WORDFENCE = "wordfence"
    CLOUDFRONT = "cloudfront"


@dataclass
class WAFFingerprint:
    """WAF detection result"""
    detected: bool
    waf_type: WAFType
    confidence: float  # 0.0 to 1.0
    indicators: List[str]
    recommended_bypasses: List[str]


class WAFDetector:
    """
    Detect and fingerprint Web Application Firewalls
    based on response headers, status codes, and body content.
    """
    
    # WAF signatures: (header_name, header_value_pattern, waf_type)
    HEADER_SIGNATURES = [
        # Cloudflare
        ("server", r"cloudflare", WAFType.CLOUDFLARE),
        ("cf-ray", r".*", WAFType.CLOUDFLARE),
        ("cf-cache-status", r".*", WAFType.CLOUDFLARE),
        ("cf-request-id", r".*", WAFType.CLOUDFLARE),
        
        # Akamai
        ("server", r"akamai", WAFType.AKAMAI),
        ("x-akamai-transformed", r".*", WAFType.AKAMAI),
        ("akamai-origin-hop", r".*", WAFType.AKAMAI),
        
        # AWS WAF / CloudFront
        ("x-amz-cf-id", r".*", WAFType.CLOUDFRONT),
        ("x-amz-cf-pop", r".*", WAFType.CLOUDFRONT),
        ("x-amzn-waf-action", r".*", WAFType.AWS_WAF),
        ("x-amzn-requestid", r".*", WAFType.AWS_WAF),
        
        # Sucuri
        ("server", r"sucuri", WAFType.SUCURI),
        ("x-sucuri-id", r".*", WAFType.SUCURI),
        ("x-sucuri-cache", r".*", WAFType.SUCURI),
        
        # Imperva / Incapsula
        ("x-iinfo", r".*", WAFType.IMPERVA),
        ("x-cdn", r"incapsula", WAFType.IMPERVA),
        ("set-cookie", r"incap_ses", WAFType.IMPERVA),
        ("set-cookie", r"visid_incap", WAFType.IMPERVA),
        
        # F5 BIG-IP
        ("server", r"big-?ip", WAFType.F5_BIG_IP),
        ("x-wa-info", r".*", WAFType.F5_BIG_IP),
        ("set-cookie", r"bigipserver", WAFType.F5_BIG_IP),
        
        # Barracuda
        ("server", r"barracuda", WAFType.BARRACUDA),
        ("barra_counter_session", r".*", WAFType.BARRACUDA),
        
        # Fortinet / FortiWeb
        ("server", r"fortiweb", WAFType.FORTINET),
        ("fortiwafsid", r".*", WAFType.FORTINET),
        
        # Citrix NetScaler
        ("set-cookie", r"ns_af", WAFType.CITRIX),
        ("set-cookie", r"citrix_ns_id", WAFType.CITRIX),
        ("via", r"ns-cache", WAFType.CITRIX),
        
        # ModSecurity
        ("server", r"mod_security", WAFType.MODSECURITY),
        ("x-mod-security", r".*", WAFType.MODSECURITY),
    ]
    
    # Body content patterns
    BODY_SIGNATURES = [
        (r"attention\s+required.*cloudflare", WAFType.CLOUDFLARE),
        (r"cloudflare\s+ray\s+id", WAFType.CLOUDFLARE),
        (r"error\s+1020.*access\s+denied", WAFType.CLOUDFLARE),
        (r"please\s+wait.*checking\s+your\s+browser", WAFType.CLOUDFLARE),
        
        (r"access\s+denied.*akamai", WAFType.AKAMAI),
        (r"reference.*akamai", WAFType.AKAMAI),
        
        (r"request\s+blocked.*aws", WAFType.AWS_WAF),
        (r"waf\s+blocked", WAFType.AWS_WAF),
        
        (r"sucuri\s+website\s+firewall", WAFType.SUCURI),
        (r"blocked\s+by\s+sucuri", WAFType.SUCURI),
        (r"sucuri\.net", WAFType.SUCURI),
        
        (r"incapsula\s+incident", WAFType.IMPERVA),
        (r"powered\s+by\s+incapsula", WAFType.IMPERVA),
        (r"request\s+blocked.*imperva", WAFType.IMPERVA),
        
        (r"the\s+requested\s+url\s+was\s+rejected", WAFType.F5_BIG_IP),
        (r"big-?ip.*application\s+security", WAFType.F5_BIG_IP),
        
        (r"barracuda.*web\s+application\s+firewall", WAFType.BARRACUDA),
        
        (r"fortiguard\s+web\s+filtering", WAFType.FORTINET),
        (r"blocked\s+by\s+fortinet", WAFType.FORTINET),
        
        (r"mod_security", WAFType.MODSECURITY),
        (r"modsecurity", WAFType.MODSECURITY),
        (r"not\s+acceptable.*406", WAFType.MODSECURITY),
        
        (r"wordfence", WAFType.WORDFENCE),
        (r"blocked\s+by\s+wordfence", WAFType.WORDFENCE),
    ]
    
    # Recommended bypasses per WAF type
    BYPASS_RECOMMENDATIONS = {
        WAFType.CLOUDFLARE: [
            "Use HTML entity encoding",
            "Try unicode escapes",
            "Use < svg > with onload",
            "Try formaction attribute",
            "Use math/maction tags",
        ],
        WAFType.AKAMAI: [
            "Use unicode escapes (\\u0061lert)",
            "Try contenteditable + onblur",
            "Use marquee/menu tags",
            "Split keywords with concatenation",
        ],
        WAFType.AWS_WAF: [
            "Use comment injection (//a suffix)",
            "Try svg use href",
            "Use autofocus + onfocus",
            "Test with body onpageshow",
        ],
        WAFType.MODSECURITY: [
            "Use object/embed/frame tags",
            "Try data: URI payloads",
            "Use < base > tag injection",
            "Test applet code attribute",
        ],
        WAFType.SUCURI: [
            "Use svg set/discard elements",
            "Try eval tricks with src.slice",
            "Use atob for base64 execution",
            "Test form action injection",
        ],
        WAFType.IMPERVA: [
            "Use Function constructor with template literals",
            "Try keyframe animation events",
            "Use keygen autofocus",
            "Test video/source onerror",
        ],
        WAFType.WORDFENCE: [
            "Use unicode normalization",
            "Try case variations",
            "Use null byte injection",
            "Test with double encoding",
        ],
        WAFType.UNKNOWN: [
            "Try stealth payloads",
            "Use heavy encoding",
            "Test keyword splitting",
            "Use alternative execution methods",
        ],
    }
    
    def __init__(self):
        self.detected_wafs: Dict[str, WAFFingerprint] = {}
    
    def detect(self, 
               url: str,
               status_code: int,
               headers: Dict[str, str],
               body: str) -> WAFFingerprint:
        """
        Detect WAF from response data.
        
        Args:
            url: Target URL
            status_code: HTTP response status code
            headers: Response headers
            body: Response body content
            
        Returns:
            WAFFingerprint with detection results
        """
        indicators = []
        waf_scores: Dict[WAFType, float] = {}
        
        # Check for block status codes
        if status_code in (403, 406, 429, 503):
            indicators.append(f"Suspicious status code: {status_code}")
        
        # Check headers
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header_name, pattern, waf_type in self.HEADER_SIGNATURES:
            if header_name in headers_lower:
                if re.search(pattern, headers_lower[header_name], re.IGNORECASE):
                    indicators.append(f"Header match: {header_name}")
                    waf_scores[waf_type] = waf_scores.get(waf_type, 0) + 0.3
        
        # Check body content
        body_lower = body.lower()
        for pattern, waf_type in self.BODY_SIGNATURES:
            if re.search(pattern, body_lower, re.IGNORECASE):
                indicators.append(f"Body pattern: {pattern[:30]}...")
                waf_scores[waf_type] = waf_scores.get(waf_type, 0) + 0.4
        
        # Determine most likely WAF
        if waf_scores:
            detected_waf = max(waf_scores, key=waf_scores.get)
            confidence = min(waf_scores[detected_waf], 1.0)
        else:
            detected_waf = WAFType.UNKNOWN
            confidence = 0.0
        
        # Get bypass recommendations
        bypasses = self.BYPASS_RECOMMENDATIONS.get(
            detected_waf, 
            self.BYPASS_RECOMMENDATIONS[WAFType.UNKNOWN]
        )
        
        result = WAFFingerprint(
            detected=confidence > 0.3,
            waf_type=detected_waf,
            confidence=confidence,
            indicators=indicators,
            recommended_bypasses=bypasses
        )
        
        # Cache result
        self.detected_wafs[url] = result
        
        return result
    
    def get_targeted_payload_categories(self, waf_type: WAFType) -> List[str]:
        """
        Get recommended payload categories for a specific WAF.
        
        Returns list of payload category names to prioritize.
        """
        category_map = {
            WAFType.CLOUDFLARE: ["stealth_payloads", "advanced_waf_bypass", "encoded_payloads"],
            WAFType.AKAMAI: ["stealth_payloads", "advanced_waf_bypass", "event_payloads"],
            WAFType.AWS_WAF: ["stealth_payloads", "svg_payloads", "event_payloads"],
            WAFType.MODSECURITY: ["advanced_waf_bypass", "attribute_payloads", "dom_payloads"],
            WAFType.SUCURI: ["stealth_payloads", "advanced_waf_bypass", "svg_payloads"],
            WAFType.IMPERVA: ["stealth_payloads", "advanced_waf_bypass", "encoded_payloads"],
            WAFType.WORDFENCE: ["stealth_payloads", "encoded_payloads", "special_char_payloads"],
            WAFType.UNKNOWN: ["stealth_payloads", "advanced_waf_bypass", "polyglot_payloads"],
        }
        return category_map.get(waf_type, category_map[WAFType.UNKNOWN])


# Singleton instance
waf_detector = WAFDetector()
