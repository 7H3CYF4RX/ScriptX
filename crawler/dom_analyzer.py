"""
ScriptX DOM Analyzer
Analyzes DOM structure for XSS sources and sinks
"""

from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from bs4 import BeautifulSoup
import re


@dataclass
class DOMSink:
    """Represents a dangerous DOM sink"""
    sink_type: str
    location: str  # file:line or script identifier
    code_snippet: str
    severity: str  # high, medium, low
    

@dataclass
class DOMSource:
    """Represents a user-controllable DOM source"""
    source_type: str
    location: str
    description: str


class DomAnalyzer:
    """
    Analyzes JavaScript code for DOM-based XSS vulnerabilities.
    Identifies sources (user input) and sinks (dangerous functions).
    """
    
    # Dangerous sinks that can lead to XSS
    SINKS = {
        'high': [
            # Direct execution
            (r'eval\s*\(', 'eval()'),
            (r'Function\s*\(', 'Function()'),
            (r'setTimeout\s*\(\s*["\']', 'setTimeout() with string'),
            (r'setInterval\s*\(\s*["\']', 'setInterval() with string'),
            
            # DOM manipulation
            (r'\.innerHTML\s*=', 'innerHTML assignment'),
            (r'\.outerHTML\s*=', 'outerHTML assignment'),
            (r'document\.write\s*\(', 'document.write()'),
            (r'document\.writeln\s*\(', 'document.writeln()'),
            (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML()'),
        ],
        'medium': [
            # URL manipulation
            (r'location\s*=', 'location assignment'),
            (r'location\.href\s*=', 'location.href assignment'),
            (r'location\.replace\s*\(', 'location.replace()'),
            (r'location\.assign\s*\(', 'location.assign()'),
            (r'window\.open\s*\(', 'window.open()'),
            
            # jQuery sinks
            (r'\$\([^)]*\)\.html\s*\(', 'jQuery .html()'),
            (r'\$\([^)]*\)\.append\s*\(', 'jQuery .append()'),
            (r'\$\([^)]*\)\.prepend\s*\(', 'jQuery .prepend()'),
            (r'\$\([^)]*\)\.after\s*\(', 'jQuery .after()'),
            (r'\$\([^)]*\)\.before\s*\(', 'jQuery .before()'),
            (r'\$\([^)]*\)\.replaceWith\s*\(', 'jQuery .replaceWith()'),
            (r'jQuery\([^)]*\)\.html\s*\(', 'jQuery .html()'),
        ],
        'low': [
            # Attribute manipulation
            (r'\.setAttribute\s*\(["\'](?:href|src|action|data|formaction)', 'setAttribute() with URL'),
            (r'\.src\s*=', 'src assignment'),
            (r'\.href\s*=', 'href assignment'),
            (r'\.action\s*=', 'action assignment'),
            
            # Other
            (r'\.textContent\s*=', 'textContent assignment'),  # Usually safe but worth noting
        ]
    }
    
    # User-controllable sources
    SOURCES = [
        (r'location\.hash', 'location.hash', 'URL fragment'),
        (r'location\.search', 'location.search', 'URL query string'),
        (r'location\.href', 'location.href', 'Full URL'),
        (r'location\.pathname', 'location.pathname', 'URL path'),
        (r'document\.URL', 'document.URL', 'Document URL'),
        (r'document\.documentURI', 'document.documentURI', 'Document URI'),
        (r'document\.referrer', 'document.referrer', 'Referrer URL'),
        (r'document\.cookie', 'document.cookie', 'Cookies'),
        (r'window\.name', 'window.name', 'Window name'),
        (r'localStorage\[', 'localStorage', 'Local storage'),
        (r'localStorage\.getItem', 'localStorage.getItem()', 'Local storage'),
        (r'sessionStorage\[', 'sessionStorage', 'Session storage'),
        (r'sessionStorage\.getItem', 'sessionStorage.getItem()', 'Session storage'),
        (r'\.postMessage\s*\(', 'postMessage()', 'Cross-origin message'),
        (r'URLSearchParams', 'URLSearchParams', 'URL parameters'),
    ]
    
    def __init__(self):
        self.sinks_found: List[DOMSink] = []
        self.sources_found: List[DOMSource] = []
        self.vulnerable_patterns: List[Dict] = []
        
    def analyze_html(self, html_content: str) -> Dict:
        """
        Analyze HTML content for DOM XSS vulnerabilities.
        
        Returns dict with sources, sinks, and potential vulnerabilities.
        """
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Reset findings
        self.sinks_found = []
        self.sources_found = []
        self.vulnerable_patterns = []
        
        # Analyze inline scripts
        for idx, script in enumerate(soup.find_all('script')):
            if script.string:
                self._analyze_script(script.string, f'inline_script_{idx}')
        
        # Analyze event handlers
        self._analyze_event_handlers(soup)
        
        # Analyze href="javascript:" links
        self._analyze_javascript_urls(soup)
        
        # Find source-to-sink flows
        self._find_vulnerable_flows()
        
        return {
            'sinks': [vars(s) for s in self.sinks_found],
            'sources': [vars(s) for s in self.sources_found],
            'vulnerable_patterns': self.vulnerable_patterns,
            'risk_score': self._calculate_risk_score()
        }
    
    def _analyze_script(self, script_content: str, location: str):
        """Analyze a script block for sources and sinks"""
        
        # Find sinks
        for severity, patterns in self.SINKS.items():
            for pattern, sink_name in patterns:
                for match in re.finditer(pattern, script_content, re.IGNORECASE):
                    # Get context (surrounding code)
                    start = max(0, match.start() - 30)
                    end = min(len(script_content), match.end() + 30)
                    snippet = script_content[start:end].strip()
                    
                    self.sinks_found.append(DOMSink(
                        sink_type=sink_name,
                        location=location,
                        code_snippet=snippet,
                        severity=severity
                    ))
        
        # Find sources
        for pattern, source_name, description in self.SOURCES:
            for match in re.finditer(pattern, script_content, re.IGNORECASE):
                self.sources_found.append(DOMSource(
                    source_type=source_name,
                    location=location,
                    description=description
                ))
    
    def _analyze_event_handlers(self, soup: BeautifulSoup):
        """Analyze inline event handlers for XSS sinks"""
        
        event_attrs = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseenter',
            'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeyup', 'onkeydown',
            'onkeypress', 'ondblclick', 'oncontextmenu', 'oninput', 'onscroll'
        ]
        
        for attr in event_attrs:
            for elem in soup.find_all(attrs={attr: True}):
                handler_code = elem.get(attr, '')
                if handler_code:
                    self._analyze_script(handler_code, f'event_handler_{attr}')
    
    def _analyze_javascript_urls(self, soup: BeautifulSoup):
        """Analyze javascript: URLs"""
        
        for elem in soup.find_all(href=re.compile(r'^javascript:', re.IGNORECASE)):
            js_code = elem.get('href', '')[11:]  # Remove 'javascript:'
            self._analyze_script(js_code, 'javascript_url')
        
        for elem in soup.find_all(src=re.compile(r'^javascript:', re.IGNORECASE)):
            js_code = elem.get('src', '')[11:]
            self._analyze_script(js_code, 'javascript_url_src')
    
    def _find_vulnerable_flows(self):
        """
        Identify potential source-to-sink flows.
        This is a simplified static analysis.
        """
        
        # If we have both sources and sinks in the same location, flag it
        source_locations = {s.location for s in self.sources_found}
        
        for sink in self.sinks_found:
            if sink.location in source_locations:
                # Check if the sink code mentions any source
                for source in self.sources_found:
                    if source.location == sink.location:
                        self.vulnerable_patterns.append({
                            'source': source.source_type,
                            'sink': sink.sink_type,
                            'location': sink.location,
                            'severity': sink.severity,
                            'description': f'{source.source_type} may flow to {sink.sink_type}'
                        })
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall DOM XSS risk score (0-100)"""
        score = 0
        
        # Add points for sinks
        for sink in self.sinks_found:
            if sink.severity == 'high':
                score += 20
            elif sink.severity == 'medium':
                score += 10
            else:
                score += 5
        
        # Add points for sources
        score += len(self.sources_found) * 5
        
        # Bonus for vulnerable patterns
        score += len(self.vulnerable_patterns) * 15
        
        return min(100, score)
    
    def get_injectable_sources(self) -> List[str]:
        """Get list of user-controllable sources to test"""
        return list(set(s.source_type for s in self.sources_found))
    
    def get_high_risk_sinks(self) -> List[DOMSink]:
        """Get high severity sinks"""
        return [s for s in self.sinks_found if s.severity == 'high']
    
    def get_stats(self) -> Dict:
        """Get analysis statistics"""
        return {
            'total_sinks': len(self.sinks_found),
            'high_severity_sinks': len([s for s in self.sinks_found if s.severity == 'high']),
            'total_sources': len(self.sources_found),
            'vulnerable_patterns': len(self.vulnerable_patterns),
            'risk_score': self._calculate_risk_score()
        }
