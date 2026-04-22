"""
ScriptX Reflected XSS Detection
Detects reflected XSS vulnerabilities via browser-based execution verification
"""

import asyncio
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import time

from core.browser import BrowserController, AlertCapture
from core.config import Config
from xss.payloads import PayloadEngine, PayloadContext
from utils.logger import logger
from utils.helpers import inject_payload, is_reflected, detect_context


@dataclass
class ReflectedXSSVuln:
    """Represents a confirmed reflected XSS vulnerability"""
    url: str  # Original URL
    param: str
    payload: str
    method: str  # GET or POST
    poc_url: Optional[str] = None  # Full URL with payload (PoC)
    alert_message: Optional[str] = None
    context: Optional[str] = None
    screenshot_path: Optional[str] = None
    request_data: Optional[Dict] = None
    response_snippet: Optional[str] = None
    severity: str = 'high'
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        return {
            'type': 'reflected_xss',
            'url': self.poc_url or self.url,  # Use PoC URL if available
            'original_url': self.url,
            'poc_url': self.poc_url,
            'param': self.param,
            'payload': self.payload,
            'method': self.method,
            'alert_message': self.alert_message,
            'context': self.context,
            'screenshot': self.screenshot_path,
            'severity': self.severity,
            'timestamp': self.timestamp
        }


class ReflectedXSS:
    """
    Reflected XSS Detection Engine
    
    Detection flow:
    1. Inject probe value to check reflection
    2. If reflected, determine context
    3. Select context-appropriate payloads
    4. Test payloads via browser
    5. Verify execution via alert capture
    """
    
    PROBE_VALUE = 'SCRIPTX_PROBE_12345'
    
    def __init__(self, browser: BrowserController, config: Config):
        self.browser = browser
        self.config = config
        self.payload_engine = PayloadEngine(config.custom_payloads)
        self.vulnerabilities: List[ReflectedXSSVuln] = []
        self._waf_logged_domains: set = set()  # Track domains where WAF was already logged
        
    async def test_url_param(self, url: str, param: str, 
                            original_value: str = '', 
                            alert_timeout: float = 2.0) -> Optional[ReflectedXSSVuln]:
        """
        Test a URL parameter for reflected XSS.
        
        Args:
            url: Target URL
            param: Parameter name to test
            original_value: Original parameter value
            alert_timeout: Seconds to wait for alert after injection
            
        Returns:
            ReflectedXSSVuln if vulnerable, None otherwise
        """
        logger.debug(f"Testing reflected XSS: {param} @ {url}")
        
        # Step 1: Check if value is reflected
        probe_url = inject_payload(url, param, self.PROBE_VALUE)
        
        response = await self.browser.navigate(probe_url)
        
        # Skip 404 and error pages
        if await self._is_error_page():
            logger.debug(f"Skipping error/404 page: {url}")
            return None
        
        page_source = await self.browser.get_page_source()
        
        # WAF Fingerprinting (only log once per domain)
        if self.config.waf_fingerprint:
            try:
                from urllib.parse import urlparse
                from utils.waf_detector import waf_detector
                
                domain = urlparse(url).netloc
                if domain not in self._waf_logged_domains:
                    headers = {}
                    status = 200
                    waf_result = waf_detector.detect(url, status, headers, page_source)
                    if waf_result.detected:
                        logger.warning(f"WAF detected: {waf_result.waf_type.value} (confidence: {waf_result.confidence:.0%})")
                        self._waf_logged_domains.add(domain)
            except Exception:
                pass
        
        if not is_reflected(page_source, self.PROBE_VALUE):
            logger.debug(f"Parameter {param} is not reflected")
            return None
        
        # Step 2: Determine reflection context
        context = detect_context(page_source, self.PROBE_VALUE)
        logger.debug(f"Reflection context: {context}")
        
        # Step 3: Get payloads (Smart mode or regular)
        if self.config.smart_mode:
            payloads = self._get_smart_payloads(param)
        else:
            payload_context = self._map_context(context)
            payloads = self.payload_engine.get_payloads(
                context=payload_context,
                include_waf_bypass=self.config.waf_bypass,
                max_payloads=self.config.max_payloads_per_param
            )
        
        # Step 4: Test payloads (including encoded versions)
        for payload in payloads:
            # Test original payload
            vuln = await self._test_payload(url, param, payload)
            
            if vuln:
                vuln.context = context
                self.vulnerabilities.append(vuln)
                if self.config.smart_mode:
                    self._report_smart_success(param)
                # Track successful payload
                self._track_payload_success(url, payload, context, param)
                return vuln
            elif self.config.smart_mode:
                self._report_smart_blocked(param)
            
            # Apply delay (random or fixed)
            await self._apply_delay()
            
            # Test encoded mutations if WAF bypass is enabled
            if self.config.waf_bypass:
                encoded_payloads = self._get_encoded_versions(payload)
                
                for encoded_payload in encoded_payloads:
                    vuln = await self._test_payload(url, param, encoded_payload)
                    
                    if vuln:
                        vuln.context = context
                        self.vulnerabilities.append(vuln)
                        if self.config.smart_mode:
                            self._report_smart_success(param)
                        # Track successful payload
                        self._track_payload_success(url, encoded_payload, context, param)
                        return vuln
                    
                    await self._apply_delay()
        
        return None
    
    async def _apply_delay(self):
        """Apply request delay (random or fixed)"""
        import random as rnd
        if self.config.random_delay:
            delay = rnd.randint(self.config.min_delay, self.config.max_delay)
            await asyncio.sleep(delay / 1000)
        elif self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay / 1000)
    
    def _get_smart_payloads(self, param: str) -> List[str]:
        """Get payloads using smart escalation"""
        try:
            from utils.smart_payload import smart_engine
            return smart_engine.get_smart_payloads(
                parameter=param,
                max_payloads=self.config.max_payloads_per_param
            )
        except Exception:
            # Fallback to regular payloads
            return self.payload_engine.get_payloads(
                include_waf_bypass=self.config.waf_bypass,
                max_payloads=self.config.max_payloads_per_param
            )
    
    def _report_smart_blocked(self, param: str):
        """Report blocked payload to smart engine"""
        try:
            from utils.smart_payload import smart_engine
            smart_engine.report_blocked(param)
        except Exception:
            pass
    
    def _report_smart_success(self, param: str):
        """Report successful payload to smart engine"""
        try:
            from utils.smart_payload import smart_engine
            smart_engine.report_success(param)
        except Exception:
            pass
    
    def _track_payload_success(self, url: str, payload: str, context: str, param: str):
        """Track successful payload for future prioritization"""
        try:
            from urllib.parse import urlparse
            from utils.payload_tracker import payload_tracker
            
            domain = urlparse(url).netloc
            
            # Get WAF type if detected
            waf_type = "unknown"
            if hasattr(self, '_waf_logged_domains') and domain in self._waf_logged_domains:
                try:
                    from utils.waf_detector import waf_detector
                    if domain in waf_detector.detected_wafs:
                        waf_type = waf_detector.detected_wafs[domain].waf_type.value
                except Exception:
                    pass
            
            payload_tracker.record_success(
                payload=payload,
                domain=domain,
                waf_type=waf_type,
                context=context or "unknown",
                param=param,
                vuln_type="reflected"
            )
        except Exception:
            pass  # Tracking is optional, don't break scan
    
    async def _is_error_page(self) -> bool:
        """Check if current page is a 404/error page"""
        try:
            # Check page title for common error indicators
            title = await self.browser.page.title()
            title_lower = (title or "").lower()
            
            error_titles = [
                '404', 'not found', 'page not found', 'error', 
                '403', 'forbidden', '500', 'server error',
                'does not exist', 'unavailable'
            ]
            
            for indicator in error_titles:
                if indicator in title_lower:
                    return True
            
            # Check page content for common error messages
            try:
                body_text = await self.browser.page.inner_text('body')
                body_lower = (body_text or "").lower()[:2000]  # Only check first 2KB
                
                error_patterns = [
                    'page not found',
                    'this page does not exist',
                    '404 error',
                    'page cannot be found',
                    'the requested url was not found',
                    'nothing was found',
                ]
                
                for pattern in error_patterns:
                    if pattern in body_lower:
                        return True
            except Exception:
                pass
            
            return False
        except Exception:
            return False
    
    def _get_encoded_versions(self, payload: str) -> List[str]:
        """Generate encoded versions of a payload for WAF bypass"""
        encoded = []
        
        # URL encoding
        encoded.append(self.payload_engine.encode_payload(payload, 'url'))
        
        # Double URL encoding (for WAF bypass)
        encoded.append(self.payload_engine.encode_payload(payload, 'url_double'))
        
        # HTML entity encoding
        encoded.append(self.payload_engine.encode_payload(payload, 'html'))
        
        # HTML hex encoding
        encoded.append(self.payload_engine.encode_payload(payload, 'html_hex'))
        
        # Case variations
        encoded.append(self.payload_engine._random_case(payload))
        
        # Remove duplicates and original
        return [e for e in list(set(encoded)) if e != payload]
    
    async def test_form(self, form_data: Dict) -> Optional[ReflectedXSSVuln]:
        """
        Test a form input for reflected XSS.
        
        Args:
            form_data: Dict with url, param, method, form_selector
            
        Returns:
            ReflectedXSSVuln if vulnerable, None otherwise
        """
        url = form_data.get('url')
        param = form_data.get('param')
        method = form_data.get('method', 'POST').upper()
        form_selector = form_data.get('form_selector')
        
        logger.debug(f"Testing form input: {param} @ {url} [{method}]")
        
        # For GET forms, treat like URL params
        if method == 'GET':
            return await self.test_url_param(url, param)
        
        # For POST forms, use browser form submission
        # First, navigate to the page with the form
        base_url = form_data.get('page_url', url)
        await self.browser.navigate(base_url)
        
        # Step 1: Check reflection with probe
        probe_result = await self._submit_form_with_payload(
            form_selector, param, self.PROBE_VALUE
        )
        
        if not probe_result or not is_reflected(probe_result, self.PROBE_VALUE):
            logger.debug(f"Form input {param} is not reflected")
            return None
        
        # Step 2: Determine context
        context = detect_context(probe_result, self.PROBE_VALUE)
        
        # Step 3: Get payloads
        payload_context = self._map_context(context)
        payloads = self.payload_engine.get_payloads(
            context=payload_context,
            include_waf_bypass=self.config.waf_bypass,
            max_payloads=self.config.max_payloads_per_param
        )
        
        # Step 4: Test payloads
        for payload in payloads:
            vuln = await self._test_form_payload(form_data, param, payload)
            
            if vuln:
                vuln.context = context
                self.vulnerabilities.append(vuln)
                return vuln
            
            # Rate limiting
            if self.config.request_delay > 0:
                await asyncio.sleep(self.config.request_delay / 1000)
        
        return None
    
    async def _test_payload(self, url: str, param: str, 
                           payload: str) -> Optional[ReflectedXSSVuln]:
        """Test a single payload via URL parameter"""
        test_url = inject_payload(url, param, payload)
        
        # Clear previous alerts
        self.browser.clear_alerts()
        
        # Navigate and wait for potential alert
        await self.browser.navigate(test_url)
        
        # Wait for JavaScript execution
        await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
        
        # Check for captured alerts
        if self.browser.captured_alerts:
            alert = self.browser.captured_alerts[0]
            
            # Verify it's our payload (contains marker)
            if self.payload_engine.payload_contains_marker(alert.message):
                logger.success(f"XSS CONFIRMED: {param} @ {test_url}")
                
                # Take screenshot
                screenshot_path = None
                if self.config.screenshots:
                    screenshot_path = f"{self.config.output_dir}/screenshots/{int(time.time())}_{param}.png"
                    await self.browser.screenshot(screenshot_path)
                
                return ReflectedXSSVuln(
                    url=url,
                    param=param,
                    payload=payload,
                    method='GET',
                    poc_url=test_url,  # Store the actual PoC URL
                    alert_message=alert.message,
                    screenshot_path=screenshot_path,
                    request_data={'url': test_url}
                )
        
        # Also check for unhandled script execution (DOM-visible effects)
        # This catches cases where alert might be blocked
        page_source = await self.browser.get_page_source()
        if self._check_payload_executed(page_source, payload):
            logger.debug(f"Potential XSS (no alert, but payload present): {param}")
            # Could be flagged as potential vuln
        
        return None
    
    async def _test_form_payload(self, form_data: Dict, param: str, 
                                 payload: str) -> Optional[ReflectedXSSVuln]:
        """Test a single payload via form submission"""
        # Navigate back to form page
        base_url = form_data.get('page_url', form_data['url'])
        await self.browser.navigate(base_url)
        
        # Clear alerts
        self.browser.clear_alerts()
        
        # Fill and submit form
        form_selector = form_data.get('form_selector', 'form')
        input_selector = f'{form_selector} [name="{param}"]'
        
        alert = await self.browser.inject_in_form(
            form_selector,
            {input_selector: payload},
            submit=True,
            alert_timeout=2.0  # Wait 2 seconds for alert
        )
        
        if alert and self.payload_engine.payload_contains_marker(alert.message):
            logger.success(f"XSS CONFIRMED (POST): {param} @ {form_data['url']}")
            
            screenshot_path = None
            if self.config.screenshots:
                screenshot_path = f"{self.config.output_dir}/screenshots/{int(time.time())}_{param}_post.png"
                await self.browser.screenshot(screenshot_path)
            
            return ReflectedXSSVuln(
                url=form_data['url'],
                param=param,
                payload=payload,
                method='POST',
                poc_url=self.browser.page.url,  # Current URL after form submission
                alert_message=alert.message,
                screenshot_path=screenshot_path,
                request_data={'form': form_data, 'payload_param': param, 'payload': payload}
            )
        
        return None
    
    async def _submit_form_with_payload(self, form_selector: str, 
                                        param: str, value: str) -> Optional[str]:
        """Submit form and return response HTML"""
        try:
            input_selector = f'{form_selector} [name="{param}"]'
            
            await self.browser.inject_in_form(
                form_selector,
                {input_selector: value},
                submit=True,
                alert_timeout=0.5
            )
            
            return await self.browser.get_page_source()
        except Exception as e:
            logger.debug(f"Form submission error: {e}")
            return None
    
    def _map_context(self, context: str) -> PayloadContext:
        """Map detected context to PayloadContext enum"""
        mapping = {
            'html': PayloadContext.HTML_BODY,
            'attribute': PayloadContext.HTML_ATTRIBUTE,
            'script': PayloadContext.JAVASCRIPT,
            'url': PayloadContext.URL,
            'comment': PayloadContext.HTML_COMMENT
        }
        return mapping.get(context, PayloadContext.HTML_BODY)
    
    def _check_payload_executed(self, page_source: str, payload: str) -> bool:
        """
        Check if payload might have executed (heuristic).
        Used when alerts are blocked.
        """
        # Check if our marker appears in an executable context
        marker = self.payload_engine.extract_marker(payload)
        if not marker:
            return False
        
        # Check for script context execution signs
        # This is a fallback heuristic
        return f'alert({marker})' in page_source or f'alert("{marker}")' in page_source
    
    async def test_quick(self, url: str) -> List[ReflectedXSSVuln]:
        """
        Quick test with minimal payloads.
        Tests all URL params with quick payload set.
        """
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            logger.debug("No URL parameters found")
            return results
        
        quick_payloads = self.payload_engine.get_quick_payloads()
        
        for param_name in params:
            for payload in quick_payloads:
                test_url = inject_payload(url, param_name, payload)
                
                self.browser.clear_alerts()
                await self.browser.navigate(test_url)
                await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
                
                if self.browser.captured_alerts:
                    alert = self.browser.captured_alerts[0]
                    if self.payload_engine.payload_contains_marker(alert.message):
                        vuln = ReflectedXSSVuln(
                            url=url,
                            param=param_name,
                            payload=payload,
                            method='GET',
                            poc_url=test_url,  # Store the actual PoC URL
                            alert_message=alert.message
                        )
                        results.append(vuln)
                        self.vulnerabilities.append(vuln)
                        break  # Found vuln for this param, move to next
        
        return results
    
    def get_results(self) -> List[Dict]:
        """Get all vulnerability results as dicts"""
        return [v.to_dict() for v in self.vulnerabilities]
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'unique_params': len(set(v.param for v in self.vulnerabilities)),
            'unique_urls': len(set(v.url for v in self.vulnerabilities))
        }
