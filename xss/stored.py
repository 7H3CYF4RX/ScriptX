"""
ScriptX Stored XSS Detection
Detects stored/persistent XSS vulnerabilities
"""

import asyncio
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
import time
import hashlib

from core.browser import BrowserController
from core.config import Config
from xss.payloads import PayloadEngine, PayloadContext
from crawler.form_finder import Form, FormInput
from utils.logger import logger


@dataclass
class StoredXSSVuln:
    """Represents a confirmed stored XSS vulnerability"""
    injection_url: str  # Where payload was submitted
    trigger_url: str  # Where payload executes
    param: str
    payload: str
    method: str
    alert_message: Optional[str] = None
    screenshot_path: Optional[str] = None
    severity: str = 'critical'  # Stored XSS is typically critical
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        return {
            'type': 'stored_xss',
            'injection_url': self.injection_url,
            'trigger_url': self.trigger_url,
            'param': self.param,
            'payload': self.payload,
            'method': self.method,
            'alert_message': self.alert_message,
            'screenshot': self.screenshot_path,
            'severity': self.severity,
            'timestamp': self.timestamp
        }


@dataclass
class StoredXSSTest:
    """Tracks a stored XSS test case"""
    form: Form
    param: str
    payload: str
    marker: str
    submitted: bool = False
    output_pages: List[str] = field(default_factory=list)


class StoredXSS:
    """
    Stored XSS Detection Engine
    
    Detection strategy:
    1. Identify forms that might store data (comments, profile, posts, etc.)
    2. Submit payloads with unique markers
    3. Crawl potential output pages
    4. Check if markers execute
    """
    
    # Forms likely to store data
    STORAGE_INDICATORS = [
        'comment', 'message', 'post', 'reply', 'feedback',
        'review', 'bio', 'description', 'profile', 'about',
        'content', 'body', 'text', 'title', 'name', 'subject',
        'contact', 'support', 'ticket', 'note'
    ]
    
    def __init__(self, browser: BrowserController, config: Config):
        self.browser = browser
        self.config = config
        self.payload_engine = PayloadEngine(config.custom_payloads)
        self.vulnerabilities: List[StoredXSSVuln] = []
        self._waf_logged_domains: set = set()  # Track domains where WAF was already logged
        
        # Track submitted payloads
        self.pending_tests: List[StoredXSSTest] = []
        self.submitted_markers: Set[str] = set()
    
    async def _check_waf(self, url: str, page_source: str):
        """Check for WAF (only once per domain)"""
        if not self.config.waf_fingerprint:
            return
        try:
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
        if self.config.random_delay:
            delay = rnd.randint(self.config.min_delay, self.config.max_delay)
            await asyncio.sleep(delay / 1000)
        elif self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay / 1000)
        
    async def identify_storage_forms(self, forms: List[Form]) -> List[Form]:
        """
        Identify forms that likely store data.
        
        Args:
            forms: List of discovered forms
            
        Returns:
            Forms likely to store user input
        """
        storage_forms = []
        
        for form in forms:
            if self._is_likely_storage_form(form):
                storage_forms.append(form)
        
        logger.debug(f"Identified {len(storage_forms)} potential storage forms")
        return storage_forms
    
    def _is_likely_storage_form(self, form: Form) -> bool:
        """Check if form likely stores data"""
        # Check form action URL
        action_lower = form.action.lower()
        for indicator in self.STORAGE_INDICATORS:
            if indicator in action_lower:
                return True
        
        # Check form name
        if form.name and any(ind in form.name.lower() for ind in self.STORAGE_INDICATORS):
            return True
        
        # Check input names
        for inp in form.inputs:
            if inp.name and any(ind in inp.name.lower() for ind in self.STORAGE_INDICATORS):
                return True
        
        # Check for textarea (often used for longer content that gets stored)
        if any(inp.tag == 'textarea' for inp in form.inputs):
            return True
        
        return False
    
    async def submit_payloads(self, forms: List[Form], 
                             output_pages: List[str] = None) -> List[StoredXSSTest]:
        """
        Submit payloads to potential storage forms.
        
        Args:
            forms: Forms to test
            output_pages: Pages where stored content might appear
            
        Returns:
            List of submitted test cases
        """
        tests = []
        
        # Use limited payloads for stored XSS (to avoid spam)
        payloads = self.payload_engine.get_quick_payloads()[:5]
        
        for form in forms:
            for inp in form.get_injectable_inputs():
                for payload in payloads:
                    # Generate unique marker
                    marker = self._generate_marker(form, inp.name)
                    marked_payload = payload.replace(
                        self.payload_engine.XSS_MARKER,
                        marker
                    )
                    
                    # Create test case
                    test = StoredXSSTest(
                        form=form,
                        param=inp.name,
                        payload=marked_payload,
                        marker=marker,
                        output_pages=output_pages or []
                    )
                    
                    # Submit payload
                    success = await self._submit_payload(test)
                    
                    if success:
                        test.submitted = True
                        tests.append(test)
                        self.pending_tests.append(test)
                        self.submitted_markers.add(marker)
                        logger.debug(f"Submitted stored XSS test: {inp.name} -> {form.action}")
                    
                    # Apply delay
                    await self._apply_delay()
        
        logger.info(f"Submitted {len(tests)} stored XSS test payloads")
        return tests
    
    async def _submit_payload(self, test: StoredXSSTest) -> bool:
        """Submit a test payload via form"""
        try:
            form = test.form
            
            # Navigate to form page
            await self.browser.navigate(form.page_url)
            await asyncio.sleep(0.5)
            
            # Build input data
            inputs = {}
            for inp in form.inputs:
                selector = f'{form.selector} [name="{inp.name}"]'
                
                if inp.name == test.param:
                    # Inject payload
                    inputs[selector] = test.payload
                elif inp.is_injectable():
                    # Fill with dummy data
                    inputs[selector] = self._get_dummy_value(inp)
            
            # Submit form
            await self.browser.inject_in_form(
                form.selector,
                inputs,
                submit=True,
                alert_timeout=2.0  # Wait 2 seconds for alert
            )
            
            return True
            
        except Exception as e:
            logger.debug(f"Failed to submit payload: {e}")
            return False
    
    async def check_execution(self, pages_to_check: List[str] = None) -> List[StoredXSSVuln]:
        """
        Check if any submitted payloads execute on output pages.
        
        Args:
            pages_to_check: URLs to check for stored XSS
            
        Returns:
            List of confirmed vulnerabilities
        """
        vulns = []
        
        # Collect pages to check
        check_pages = set(pages_to_check or [])
        
        for test in self.pending_tests:
            check_pages.update(test.output_pages)
            check_pages.add(test.form.page_url)
            check_pages.add(test.form.get_absolute_action())
        
        logger.info(f"Checking {len(check_pages)} pages for stored XSS execution")
        
        for page_url in check_pages:
            self.browser.clear_alerts()
            
            try:
                await self.browser.navigate(page_url)
                await asyncio.sleep(2.0)  # Wait 2 seconds for JS execution
                
                # Check for captured alerts
                for alert in self.browser.captured_alerts:
                    # Find which test triggered this
                    for test in self.pending_tests:
                        if test.marker in alert.message:
                            vuln = StoredXSSVuln(
                                injection_url=test.form.get_absolute_action(),
                                trigger_url=page_url,
                                param=test.param,
                                payload=test.payload,
                                method=test.form.method,
                                alert_message=alert.message
                            )
                            
                            # Screenshot
                            if self.config.screenshots:
                                screenshot_path = f"{self.config.output_dir}/screenshots/stored_{int(time.time())}.png"
                                await self.browser.screenshot(screenshot_path)
                                vuln.screenshot_path = screenshot_path
                            
                            vulns.append(vuln)
                            self.vulnerabilities.append(vuln)
                            
                            logger.success(f"STORED XSS CONFIRMED: {test.param} -> {page_url}")
                            
                            # Remove from pending
                            if test in self.pending_tests:
                                self.pending_tests.remove(test)
                
            except Exception as e:
                logger.debug(f"Error checking {page_url}: {e}")
            
            # Apply delay
            await self._apply_delay()
        
        return vulns
    
    def _generate_marker(self, form: Form, param: str) -> str:
        """Generate unique marker for tracking"""
        data = f"{form.action}:{param}:{time.time()}"
        hash_val = hashlib.md5(data.encode()).hexdigest()[:10]
        return f"SX_{hash_val}"
    
    def _get_dummy_value(self, inp: FormInput) -> str:
        """Get dummy value for form field"""
        type_values = {
            'email': 'test@scriptx.local',
            'number': '123',
            'tel': '+1234567890',
            'url': 'https://scriptx.local',
            'date': '2024-01-01',
            'password': 'password123',
            'checkbox': 'on',
            'select': '',  # Handled by auto-fill
        }
        
        if inp.input_type in type_values:
            return type_values[inp.input_type]
        
        # Smart dummy values based on field name
        name_lower = (inp.name or '').lower()
        
        name_map = {
            'email': 'test@scriptx.local',
            'phone': '+1234567890',
            'tel': '+1234567890',
            'company': 'Test Corp',
            'organization': 'Test Corp',
            'first': 'John',
            'last': 'Doe',
            'name': 'John Doe',
            'city': 'New York',
            'country': 'US',
            'zip': '10001',
            'postal': '10001',
            'address': '123 Test Street',
            'website': 'https://scriptx.local',
            'url': 'https://scriptx.local',
            'subject': 'Test Message',
            'title': 'Test',
            'message': 'This is a test message',
            'comment': 'This is a test comment',
        }
        
        for key, value in name_map.items():
            if key in name_lower:
                return value
        
        return 'test_value'
    
    async def test_form_stored(self, form: Form, 
                               output_pages: List[str]) -> Optional[StoredXSSVuln]:
        """
        Full stored XSS test for a single form.
        
        Args:
            form: Form to test
            output_pages: Pages where output might appear
            
        Returns:
            First confirmed vulnerability, or None
        """
        # Submit payloads
        tests = await self.submit_payloads([form], output_pages)
        
        if not tests:
            return None
        
        # Short delay before checking
        await asyncio.sleep(2.0)  # Wait 2 seconds before checking
        
        # Check execution
        vulns = await self.check_execution(output_pages)
        
        return vulns[0] if vulns else None
    
    def get_results(self) -> List[Dict]:
        """Get all vulnerability results"""
        return [v.to_dict() for v in self.vulnerabilities]
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'pending_tests': len(self.pending_tests),
            'submitted_payloads': len(self.submitted_markers)
        }
