"""
ScriptX XSS Detector
Main XSS detection orchestrator
"""

import asyncio
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
import time

from core.browser import BrowserController
from core.config import Config, ScanMode
from xss.reflected import ReflectedXSS, ReflectedXSSVuln
from xss.stored import StoredXSS, StoredXSSVuln
from xss.dom_xss import DomXSS, DOMXSSVuln
from crawler.crawler import CrawlState
from crawler.form_finder import Form
from utils.logger import logger


@dataclass
class XSSResult:
    """Combined XSS scan result"""
    reflected: List[Dict] = field(default_factory=list)
    stored: List[Dict] = field(default_factory=list)
    dom: List[Dict] = field(default_factory=list)
    
    @property
    def total(self) -> int:
        return len(self.reflected) + len(self.stored) + len(self.dom)
    
    def to_dict(self) -> Dict:
        return {
            'summary': {
                'total': self.total,
                'reflected': len(self.reflected),
                'stored': len(self.stored),
                'dom': len(self.dom)
            },
            'vulnerabilities': {
                'reflected': self.reflected,
                'stored': self.stored,
                'dom': self.dom
            }
        }


class XSSDetector:
    """
    Main XSS Detection Orchestrator
    
    Coordinates between:
    - Reflected XSS detection
    - Stored XSS detection
    - DOM-based XSS detection
    
    Features:
    - Configurable scan modes
    - Real-time callbacks
    - Progress tracking
    """
    
    def __init__(self, browser: BrowserController, config: Config):
        self.browser = browser
        self.config = config
        
        # Initialize detection modules
        self.reflected = ReflectedXSS(browser, config)
        self.stored = StoredXSS(browser, config)
        self.dom = DomXSS(browser, config)
        
        # Results
        self.result = XSSResult()
        
        # Callbacks
        self.on_vuln_found: Optional[Callable] = None
        self.on_progress: Optional[Callable] = None
        
        # Stats
        self.start_time: float = 0
        self.tests_completed: int = 0
        self.total_tests: int = 0
        
    async def scan_from_crawl(self, crawl_state: CrawlState) -> XSSResult:
        """
        Run XSS detection based on crawl results.
        
        Args:
            crawl_state: Crawled data including forms, params, URLs
            
        Returns:
            XSSResult with all findings
        """
        self.start_time = time.time()
        
        # Get all injection points
        injection_points = self._collect_injection_points(crawl_state)
        self.total_tests = len(injection_points)
        
        logger.info(f"Starting XSS scan: {self.total_tests} injection points")
        
        # Determine what to scan
        scan_mode = self.config.scan_mode
        if isinstance(scan_mode, ScanMode):
            scan_mode = scan_mode.value
        
        # Run appropriate scans
        if scan_mode in ('all', 'reflected'):
            await self._scan_reflected(injection_points)
        
        if scan_mode in ('all', 'stored'):
            await self._scan_stored(crawl_state.forms, list(crawl_state.visited))
        
        if scan_mode in ('all', 'dom'):
            await self._scan_dom(list(crawl_state.dom_analysis.keys()))
        
        # Compile results
        self.result.reflected = self.reflected.get_results()
        self.result.stored = self.stored.get_results()
        self.result.dom = self.dom.get_results()
        
        return self.result
    
    async def scan_url(self, url: str) -> XSSResult:
        """
        Quick scan of a single URL.
        Tests URL parameters and performs DOM analysis.
        """
        self.start_time = time.time()
        
        logger.info(f"Quick scanning: {url}")
        
        scan_mode = self.config.scan_mode
        if isinstance(scan_mode, ScanMode):
            scan_mode = scan_mode.value
        
        # Reflected XSS quick test
        if scan_mode in ('all', 'reflected'):
            await self.reflected.test_quick(url)
        
        # DOM XSS test
        if scan_mode in ('all', 'dom'):
            await self.dom.test_url(url)
        
        # Compile results
        self.result.reflected = self.reflected.get_results()
        self.result.dom = self.dom.get_results()
        
        return self.result
    
    async def _scan_reflected(self, injection_points: List[Dict]):
        """Scan for reflected XSS"""
        logger.info(f"Scanning for Reflected XSS: {len(injection_points)} points")
        
        for idx, point in enumerate(injection_points):
            try:
                if point['type'] == 'url_param':
                    vuln = await self.reflected.test_url_param(
                        point['url'],
                        point['param'],
                        point.get('value', '')
                    )
                elif point['type'] == 'form_input':
                    vuln = await self.reflected.test_form(point)
                else:
                    vuln = None
                
                if vuln:
                    await self._handle_vuln_found('reflected', vuln)
                
                # Progress update
                self.tests_completed += 1
                await self._update_progress('reflected', idx + 1, len(injection_points))
                
            except Exception as e:
                logger.debug(f"Error testing {point['param']}: {e}")
    
    async def _scan_stored(self, forms: List[Form], visited_urls: List[str]):
        """Scan for stored XSS"""
        # Identify storage forms
        storage_forms = await self.stored.identify_storage_forms(forms)
        
        if not storage_forms:
            logger.debug("No storage forms identified")
            return
        
        logger.info(f"Scanning for Stored XSS: {len(storage_forms)} forms")
        
        # Submit payloads
        await self.stored.submit_payloads(storage_forms, visited_urls)
        
        # Wait a bit for data to be stored
        await asyncio.sleep(1.0)
        
        # Check for execution
        vulns = await self.stored.check_execution(visited_urls)
        
        for vuln in vulns:
            await self._handle_vuln_found('stored', vuln)
    
    async def _scan_dom(self, urls: List[str]):
        """Scan for DOM-based XSS"""
        logger.info(f"Scanning for DOM XSS: {len(urls)} URLs")
        
        for idx, url in enumerate(urls):
            try:
                vulns = await self.dom.test_url(url)
                
                for vuln in vulns:
                    await self._handle_vuln_found('dom', vuln)
                
                await self._update_progress('dom', idx + 1, len(urls))
                
            except Exception as e:
                logger.debug(f"Error testing DOM XSS on {url}: {e}")
    
    def _collect_injection_points(self, crawl_state: CrawlState) -> List[Dict]:
        """Collect all injection points from crawl state"""
        points = []
        
        # URL parameters
        for url, params in crawl_state.url_params.items():
            for param_name, param_values in params.items():
                points.append({
                    'type': 'url_param',
                    'url': url,
                    'param': param_name,
                    'value': param_values[0] if param_values else '',
                    'method': 'GET'
                })
        
        # Form inputs
        for form in crawl_state.forms:
            for inp in form.get_injectable_inputs():
                points.append({
                    'type': 'form_input',
                    'url': form.get_absolute_action(),
                    'page_url': form.page_url,
                    'param': inp.name,
                    'value': inp.value or '',
                    'method': form.method,
                    'form_selector': form.selector,
                    'input_type': inp.input_type
                })
        
        return points
    
    async def _handle_vuln_found(self, vuln_type: str, vuln):
        """Handle a found vulnerability"""
        if self.on_vuln_found:
            await self.on_vuln_found(vuln_type, vuln)
        
        # Log to console - use poc_url if available (the actual exploitable URL)
        if hasattr(vuln, 'param') and hasattr(vuln, 'payload'):
            # Prefer poc_url, fallback to url
            display_url = getattr(vuln, 'poc_url', None) or getattr(vuln, 'url', 'unknown')
            logger.vuln_found(
                vuln_type.upper(),
                display_url,
                vuln.param if hasattr(vuln, 'param') else vuln.injection_point,
                vuln.payload[:100]
            )
    
    async def _update_progress(self, phase: str, current: int, total: int):
        """Update progress"""
        if self.on_progress:
            await self.on_progress(phase, current, total)
    
    def get_stats(self) -> Dict:
        """Get combined statistics"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        return {
            'total_vulnerabilities': self.result.total,
            'reflected': len(self.result.reflected),
            'stored': len(self.result.stored),
            'dom': len(self.result.dom),
            'tests_completed': self.tests_completed,
            'elapsed_time': elapsed,
            'reflected_stats': self.reflected.get_stats(),
            'stored_stats': self.stored.get_stats(),
            'dom_stats': self.dom.get_stats()
        }
    
    def get_results(self) -> Dict:
        """Get all results"""
        return self.result.to_dict()
