"""
ScriptX Scanner
Main scanning controller that coordinates crawling and XSS detection
"""

import asyncio
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field
import time
import json
import os

from core.browser import BrowserController
from core.config import Config
from crawler.crawler import Crawler, CrawlState
from xss.detector import XSSDetector, XSSResult
from utils.logger import logger
from utils.reporter import Reporter


@dataclass
class ScanResult:
    """Complete scan result"""
    target: str
    scan_time: float
    crawl_stats: Dict = field(default_factory=dict)
    xss_result: Optional[XSSResult] = None
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'target': self.target,
            'scan_time': self.scan_time,
            'crawl': self.crawl_stats,
            'xss': self.xss_result.to_dict() if self.xss_result else {},
            'errors': self.errors
        }


class Scanner:
    """
    Main ScriptX Scanner
    
    Orchestrates:
    1. Browser launch
    2. Crawling
    3. XSS Detection
    4. Reporting
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.browser: Optional[BrowserController] = None
        self.crawler: Optional[Crawler] = None
        self.detector: Optional[XSSDetector] = None
        self.reporter = Reporter(config)
        
        # State
        self.crawl_state: Optional[CrawlState] = None
        self.scan_result: Optional[ScanResult] = None
        
        # Callbacks for real-time updates
        self.on_page_crawled: Optional[Callable] = None
        self.on_form_found: Optional[Callable] = None
        self.on_vuln_found: Optional[Callable] = None
        self.on_progress: Optional[Callable] = None
        
    async def cleanup(self):
        """Clean up resources (browser, etc.) - for graceful shutdown"""
        try:
            if self.browser:
                # Use force_close for faster cleanup during interrupts
                try:
                    await self.browser.force_close()
                except AttributeError:
                    # Fallback to regular close
                    await self.browser.close()
                self.browser = None
        except Exception:
            pass  # Ignore errors during cleanup
        
    async def scan(self, target_url: str) -> ScanResult:
        """
        Run a full scan on the target URL.
        
        Args:
            target_url: URL to scan
            
        Returns:
            ScanResult with all findings
        """
        start_time = time.time()
        
        logger.banner()
        logger.target_info(
            target_url,
            self.config.browser_type.value,
            self.config.scan_mode.value if hasattr(self.config.scan_mode, 'value') else str(self.config.scan_mode)
        )
        
        result = ScanResult(target=target_url, scan_time=0)
        
        try:
            # Initialize browser
            self.browser = BrowserController(self.config)
            await self.browser.launch()
            
            # Initialize components
            self.crawler = Crawler(self.browser, self.config)
            self.detector = XSSDetector(self.browser, self.config)
            
            # Set up callbacks
            self._setup_callbacks()
            
            # Phase 1: Crawling
            if self.config.crawl_enabled:
                logger.info("Phase 1: Crawling target...")
                self.crawl_state = await self.crawler.crawl(target_url)
                result.crawl_stats = self.crawler.get_stats()
                logger.info(f"Crawling complete: {result.crawl_stats}")
            else:
                logger.info("Crawling disabled, quick scanning URL only")
                self.crawl_state = await self.crawler.quick_crawl(target_url)
                result.crawl_stats = self.crawler.get_stats()
            
            # Phase 2: XSS Detection
            logger.info("Phase 2: XSS Detection...")
            result.xss_result = await self.detector.scan_from_crawl(self.crawl_state)
            
            # Store result
            self.scan_result = result
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            result.errors.append(str(e))
            
        finally:
            # Cleanup
            if self.browser:
                await self.browser.close()
        
        # Calculate scan time
        result.scan_time = time.time() - start_time
        
        # Generate reports
        await self._generate_reports(result)
        
        # Display summary
        self._display_summary(result)
        
        return result
    
    async def scan_quick(self, target_url: str) -> ScanResult:
        """
        Quick scan without crawling.
        Only tests the provided URL.
        """
        start_time = time.time()
        
        logger.banner()
        logger.target_info(target_url, self.config.browser_type.value, "Quick Scan")
        
        result = ScanResult(target=target_url, scan_time=0)
        
        try:
            # Initialize browser
            self.browser = BrowserController(self.config)
            await self.browser.launch()
            
            # Initialize detector
            self.detector = XSSDetector(self.browser, self.config)
            
            # Set up vuln callback
            if self.on_vuln_found:
                self.detector.on_vuln_found = self.on_vuln_found
            
            # Run quick scan
            result.xss_result = await self.detector.scan_url(target_url)
            
            self.scan_result = result
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            result.errors.append(str(e))
            
        finally:
            if self.browser:
                await self.browser.close()
        
        result.scan_time = time.time() - start_time
        
        await self._generate_reports(result)
        self._display_summary(result)
        
        return result
    
    async def scan_urls(self, urls: List[str]) -> List[ScanResult]:
        """
        Scan multiple URLs.
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of ScanResult for each URL
        """
        results = []
        
        logger.banner()
        logger.info(f"Scanning {len(urls)} URLs")
        
        try:
            # Initialize browser once
            self.browser = BrowserController(self.config)
            await self.browser.launch()
            
            for idx, url in enumerate(urls):
                logger.info(f"[{idx + 1}/{len(urls)}] Scanning: {url}")
                
                try:
                    # Create new components for each URL
                    self.crawler = Crawler(self.browser, self.config)
                    self.detector = XSSDetector(self.browser, self.config)
                    self._setup_callbacks()
                    
                    start_time = time.time()
                    result = ScanResult(target=url, scan_time=0)
                    
                    # Crawl
                    if self.config.crawl_enabled:
                        self.crawl_state = await self.crawler.crawl(url)
                    else:
                        self.crawl_state = await self.crawler.quick_crawl(url)
                    
                    result.crawl_stats = self.crawler.get_stats()
                    
                    # Detect
                    result.xss_result = await self.detector.scan_from_crawl(self.crawl_state)
                    
                    result.scan_time = time.time() - start_time
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Error scanning {url}: {e}")
                    result = ScanResult(target=url, scan_time=0, errors=[str(e)])
                    results.append(result)
            
        finally:
            if self.browser:
                await self.browser.close()
        
        # Generate combined report
        await self._generate_combined_report(results)
        
        return results
    
    def _setup_callbacks(self):
        """Set up callbacks for real-time updates"""
        if self.on_page_crawled and self.crawler:
            self.crawler.on_page_crawled = self.on_page_crawled
        
        if self.on_form_found and self.crawler:
            self.crawler.on_form_found = self.on_form_found
        
        if self.on_vuln_found and self.detector:
            self.detector.on_vuln_found = self.on_vuln_found
        
        if self.on_progress and self.detector:
            self.detector.on_progress = self.on_progress
    
    async def _generate_reports(self, result: ScanResult):
        """Generate output reports"""
        os.makedirs(self.config.output_dir, exist_ok=True)
        os.makedirs(f"{self.config.output_dir}/screenshots", exist_ok=True)
        
        # JSON report
        if self.config.output_format in ('json', 'all'):
            json_path = f"{self.config.output_dir}/scriptx_results.json"
            self.reporter.save_json(result.to_dict(), json_path)
            logger.info(f"JSON report saved: {json_path}")
        
        # HTML report
        if self.config.output_format in ('html', 'all'):
            html_path = f"{self.config.output_dir}/scriptx_report.html"
            self.reporter.save_html(result.to_dict(), html_path)
            logger.info(f"HTML report saved: {html_path}")
    
    async def _generate_combined_report(self, results: List[ScanResult]):
        """Generate combined report for multiple scans"""
        combined = {
            'total_targets': len(results),
            'total_vulnerabilities': sum(r.xss_result.total if r.xss_result else 0 for r in results),
            'results': [r.to_dict() for r in results]
        }
        
        json_path = f"{self.config.output_dir}/scriptx_combined_results.json"
        self.reporter.save_json(combined, json_path)
        logger.info(f"Combined report saved: {json_path}")
    
    def _display_summary(self, result: ScanResult):
        """Display scan summary"""
        vuln_count = result.xss_result.total if result.xss_result else 0
        
        logger.scan_summary(
            total_urls=result.crawl_stats.get('pages_crawled', 1),
            total_forms=result.crawl_stats.get('forms_found', 0),
            total_params=result.crawl_stats.get('total_params', 0),
            vulns_found=vuln_count,
            duration=result.scan_time
        )
        
        if vuln_count > 0:
            logger.warning(f"⚠️  Found {vuln_count} XSS vulnerabilities!")
        else:
            logger.success("✓ No XSS vulnerabilities found")
