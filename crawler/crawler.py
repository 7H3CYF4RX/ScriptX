"""
ScriptX Web Crawler
Intelligent crawling with browser-based navigation
"""

import asyncio
from typing import List, Dict, Set, Optional, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import re
import time

from core.browser import BrowserController
from core.config import Config, CrawlScope
from crawler.link_extractor import LinkExtractor
from crawler.form_finder import FormFinder, Form
from crawler.dom_analyzer import DomAnalyzer
from utils.logger import logger
from utils.helpers import normalize_url, is_static_file, extract_params


@dataclass
class CrawlResult:
    """Result of crawling a single page"""
    url: str
    status: str  # success, error, skipped
    links_found: int = 0
    forms_found: int = 0
    params_found: int = 0
    dom_risk_score: int = 0
    has_captcha: bool = False
    error: Optional[str] = None
    

@dataclass
class CrawlState:
    """Current state of the crawler"""
    visited: Set[str] = field(default_factory=set)
    pending: Set[str] = field(default_factory=set)
    forms: List[Form] = field(default_factory=list)
    url_params: Dict[str, Dict] = field(default_factory=dict)  # URL -> params
    dom_analysis: Dict[str, Dict] = field(default_factory=dict)  # URL -> analysis
    

class Crawler:
    """
    Browser-based web crawler for XSS scanning.
    
    Features:
    - Depth-controlled crawling
    - Scope restriction (domain/subdomain)
    - Form discovery
    - Parameter extraction
    - DOM analysis
    - Rate limiting
    """
    
    def __init__(self, browser: BrowserController, config: Config):
        self.browser = browser
        self.config = config
        self.state = CrawlState()
        
        # Initialize components
        self.link_extractor: Optional[LinkExtractor] = None
        self.form_finder = FormFinder()
        self.dom_analyzer = DomAnalyzer()
        
        # Callbacks for real-time updates
        self.on_page_crawled: Optional[Callable] = None
        self.on_form_found: Optional[Callable] = None
        self.on_param_found: Optional[Callable] = None
        
        # Exclude patterns
        self.exclude_patterns = [re.compile(p) for p in config.exclude_patterns]
        
    async def crawl(self, start_url: str, max_pages: int = 100) -> CrawlState:
        """
        Start crawling from the given URL.
        
        Args:
            start_url: URL to start crawling from
            max_pages: Maximum number of pages to crawl (overridden by config.max_urls if set)
            
        Returns:
            CrawlState with all discovered data
        """
        # Initialize
        start_url = normalize_url(start_url)
        scope = self.config.crawl_scope.value if isinstance(self.config.crawl_scope, CrawlScope) else self.config.crawl_scope
        self.link_extractor = LinkExtractor(start_url, scope=scope)
        
        # Use config.max_urls if set, otherwise use max_pages
        url_limit = self.config.max_urls if self.config.max_urls > 0 else max_pages
        
        # Add start URL to pending
        self.state.pending.add(start_url)
        
        logger.info(f"Starting crawl from: {start_url}")
        logger.info(f"Max depth: {self.config.max_depth}, Scope: {scope}, Max URLs: {url_limit if self.config.max_urls > 0 else 'unlimited'}")
        
        pages_crawled = 0
        current_depth = 0
        depth_urls = {0: {start_url}}
        
        # Track all seen URLs to prevent duplicates
        seen_urls: Set[str] = set()
        seen_urls.add(normalize_url(start_url))
        
        while current_depth <= self.config.max_depth and pages_crawled < url_limit:
            current_level_urls = depth_urls.get(current_depth, set())
            
            if not current_level_urls:
                break
                
            logger.debug(f"Crawling depth {current_depth}: {len(current_level_urls)} URLs")
            
            next_level_urls = set()
            
            for url in current_level_urls:
                # Normalize URL to prevent duplicates
                normalized = normalize_url(url)
                
                if normalized in self.state.visited:
                    continue
                
                # Check URL limit
                if pages_crawled >= url_limit:
                    logger.info(f"Reached max URL limit ({url_limit})")
                    break
                
                # Check exclusions
                if self._should_exclude(url):
                    logger.debug(f"Excluding: {url}")
                    continue
                
                # Crawl the page
                result = await self._crawl_page(url)
                pages_crawled += 1
                
                if result.status == 'success':
                    # Get new links for next depth (deduplicated)
                    unvisited = self.link_extractor.get_unvisited()
                    for link in unvisited:
                        norm_link = normalize_url(link)
                        if norm_link not in seen_urls:
                            seen_urls.add(norm_link)
                            next_level_urls.add(link)
                    
                    # Callback
                    if self.on_page_crawled:
                        await self.on_page_crawled(result)
                
                # Rate limiting
                if self.config.request_delay > 0:
                    await asyncio.sleep(self.config.request_delay / 1000)
            
            # Move to next depth
            current_depth += 1
            depth_urls[current_depth] = next_level_urls - self.state.visited
        
        logger.success(f"Crawl complete: {pages_crawled} pages, {len(self.state.forms)} forms, {len(self.state.url_params)} URLs with params")
        
        return self.state
    
    async def _crawl_page(self, url: str) -> CrawlResult:
        """Crawl a single page"""
        result = CrawlResult(url=url, status='success')
        
        try:
            # Mark as visited
            self.state.visited.add(url)
            self.link_extractor.mark_visited(url)
            
            # Navigate to page
            success = await self.browser.navigate(url)
            
            if not success:
                result.status = 'error'
                result.error = 'Navigation failed'
                return result
            
            # Check for CAPTCHA on every page
            has_captcha = await self.browser.check_for_captcha()
            if has_captcha:
                if self.config.interactive:
                    # Pause for user to solve manually
                    logger.warning(f"CAPTCHA detected on {url}")
                    await self.browser.wait_for_captcha()
                else:
                    # Log and skip this page's forms (can't submit with CAPTCHA)
                    logger.warning(f"CAPTCHA detected on {url} — skipping forms on this page")
                    result.has_captcha = True
            
            # Get page content
            html_content = await self.browser.get_page_source()
            current_url = self.browser.page.url
            
            # Extract links
            links = self.link_extractor.extract_from_html(html_content, current_url)
            result.links_found = len(links)
            
            # Find forms
            forms = self.form_finder.find_forms(html_content, current_url)
            result.forms_found = len(forms)
            self.state.forms.extend(forms)
            
            # Mark forms on CAPTCHA pages
            if result.has_captcha:
                for form in forms:
                    form.has_captcha = True
            
            # Form callback
            for form in forms:
                if self.on_form_found:
                    await self.on_form_found(form)
            
            # Extract URL parameters
            url_params = extract_params(current_url)
            if url_params:
                self.state.url_params[current_url] = url_params
                result.params_found = len(url_params)
                
                if self.on_param_found:
                    await self.on_param_found(current_url, url_params)
            
            # Also check for params in discovered links
            for link in links:
                link_params = extract_params(link)
                if link_params and link not in self.state.url_params:
                    self.state.url_params[link] = link_params
            
            # DOM analysis
            dom_result = self.dom_analyzer.analyze_html(html_content)
            self.state.dom_analysis[current_url] = dom_result
            result.dom_risk_score = dom_result.get('risk_score', 0)
            
            logger.debug(f"Crawled: {url} - Links: {result.links_found}, Forms: {result.forms_found}, DOM Risk: {result.dom_risk_score}")
            
        except Exception as e:
            result.status = 'error'
            result.error = str(e)
            logger.debug(f"Error crawling {url}: {e}")
        
        return result
    
    def _should_exclude(self, url: str) -> bool:
        """Check if URL should be excluded"""
        # Skip static files
        if is_static_file(url):
            return True
        
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if pattern.search(url):
                return True
        
        return False
    
    async def quick_crawl(self, url: str) -> CrawlState:
        """
        Quick crawl - just the single page, no depth.
        Useful for testing a specific URL.
        """
        url = normalize_url(url)
        scope = self.config.crawl_scope.value if isinstance(self.config.crawl_scope, CrawlScope) else self.config.crawl_scope
        self.link_extractor = LinkExtractor(url, scope=scope)
        
        await self._crawl_page(url)
        
        return self.state
    
    def get_all_injection_points(self) -> List[Dict]:
        """
        Get all discovered injection points.
        Combines URL parameters and form inputs.
        """
        injection_points = []
        
        # URL parameters
        for url, params in self.state.url_params.items():
            for param_name, param_values in params.items():
                injection_points.append({
                    'type': 'url_param',
                    'url': url,
                    'param': param_name,
                    'value': param_values[0] if param_values else '',
                    'method': 'GET'
                })
        
        # Form inputs
        for form in self.state.forms:
            for inp in form.get_injectable_inputs():
                injection_points.append({
                    'type': 'form_input',
                    'url': form.get_absolute_action(),
                    'param': inp.name,
                    'value': inp.value or '',
                    'method': form.method,
                    'form_selector': form.selector,
                    'input_type': inp.input_type
                })
        
        return injection_points
    
    def get_stats(self) -> Dict:
        """Get crawl statistics"""
        form_stats = self.form_finder.get_stats()
        
        total_params = sum(len(p) for p in self.state.url_params.values())
        high_risk_pages = sum(1 for d in self.state.dom_analysis.values() if d.get('risk_score', 0) > 50)
        
        return {
            'pages_crawled': len(self.state.visited),
            'forms_found': form_stats['forms'],
            'injectable_inputs': form_stats['injectable_inputs'],
            'urls_with_params': len(self.state.url_params),
            'total_params': total_params,
            'high_risk_pages': high_risk_pages,
            'total_injection_points': len(self.get_all_injection_points())
        }
