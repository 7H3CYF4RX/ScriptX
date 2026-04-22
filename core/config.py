"""
ScriptX Configuration Management
"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
import json
import os


class BrowserType(Enum):
    FIREFOX = "firefox"
    CHROME = "chromium"
    WEBKIT = "webkit"


class ScanMode(Enum):
    ALL = "all"
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"


class CrawlScope(Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    ALL = "all"


@dataclass
class Config:
    """ScriptX Configuration"""
    
    # Target
    target_url: Optional[str] = None
    target_list: Optional[str] = None
    
    # Browser Settings
    browser_type: BrowserType = BrowserType.CHROME
    headless: bool = True
    timeout: int = 30000  # ms
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    
    # Crawling Settings
    crawl_enabled: bool = True
    max_depth: int = 3
    max_urls: int = 0  # Maximum URLs to crawl, 0 = unlimited
    crawl_scope: CrawlScope = CrawlScope.DOMAIN
    exclude_patterns: List[str] = field(default_factory=lambda: [
        r'.*\.(jpg|jpeg|png|gif|svg|ico|webp|bmp)$',
        r'.*\.(css|js|woff|woff2|ttf|eot)$',
        r'.*\.(pdf|doc|docx|xls|xlsx|zip|rar)$',
        r'.*/logout.*',
        r'.*/signout.*',
    ])
    
    # Scanning Settings
    scan_mode: ScanMode = ScanMode.ALL
    custom_payloads: Optional[str] = None
    waf_bypass: bool = True
    request_delay: int = 100  # ms
    max_payloads_per_param: int = 20
    verify_ssl: bool = True
    
    # Smart Mode & Throttling
    smart_mode: bool = False  # Start with simple payloads, escalate if needed
    waf_fingerprint: bool = True  # Auto-detect WAF and use targeted payloads
    random_delay: bool = False  # Random delay between requests
    min_delay: int = 500  # Min delay for random mode (ms)
    max_delay: int = 3000  # Max delay for random mode (ms)
    
    # Stealth & CAPTCHA Settings
    stealth_mode: bool = False  # Enable anti-detection techniques
    interactive: bool = False   # Pause for manual CAPTCHA solving
    
    # Authentication
    cookies: Optional[str] = None
    headers: dict = field(default_factory=dict)
    
    # Output Settings
    output_format: str = "json"
    output_dir: str = "./output"
    screenshots: bool = True
    verbose: bool = False
    
    # Dashboard
    dashboard_enabled: bool = False
    dashboard_port: int = 8888
    
    @classmethod
    def from_file(cls, path: str) -> 'Config':
        """Load configuration from JSON file"""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)
    
    def to_file(self, path: str) -> None:
        """Save configuration to JSON file"""
        data = {
            'target_url': self.target_url,
            'browser_type': self.browser_type.value,
            'headless': self.headless,
            'timeout': self.timeout,
            'crawl_enabled': self.crawl_enabled,
            'max_depth': self.max_depth,
            'crawl_scope': self.crawl_scope.value,
            'scan_mode': self.scan_mode.value,
            'waf_bypass': self.waf_bypass,
            'request_delay': self.request_delay,
            'output_format': self.output_format,
            'output_dir': self.output_dir,
            'screenshots': self.screenshots,
            'verbose': self.verbose,
        }
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def validate(self) -> bool:
        """Validate configuration"""
        if not self.target_url and not self.target_list:
            raise ValueError("Either target_url or target_list must be provided")
        return True
