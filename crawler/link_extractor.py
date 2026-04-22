"""
ScriptX Link Extractor
Extracts and normalizes links from web pages
"""

from typing import List, Set, Dict, Optional
from urllib.parse import urlparse, urljoin, urldefrag
import re
from bs4 import BeautifulSoup
from utils.helpers import (
    normalize_url, get_domain, is_same_domain, 
    is_same_subdomain, is_static_file, is_valid_url
)


class LinkExtractor:
    """Extract and filter links from HTML content"""
    
    def __init__(self, base_url: str, scope: str = 'domain'):
        """
        Initialize link extractor.
        
        Args:
            base_url: Base URL for resolving relative links
            scope: 'domain', 'subdomain', or 'all'
        """
        self.base_url = base_url
        self.scope = scope
        self.visited: Set[str] = set()
        self.discovered: Set[str] = set()
        
    def extract_from_html(self, html_content: str, page_url: str) -> List[str]:
        """Extract all links from HTML content"""
        links = []
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Extract from <a> tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = self._make_absolute(href, page_url)
            if absolute_url and self._is_in_scope(absolute_url):
                links.append(absolute_url)
        
        # Extract from <form> action attributes
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action:
                absolute_url = self._make_absolute(action, page_url)
                if absolute_url and self._is_in_scope(absolute_url):
                    links.append(absolute_url)
        
        # Extract from <iframe> and <frame> src
        for frame in soup.find_all(['iframe', 'frame'], src=True):
            src = frame['src']
            absolute_url = self._make_absolute(src, page_url)
            if absolute_url and self._is_in_scope(absolute_url):
                links.append(absolute_url)
        
        # Extract from JavaScript (basic extraction)
        links.extend(self._extract_from_scripts(soup, page_url))
        
        # Filter and deduplicate
        filtered = self._filter_links(links)
        
        return filtered
    
    def _extract_from_scripts(self, soup: BeautifulSoup, page_url: str) -> List[str]:
        """Extract URLs from JavaScript code"""
        links = []
        
        # URL patterns in JS
        url_patterns = [
            r'["\']((https?:)?//[^"\']+)["\']',  # Absolute URLs
            r'["\'](/[^"\']+)["\']',  # Root-relative URLs
            r'location\s*=\s*["\']([^"\']+)["\']',  # location assignments
            r'window\.open\s*\(["\']([^"\']+)["\']',  # window.open
            r'fetch\s*\(["\']([^"\']+)["\']',  # fetch calls
            r'\.ajax\s*\(\s*{\s*url:\s*["\']([^"\']+)["\']',  # jQuery ajax
        ]
        
        for script in soup.find_all('script'):
            if script.string:
                for pattern in url_patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        url = match[0] if isinstance(match, tuple) else match
                        if url and not url.startswith('data:'):
                            absolute_url = self._make_absolute(url, page_url)
                            if absolute_url and self._is_in_scope(absolute_url):
                                links.append(absolute_url)
        
        return links
    
    def _make_absolute(self, url: str, page_url: str) -> Optional[str]:
        """Convert URL to absolute URL with strict validation"""
        if not url:
            return None
        
        # Skip unwanted URL types
        if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
            return None
        
        # Skip URLs that look like code/payloads (not real URLs)
        suspicious_patterns = [
            '()', '[]', '{}', '<>', 'alert', 'script', 'onerror', 
            'onclick', 'onload', 'eval(', 'document.', 'window.',
            '\\x', '\\u', '%3C', '%3E', '&lt;', '&gt;'
        ]
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern.lower() in url_lower:
                return None
        
        # Remove fragment
        url = urldefrag(url)[0]
        
        if not url:
            return None
        
        # Make absolute
        try:
            absolute = urljoin(page_url, url)
            
            # Validate the result
            parsed = urlparse(absolute)
            
            # Must have valid scheme and netloc
            if parsed.scheme not in ('http', 'https') or not parsed.netloc:
                return None
            
            # Path should not contain obvious payload patterns
            path = parsed.path
            if any(c in path for c in ['<', '>', '"', "'", '()', '[]']):
                return None
            
            return normalize_url(absolute)
        except:
            return None
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within configured scope"""
        if not is_valid_url(url):
            return False
        
        if self.scope == 'all':
            return True
        elif self.scope == 'subdomain':
            return is_same_subdomain(url, self.base_url)
        else:  # domain
            return is_same_domain(url, self.base_url)
    
    def _filter_links(self, links: List[str]) -> List[str]:
        """Filter and deduplicate links"""
        filtered = []
        seen = set()
        
        for link in links:
            if link in seen:
                continue
            
            # Skip static files
            if is_static_file(link):
                continue
            
            # Skip already visited
            if link in self.visited:
                continue
            
            seen.add(link)
            filtered.append(link)
            self.discovered.add(link)
        
        return filtered
    
    def mark_visited(self, url: str):
        """Mark URL as visited"""
        normalized = normalize_url(url)
        self.visited.add(normalized)
    
    def get_unvisited(self) -> List[str]:
        """Get discovered but unvisited URLs"""
        return list(self.discovered - self.visited)
    
    def get_stats(self) -> Dict[str, int]:
        """Get extraction statistics"""
        return {
            'discovered': len(self.discovered),
            'visited': len(self.visited),
            'pending': len(self.discovered - self.visited)
        }
