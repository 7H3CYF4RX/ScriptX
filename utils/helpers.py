"""
ScriptX Helper Utilities
"""

import re
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple, Optional
import tldextract


def normalize_url(url: str) -> str:
    """Normalize URL for consistent comparison"""
    parsed = urlparse(url)
    # Remove trailing slash, fragment, sort query params
    path = parsed.path.rstrip('/') or '/'
    query = urlencode(sorted(parse_qs(parsed.query, keep_blank_values=True).items()))
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        '',  # params
        query,
        ''   # fragment
    ))


def get_domain(url: str) -> str:
    """Extract domain from URL"""
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"


def get_full_domain(url: str) -> str:
    """Get full domain including subdomain"""
    parsed = urlparse(url)
    return parsed.netloc


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs are on the same domain"""
    return get_domain(url1) == get_domain(url2)


def is_same_subdomain(url1: str, url2: str) -> bool:
    """Check if two URLs are on the same subdomain"""
    return get_full_domain(url1) == get_full_domain(url2)


def extract_params(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from URL"""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def inject_payload(url: str, param: str, payload: str) -> str:
    """Inject payload into URL parameter safely"""
    # Validate input URL first
    if not is_valid_url(url):
        return url  # Return original if invalid
    
    parsed = urlparse(url)
    
    # Don't inject into URLs that already look corrupted
    if any(c in parsed.path for c in ['<', '>', '()', '[]']):
        return url
    
    params = parse_qs(parsed.query, keep_blank_values=True)
    
    if param in params:
        params[param] = [payload]
    else:
        params[param] = [payload]
    
    new_query = urlencode(params, doseq=True)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        '',
        new_query,
        parsed.fragment
    ))


def get_url_hash(url: str) -> str:
    """Generate hash of URL for deduplication"""
    normalized = normalize_url(url)
    return hashlib.md5(normalized.encode()).hexdigest()[:16]


def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False


def clean_url(url: str) -> str:
    """Clean and validate URL"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def make_absolute_url(base_url: str, relative_url: str) -> str:
    """Convert relative URL to absolute"""
    return urljoin(base_url, relative_url)


def is_static_file(url: str) -> bool:
    """Check if URL points to a static file"""
    static_extensions = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp',
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    ]
    parsed = urlparse(url.lower())
    path = parsed.path
    return any(path.endswith(ext) for ext in static_extensions)


def generate_unique_id() -> str:
    """Generate unique identifier"""
    import uuid
    return str(uuid.uuid4())[:8]


def escape_html(text: str) -> str:
    """Escape HTML characters"""
    return (text
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#x27;'))


def detect_context(response_text: str, payload: str) -> Optional[str]:
    """
    Detect the context where payload appears in response
    Returns: 'html', 'attribute', 'script', 'url', 'comment', or None
    """
    if payload not in response_text:
        return None
    
    # Find payload position
    pos = response_text.find(payload)
    before = response_text[:pos]
    after = response_text[pos + len(payload):]
    
    # Check if inside HTML comment
    last_comment_start = before.rfind('<!--')
    last_comment_end = before.rfind('-->')
    if last_comment_start > last_comment_end:
        return 'comment'
    
    # Check if inside script tag
    last_script_open = before.rfind('<script')
    last_script_close = before.rfind('</script>')
    if last_script_open > last_script_close:
        return 'script'
    
    # Check if inside HTML attribute
    # Look for pattern like attribute="...payload..."
    attr_pattern = r'[\w-]+\s*=\s*["\'][^"\']*$'
    if re.search(attr_pattern, before):
        return 'attribute'
    
    # Check if inside URL (href, src, etc.)
    url_attr_pattern = r'(?:href|src|action|data|formaction)\s*=\s*["\'][^"\']*$'
    if re.search(url_attr_pattern, before, re.IGNORECASE):
        return 'url'
    
    return 'html'


def is_reflected(response_text: str, payload: str) -> bool:
    """Check if payload is reflected in response"""
    return payload in response_text


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file creation"""
    # Remove/replace invalid characters
    return re.sub(r'[<>:"/\\|?*]', '_', filename)
