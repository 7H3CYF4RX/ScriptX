"""
ScriptX Browser Controller
Full browser control using Playwright for XSS detection
"""

import asyncio
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Dialog
from urllib.parse import urlparse
import os
import json

from core.config import Config, BrowserType
from utils.logger import logger


@dataclass
class AlertCapture:
    """Captured JavaScript alert/confirm/prompt"""
    type: str  # alert, confirm, prompt
    message: str
    url: str
    timestamp: float


@dataclass
class PageState:
    """State captured from a page"""
    url: str
    title: str
    html: str
    dom_snapshot: Optional[str] = None
    cookies: List[Dict] = field(default_factory=list)
    console_logs: List[str] = field(default_factory=list)
    network_requests: List[Dict] = field(default_factory=list)


class BrowserController:
    """
    Playwright-based browser controller for XSS detection.
    Supports Firefox, Chrome (Chromium), and WebKit.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        
        # Alert capture
        self.captured_alerts: List[AlertCapture] = []
        self._alert_callback: Optional[Callable] = None
        
        # Console capture
        self.console_logs: List[str] = []
        
        # Network capture
        self.network_requests: List[Dict] = []
        
    async def launch(self) -> bool:
        """Launch browser with configured settings"""
        try:
            self.playwright = await async_playwright().start()
            
            # Select browser type
            browser_map = {
                BrowserType.FIREFOX: self.playwright.firefox,
                BrowserType.CHROME: self.playwright.chromium,
                BrowserType.WEBKIT: self.playwright.webkit,
            }
            
            browser_launcher = browser_map.get(self.config.browser_type, self.playwright.chromium)
            
            # Launch options
            launch_options = {
                'headless': self.config.headless,
            }
            
            # Stealth mode - add anti-detection args
            if self.config.stealth_mode and self.config.browser_type in (BrowserType.CHROME, BrowserType.WEBKIT):
                launch_options['args'] = [
                    '--disable-blink-features=AutomationControlled',
                    '--disable-infobars',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                ]
            
            # Add proxy if configured
            if self.config.proxy:
                launch_options['proxy'] = {'server': self.config.proxy}
            
            logger.debug(f"Launching {self.config.browser_type.value} browser (headless={self.config.headless}, stealth={self.config.stealth_mode})")
            self.browser = await browser_launcher.launch(**launch_options)
            
            # Create context with optional user agent
            context_options = {
                'ignore_https_errors': not self.config.verify_ssl,
            }
            
            # Stealth mode - use realistic user agent
            if self.config.stealth_mode:
                context_options['user_agent'] = self.config.user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                context_options['viewport'] = {'width': 1920, 'height': 1080}
                context_options['locale'] = 'en-US'
                context_options['timezone_id'] = 'America/New_York'
            elif self.config.user_agent:
                context_options['user_agent'] = self.config.user_agent
            
            self.context = await self.browser.new_context(**context_options)
            
            # Load cookies if provided
            if self.config.cookies:
                await self._load_cookies()
            
            # Create main page
            self.page = await self.context.new_page()
            
            # Stealth mode - inject anti-detection scripts
            if self.config.stealth_mode:
                await self._inject_stealth_scripts()
            
            # Set timeout
            self.page.set_default_timeout(self.config.timeout)
            
            # Setup event listeners
            await self._setup_listeners()
            
            logger.success(f"Browser launched: {self.config.browser_type.value}" + (" [STEALTH]" if self.config.stealth_mode else ""))
            return True
            
        except Exception as e:
            logger.error(f"Failed to launch browser: {e}")
    
    async def _inject_stealth_scripts(self):
        """Inject anti-detection JavaScript"""
        stealth_js = """
        // Override navigator.webdriver
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        
        // Override chrome detection
        window.chrome = { runtime: {} };
        
        // Override permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
        );
        
        // Override plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });
        
        // Override languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });
        """
        await self.page.add_init_script(stealth_js)
    
    async def wait_for_captcha(self, timeout: int = 60):
        """
        Wait for user to solve CAPTCHA manually.
        Shows a prompt and waits for user input.
        """
        from rich.console import Console
        console = Console()
        
        console.print("\n[bold yellow]⚠️  CAPTCHA DETECTED[/bold yellow]")
        console.print("[cyan]Please solve the CAPTCHA in the browser window.[/cyan]")
        console.print(f"[dim]Waiting up to {timeout} seconds...[/dim]")
        console.print("[green]Press ENTER when done (or wait for auto-continue)...[/green]\n")
        
        import sys
        import select
        
        # Wait for user input or timeout
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            # Check if user pressed Enter (non-blocking)
            if sys.stdin in select.select([sys.stdin], [], [], 0.5)[0]:
                sys.stdin.readline()
                console.print("[green]✓ Continuing...[/green]")
                return True
            
            # Small delay to avoid CPU spinning
            await asyncio.sleep(0.5)
        
        console.print("[yellow]Timeout reached, continuing scan...[/yellow]")
        return False
    
    async def check_for_captcha(self) -> bool:
        """
        Check if current page has an active CAPTCHA challenge.
        Detects visible CAPTCHA widgets (reCAPTCHA, hCaptcha, Cloudflare).
        """
        try:
            # Check for reCAPTCHA iframes (various src patterns)
            recaptcha_iframes = await self.page.query_selector_all('iframe[src*="recaptcha"]')
            for iframe in recaptcha_iframes:
                if await iframe.is_visible():
                    return True
            
            # Check for hCaptcha iframes
            hcaptcha_iframes = await self.page.query_selector_all('iframe[src*="hcaptcha"]')
            for iframe in hcaptcha_iframes:
                if await iframe.is_visible():
                    return True
            
            # Check for Cloudflare Turnstile iframes
            cf_iframes = await self.page.query_selector_all('iframe[src*="challenges.cloudflare"]')
            for iframe in cf_iframes:
                if await iframe.is_visible():
                    return True
            
            # Check for reCAPTCHA widget div (.g-recaptcha)
            recaptcha_divs = await self.page.query_selector_all('.g-recaptcha')
            for div in recaptcha_divs:
                if await div.is_visible():
                    return True
            
            # Check for hCaptcha widget div
            hcaptcha_divs = await self.page.query_selector_all('.h-captcha')
            for div in hcaptcha_divs:
                if await div.is_visible():
                    return True
            
            # Check for Cloudflare Turnstile div
            cf_divs = await self.page.query_selector_all('.cf-turnstile')
            for div in cf_divs:
                if await div.is_visible():
                    return True
            
            # Check for "I'm not a robot" text near a checkbox
            try:
                not_robot = await self.page.query_selector('text="I\'m not a robot"')
                if not_robot and await not_robot.is_visible():
                    return True
            except Exception:
                pass
            
            # Check for Cloudflare challenge page
            cf_challenge = await self.page.query_selector('#cf-challenge-running')
            if cf_challenge:
                return True
            
            return False
        except Exception:
            return False
    
    async def _setup_listeners(self):
        """Setup page event listeners"""
        
        # Dialog handler (alerts, confirms, prompts)
        async def handle_dialog(dialog: Dialog):
            alert = AlertCapture(
                type=dialog.type,
                message=dialog.message,
                url=self.page.url,
                timestamp=asyncio.get_event_loop().time()
            )
            self.captured_alerts.append(alert)
            logger.debug(f"Alert captured: {dialog.type} - {dialog.message[:50]}...")
            
            if self._alert_callback:
                await self._alert_callback(alert)
            
            # Wait before dismissing so user can see the alert in headed mode
            if not self.config.headless:
                await asyncio.sleep(1.5)  # 1.5 second delay to view alert
            
            # Dismiss the dialog
            await dialog.dismiss()
        
        self.page.on('dialog', handle_dialog)
        
        # Console handler
        def handle_console(msg):
            self.console_logs.append(f"[{msg.type}] {msg.text}")
        
        self.page.on('console', handle_console)
        
        # Network handler
        async def handle_request(request):
            self.network_requests.append({
                'url': request.url,
                'method': request.method,
                'headers': await request.all_headers(),
            })
        
        self.page.on('request', handle_request)
    
    async def _load_cookies(self):
        """Load cookies from file or string"""
        try:
            if os.path.isfile(self.config.cookies):
                with open(self.config.cookies, 'r') as f:
                    cookies = json.load(f)
            else:
                cookies = json.loads(self.config.cookies)
            
            await self.context.add_cookies(cookies)
            logger.debug(f"Loaded {len(cookies)} cookies")
        except Exception as e:
            logger.warning(f"Failed to load cookies: {e}")
    
    async def navigate(self, url: str, wait_until: str = 'domcontentloaded') -> bool:
        """Navigate to URL"""
        try:
            logger.debug(f"Navigating to: {url}")
            response = await self.page.goto(url, wait_until=wait_until)
            
            if response:
                logger.debug(f"Response status: {response.status}")
                return response.status < 400
            return True
            
        except Exception as e:
            logger.debug(f"Navigation error: {e}")
            return False
    
    async def get_page_source(self) -> str:
        """Get current page HTML source"""
        return await self.page.content()
    
    async def get_page_state(self) -> PageState:
        """Capture complete page state"""
        return PageState(
            url=self.page.url,
            title=await self.page.title(),
            html=await self.page.content(),
            cookies=await self.context.cookies(),
            console_logs=self.console_logs.copy(),
            network_requests=self.network_requests.copy()
        )
    
    async def inject_in_url(self, url: str, wait_for_alert: bool = True, 
                           alert_timeout: float = 2.0) -> Optional[AlertCapture]:
        """
        Navigate to URL (with payload in params) and check for alerts.
        Returns captured alert if XSS executed, None otherwise.
        """
        # Clear previous alerts
        self.captured_alerts.clear()
        
        # Navigate
        await self.navigate(url)
        
        # Wait for potential alert
        if wait_for_alert:
            await asyncio.sleep(alert_timeout)
        
        # Return first captured alert if any
        return self.captured_alerts[0] if self.captured_alerts else None
    
    async def inject_in_form(self, form_selector: str, inputs: Dict[str, str], 
                            submit: bool = True, alert_timeout: float = 2.0) -> Optional[AlertCapture]:
        """
        Fill form with payloads and submit.
        Handles text inputs, textareas, checkboxes, radio buttons, and selects.
        Returns captured alert if XSS executed.
        """
        # Clear previous alerts
        self.captured_alerts.clear()
        
        try:
            # Auto-fill checkboxes, selects, and required fields in the form
            await self._auto_fill_form(form_selector)
            
            # Fill each specified input (payloads go here)
            for selector, value in inputs.items():
                try:
                    # Determine element type
                    el_type = await self.page.evaluate(f'''() => {{
                        const el = document.querySelector("{selector}");
                        if (!el) return null;
                        return {{
                            tag: el.tagName.toLowerCase(),
                            type: (el.type || '').toLowerCase()
                        }};
                    }}''')
                    
                    if not el_type:
                        continue
                    
                    tag = el_type.get('tag', '')
                    input_type = el_type.get('type', '')
                    
                    if tag == 'select':
                        # Try to select by value, fallback to first non-empty option
                        try:
                            await self.page.select_option(selector, value=value)
                        except:
                            try:
                                await self.page.select_option(selector, index=1)
                            except:
                                pass
                    elif input_type == 'checkbox':
                        await self.page.check(selector)
                    elif input_type == 'radio':
                        await self.page.check(selector)
                    elif input_type in ('text', 'email', 'password', 'search', 'tel', 'url', 'number', '') or tag == 'textarea':
                        await self.page.fill(selector, value)
                    else:
                        await self.page.fill(selector, value)
                        
                except Exception:
                    # Fallback: try JS injection
                    try:
                        escaped_value = value.replace('`', '\\`').replace('\\', '\\\\')
                        await self.page.evaluate(f'''() => {{
                            const el = document.querySelector("{selector}");
                            if (el) {{ el.value = `{escaped_value}`; el.dispatchEvent(new Event('input', {{bubbles: true}})); }}
                        }}''')
                    except:
                        logger.debug(f"Could not fill input: {selector}")
            
            if submit:
                # Find and click submit button
                submit_selectors = [
                    f'{form_selector} input[type="submit"]',
                    f'{form_selector} button[type="submit"]',
                    f'{form_selector} button:not([type])',
                    f'{form_selector} input[type="button"]',
                ]
                
                for sel in submit_selectors:
                    try:
                        await self.page.click(sel)
                        break
                    except:
                        continue
                else:
                    # Try submitting the form directly
                    try:
                        await self.page.evaluate(f'''
                            document.querySelector("{form_selector}").submit();
                        ''')
                    except:
                        logger.debug("Could not submit form")
            
            # Wait for potential alert
            await asyncio.sleep(alert_timeout)
            
            return self.captured_alerts[0] if self.captured_alerts else None
            
        except Exception as e:
            logger.debug(f"Form injection error: {e}")
            return None
    
    async def _auto_fill_form(self, form_selector: str):
        """
        Auto-fill form elements that need special handling:
        - Check all required checkboxes
        - Select first valid option in dropdowns
        - Fill required fields with dummy data
        """
        try:
            # Handle all select elements - pick first non-empty option
            selects = await self.page.query_selector_all(f'{form_selector} select')
            for select in selects:
                try:
                    # Select the second option (first is usually "Please select...")
                    options = await select.query_selector_all('option')
                    if len(options) > 1:
                        value = await options[1].get_attribute('value')
                        if value:
                            name = await select.get_attribute('name')
                            if name:
                                await self.page.select_option(f'{form_selector} select[name="{name}"]', index=1)
                except Exception:
                    pass
            
            # Handle checkboxes - check required ones and privacy/consent checkboxes
            checkboxes = await self.page.query_selector_all(f'{form_selector} input[type="checkbox"]')
            for checkbox in checkboxes:
                try:
                    is_required = await checkbox.get_attribute('required')
                    name = (await checkbox.get_attribute('name') or '').lower()
                    cb_id = (await checkbox.get_attribute('id') or '').lower()
                    
                    # Check required checkboxes, consent/privacy/terms checkboxes
                    consent_keywords = ['consent', 'privacy', 'agree', 'terms', 'accept', 'gdpr', 'policy']
                    should_check = is_required is not None or any(k in name or k in cb_id for k in consent_keywords)
                    
                    if should_check:
                        is_checked = await checkbox.is_checked()
                        if not is_checked:
                            await checkbox.check()
                except Exception:
                    pass
            
            # Handle radio buttons - select first option in each group
            radio_groups_handled = set()
            radios = await self.page.query_selector_all(f'{form_selector} input[type="radio"]')
            for radio in radios:
                try:
                    name = await radio.get_attribute('name')
                    if name and name not in radio_groups_handled:
                        is_checked = await radio.is_checked()
                        if not is_checked:
                            await radio.check()
                        radio_groups_handled.add(name)
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"Auto-fill error: {e}")
    
    async def execute_js(self, script: str) -> Any:
        """Execute JavaScript in page context"""
        try:
            return await self.page.evaluate(script)
        except Exception as e:
            logger.debug(f"JS execution error: {e}")
            return None
    
    async def check_dom_xss(self, payload: str, sinks: List[str] = None) -> Dict[str, bool]:
        """
        Check for DOM-based XSS by monitoring dangerous sinks.
        Injects payload into sources and monitors sinks.
        """
        if sinks is None:
            sinks = [
                'document.write',
                'document.writeln',
                'innerHTML',
                'outerHTML',
                'insertAdjacentHTML',
                'eval',
                'setTimeout',
                'setInterval',
                'Function',
                'location',
                'location.href',
                'location.replace',
                'location.assign',
            ]
        
        results = {}
        
        # Monitor each sink
        monitor_script = '''
        (function() {
            window.__xss_sinks_triggered = {};
            
            // Override document.write
            const origWrite = document.write;
            document.write = function(content) {
                if (content.includes('SCRIPTX_XSS_MARKER')) {
                    window.__xss_sinks_triggered['document.write'] = content;
                }
                return origWrite.apply(this, arguments);
            };
            
            // Override innerHTML setter
            const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(value) {
                    if (value && value.includes && value.includes('SCRIPTX_XSS_MARKER')) {
                        window.__xss_sinks_triggered['innerHTML'] = value;
                    }
                    return origInnerHTML.set.call(this, value);
                },
                get: origInnerHTML.get
            });
            
            // Override eval
            const origEval = window.eval;
            window.eval = function(code) {
                if (code && code.includes && code.includes('SCRIPTX_XSS_MARKER')) {
                    window.__xss_sinks_triggered['eval'] = code;
                }
                return origEval.apply(this, arguments);
            };
        })();
        '''
        
        try:
            await self.page.evaluate(monitor_script)
            
            # Check what sinks were triggered
            triggered = await self.page.evaluate('window.__xss_sinks_triggered || {}')
            
            for sink in sinks:
                results[sink] = sink in triggered
                
        except Exception as e:
            logger.debug(f"DOM XSS check error: {e}")
        
        return results
    
    async def screenshot(self, path: str, full_page: bool = False) -> bool:
        """Take screenshot of current page"""
        try:
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            await self.page.screenshot(path=path, full_page=full_page)
            logger.debug(f"Screenshot saved: {path}")
            return True
        except Exception as e:
            logger.debug(f"Screenshot error: {e}")
            return False
    
    async def get_all_links(self) -> List[str]:
        """Get all links from current page"""
        links = await self.page.evaluate('''
            Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('mailto:'))
        ''')
        return links
    
    async def get_all_forms(self) -> List[Dict]:
        """Get all forms from current page"""
        forms = await self.page.evaluate('''
            Array.from(document.querySelectorAll('form')).map((form, index) => ({
                index: index,
                id: form.id || null,
                name: form.name || null,
                action: form.action || window.location.href,
                method: (form.method || 'GET').toUpperCase(),
                enctype: form.enctype || 'application/x-www-form-urlencoded',
                inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(input => ({
                    name: input.name || null,
                    id: input.id || null,
                    type: input.type || 'text',
                    value: input.value || '',
                    placeholder: input.placeholder || '',
                    required: input.required || false,
                    tagName: input.tagName.toLowerCase()
                })).filter(i => i.name)
            }))
        ''')
        return forms
    
    async def get_url_params(self) -> Dict[str, str]:
        """Get URL parameters from current page"""
        params = await self.page.evaluate('''
            Object.fromEntries(new URLSearchParams(window.location.search))
        ''')
        return params
    
    async def wait_for_navigation(self, timeout: int = None):
        """Wait for page navigation to complete"""
        timeout = timeout or self.config.timeout
        await self.page.wait_for_load_state('domcontentloaded', timeout=timeout)
    
    async def new_page(self) -> Page:
        """Create a new page in the same context"""
        return await self.context.new_page()
    
    def clear_alerts(self):
        """Clear captured alerts"""
        self.captured_alerts.clear()
    
    def clear_logs(self):
        """Clear console logs"""
        self.console_logs.clear()
    
    def clear_network(self):
        """Clear network requests"""
        self.network_requests.clear()
    
    async def close(self):
        """Close browser and cleanup gracefully"""
        # Set references to None first to prevent multiple close attempts
        page = self.page
        context = self.context
        browser = self.browser
        playwright = self.playwright
        
        self.page = None
        self.context = None
        self.browser = None
        self.playwright = None
        
        try:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
        except Exception:
            pass
        
        try:
            if context:
                try:
                    await context.close()
                except Exception:
                    pass
        except Exception:
            pass
        
        try:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
        except Exception:
            pass
        
        try:
            if playwright:
                try:
                    await playwright.stop()
                except Exception:
                    pass
        except Exception:
            pass
        
        logger.debug("Browser closed")
    
    async def force_close(self):
        """Force close browser without waiting - for interrupt handling"""
        self.page = None
        self.context = None
        
        try:
            if self.browser:
                await asyncio.wait_for(self.browser.close(), timeout=2.0)
        except (Exception, asyncio.TimeoutError):
            pass
        
        self.browser = None
        
        try:
            if self.playwright:
                await asyncio.wait_for(self.playwright.stop(), timeout=2.0)
        except (Exception, asyncio.TimeoutError):
            pass
        
        self.playwright = None
    
    async def __aenter__(self):
        await self.launch()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
