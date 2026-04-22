#!/usr/bin/env python3
"""
ScriptX - Advanced XSS Detection Tool with Browser Control

A comprehensive, Python-based XSS vulnerability scanner that leverages
real browser engines to accurately detect XSS vulnerabilities.

Author: ScriptX Team
Version: 1.0.0
"""

import asyncio
import sys
import os

import click
from rich.console import Console

from core.config import Config, BrowserType, ScanMode, CrawlScope
from core.scanner import Scanner
from utils.logger import logger


console = Console()


def validate_url(ctx, param, value):
    """Validate URL format"""
    if value and not value.startswith(('http://', 'https://')):
        value = 'https://' + value
    return value


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
# ═══════════════════ TARGET OPTIONS ═══════════════════
@click.option('-u', '--url', 'target_url', callback=validate_url,
              help='Target URL to scan')
@click.option('-l', '--list', 'url_list', type=click.Path(exists=True),
              help='File with URLs (one per line)')
# ═══════════════════ BROWSER OPTIONS ═══════════════════
@click.option('-b', '--browser', 'browser_type',
              type=click.Choice(['firefox', 'chrome', 'webkit'], case_sensitive=False),
              default='chrome', show_default=True, help='Browser engine')
@click.option('--headless/--headed', default=True,
              help='Headless or visible browser')
@click.option('--timeout', default=30000, type=int, show_default=True,
              help='Page timeout (ms)')
@click.option('--proxy', help='Proxy URL (http://host:port)')
@click.option('--cookies', help='Cookies (JSON file or string)')
@click.option('--user-agent', help='Custom User-Agent')
# ═══════════════════ CRAWL OPTIONS ═══════════════════
@click.option('--crawl/--no-crawl', default=True,
              help='Enable/disable crawling')
@click.option('--depth', '-d', default=3, type=int, show_default=True,
              help='Max crawl depth')
@click.option('-mu', '--max-urls', 'max_urls', default=0, type=int, show_default=True,
              help='Max URLs to crawl (0=unlimited)')
@click.option('--scope', '-s', type=click.Choice(['domain', 'subdomain', 'all']),
              default='domain', show_default=True, help='Crawl scope')
# ═══════════════════ SCAN OPTIONS ═══════════════════
@click.option('--mode', '-m', type=click.Choice(['all', 'reflected', 'stored', 'dom']),
              default='all', show_default=True, help='XSS scan mode')
@click.option('--payloads', '-p', type=click.Path(exists=True),
              help='Custom payloads file')
@click.option('--waf-bypass/--no-waf-bypass', default=True,
              help='Enable WAF bypass techniques')
@click.option('--delay', default=100, type=int, show_default=True,
              help='Request delay (ms)')
# ═══════════════════ SMART MODE & THROTTLING ═══════════════════
@click.option('--smart', is_flag=True,
              help='Smart mode: start simple, escalate if blocked')
@click.option('--fingerprint/--no-fingerprint', default=True,
              help='Auto-detect WAF and use targeted payloads')
@click.option('--random-delay', is_flag=True,
              help='Random delay (500-3000ms) between requests')
@click.option('--throttle', type=int, default=0, show_default=True,
              help='Fixed throttle delay (ms), 0=disabled')
# ═══════════════════ STEALTH & CAPTCHA OPTIONS ═══════════════════
@click.option('--stealth', is_flag=True,
              help='Enable stealth mode (anti-detection)')
@click.option('--interactive', '-i', is_flag=True,
              help='Interactive mode (pause for CAPTCHA)')
# ═══════════════════ OUTPUT OPTIONS ═══════════════════
@click.option('-o', '--output', 'output_format',
              type=click.Choice(['json', 'html', 'all']),
              default='json', show_default=True, help='Report format')
@click.option('--output-dir', default='./output', show_default=True,
              help='Output directory')
@click.option('--screenshots/--no-screenshots', default=True,
              help='Capture vuln screenshots')
@click.option('-v', '--verbose', is_flag=True,
              help='Verbose output')
# ═══════════════════ DASHBOARD OPTIONS ═══════════════════
@click.option('--dashboard', is_flag=True,
              help='Start web dashboard')
@click.option('--port', default=8888, type=int, show_default=True,
              help='Dashboard port')
@click.version_option(version='1.0.0', prog_name='ScriptX')
def main(target_url, url_list, browser_type, headless, timeout, proxy, cookies, 
         user_agent, crawl, depth, max_urls, scope, mode, payloads, waf_bypass, 
         delay, smart, fingerprint, random_delay, throttle, stealth, interactive, 
         output_format, output_dir, screenshots, verbose, dashboard, port):
    """
    ╔═══════════════════════════════════════════════════════════╗
    ║  ScriptX - Advanced XSS Detection with Browser Control   ║
    ╚═══════════════════════════════════════════════════════════╝
    
    \b
    USAGE EXAMPLES:
    ───────────────────────────────────────────────────
      Basic scan:          scriptx -u https://target.com
      Smart mode:          scriptx -u https://target.com --smart
      WAF bypass:          scriptx -u https://target.com --smart --stealth
      Throttled:           scriptx -u https://target.com --throttle 2000
      Random delay:        scriptx -u https://target.com --random-delay
      Limit crawl:         scriptx -u https://target.com -mu 50 -d 2
      With proxy:          scriptx -u https://target.com --proxy http://127.0.0.1:8080
      Dashboard mode:      scriptx -u https://target.com --dashboard
    """
    
    # Validate input
    if not target_url and not url_list:
        console.print("[red]Error:[/red] Please provide a target URL (-u) or URL list (-l)")
        sys.exit(1)
    
    # Build configuration
    config = Config(
        target_url=target_url,
        target_list=url_list,
        browser_type=BrowserType(browser_type.lower() if browser_type != 'chrome' else 'chromium'),
        headless=headless if not interactive else False,  # Force headed mode for interactive
        timeout=timeout,
        user_agent=user_agent,
        proxy=proxy,
        crawl_enabled=crawl,
        max_depth=depth,
        max_urls=max_urls,
        crawl_scope=CrawlScope(scope),
        scan_mode=ScanMode(mode),
        custom_payloads=payloads,
        waf_bypass=waf_bypass,
        request_delay=throttle if throttle > 0 else delay,  # Use throttle if set
        smart_mode=smart,
        waf_fingerprint=fingerprint,
        random_delay=random_delay,
        min_delay=500,
        max_delay=3000,
        stealth_mode=stealth,
        interactive=interactive,
        cookies=cookies,
        output_format=output_format,
        output_dir=output_dir,
        screenshots=screenshots,
        verbose=verbose,
        dashboard_enabled=dashboard,
        dashboard_port=port,
    )
    
    # Update logger verbosity
    logger.verbose = verbose
    
    # Start dashboard if requested
    if dashboard:
        from dashboard.app import run_dashboard
        run_dashboard(config, port)
        return
    
    # Run scanner with proper interrupt handling
    run_with_interrupt_handling(config, target_url, url_list)


async def run_scan(config: Config, target_url: str = None, url_list: str = None):
    """Run the XSS scan with graceful shutdown support"""
    scanner = Scanner(config)
    
    try:
        if url_list:
            # Scan multiple URLs
            with open(url_list, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if not urls:
                console.print("[red]Error:[/red] No valid URLs found in file")
                return
            
            results = await scanner.scan_urls(urls)
            
            total_vulns = sum(r.xss_result.total if r.xss_result else 0 for r in results)
            console.print(f"\n[bold]Total: {len(results)} targets scanned, {total_vulns} vulnerabilities found[/bold]")
            
        else:
            # Scan single URL
            result = await scanner.scan(target_url)
            
            if result.xss_result and result.xss_result.total > 0:
                console.print(f"\n[bold red]⚠️  {result.xss_result.total} XSS vulnerabilities found![/bold red]")
            else:
                console.print("\n[bold green]✓ No XSS vulnerabilities found[/bold green]")
                
    except asyncio.CancelledError:
        console.print("\n[yellow]Scan cancelled[/yellow]")
    finally:
        # Ensure browser is closed on exit
        await scanner.cleanup()


def run_with_interrupt_handling(config: Config, target_url: str = None, url_list: str = None):
    """Run scan with proper keyboard interrupt handling"""
    import os
    import sys
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    main_task = loop.create_task(run_scan(config, target_url, url_list))
    
    try:
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted - cleaning up...[/yellow]")
        
        # Cancel the main task
        main_task.cancel()
        
        # Suppress stderr to hide Node.js EPIPE errors
        stderr_fd = sys.stderr.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, stderr_fd)
        
        # Give it a moment to cleanup
        try:
            loop.run_until_complete(asyncio.wait_for(main_task, timeout=3.0))
        except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
            pass
        
        # Restore stderr for our message
        sys.stderr = sys.__stderr__
        console.print("[green]✓ Cleanup complete[/green]")
    except Exception:
        pass
    finally:
        # Close the loop
        try:
            # Cancel all pending tasks
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()
        except Exception:
            pass


if __name__ == '__main__':
    import signal
    import warnings
    import os
    
    # Suppress asyncio warnings on exit
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    
    # Ignore SIGPIPE to prevent broken pipe errors
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (AttributeError, ValueError):
        pass  # SIGPIPE doesn't exist on Windows
    
    try:
        main()
    except KeyboardInterrupt:
        # Suppress stderr to hide Node.js errors
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 2)  # Redirect stderr to /dev/null
        except Exception:
            pass
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        os._exit(0)  # Force exit without cleanup
    except SystemExit:
        pass
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
