"""
ScriptX Web Dashboard
Real-time web interface for XSS scanning
"""

import asyncio
import json
import os
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Add parent directory to path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import Config
from core.scanner import Scanner


app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
app.config['SECRET_KEY'] = 'scriptx-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state
current_scan = None
scan_results = []
scan_status = {
    'running': False,
    'target': None,
    'progress': 0,
    'phase': 'idle'
}


@app.route('/')
def index():
    """Render dashboard"""
    return render_template('index.html')


@app.route('/api/status')
def get_status():
    """Get current scan status"""
    return jsonify(scan_status)


@app.route('/api/results')
def get_results():
    """Get all scan results"""
    return jsonify(scan_results)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    global scan_status
    
    if scan_status['running']:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    data = request.json
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan_async, args=(target_url, data))
    thread.start()
    
    return jsonify({'status': 'started', 'target': target_url})


def run_scan_async(target_url, options):
    """Run scan in background"""
    global scan_status, scan_results
    
    scan_status = {
        'running': True,
        'target': target_url,
        'progress': 0,
        'phase': 'initializing'
    }
    
    socketio.emit('scan_status', scan_status)
    
    # Create config from options
    from core.config import Config, BrowserType, ScanMode
    
    config = Config(
        target_url=target_url,
        browser_type=BrowserType.CHROME,
        headless=True,
        crawl_enabled=options.get('crawl', True),
        max_depth=options.get('depth', 2),
        scan_mode=ScanMode(options.get('mode', 'all')),
        waf_bypass=options.get('waf_bypass', True),
        output_dir='./output',
        screenshots=True
    )
    
    # Create scanner with callbacks
    scanner = Scanner(config)
    
    async def on_vuln_found(vuln_type, vuln):
        result = {
            'type': vuln_type,
            'url': getattr(vuln, 'url', 'N/A'),
            'param': getattr(vuln, 'param', 'N/A'),
            'payload': getattr(vuln, 'payload', 'N/A'),
            'severity': getattr(vuln, 'severity', 'high'),
            'timestamp': datetime.now().isoformat()
        }
        scan_results.append(result)
        socketio.emit('vuln_found', result)
    
    async def on_progress(phase, current, total):
        global scan_status
        scan_status['phase'] = phase
        scan_status['progress'] = int((current / total) * 100) if total > 0 else 0
        socketio.emit('scan_status', scan_status)
    
    scanner.on_vuln_found = on_vuln_found
    scanner.on_progress = on_progress
    
    # Run scan
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        scan_status['phase'] = 'crawling'
        socketio.emit('scan_status', scan_status)
        
        result = loop.run_until_complete(scanner.scan(target_url))
        
        scan_status['running'] = False
        scan_status['phase'] = 'complete'
        scan_status['progress'] = 100
        
        socketio.emit('scan_complete', {
            'target': target_url,
            'total_vulns': result.xss_result.total if result.xss_result else 0
        })
        
    except Exception as e:
        scan_status['running'] = False
        scan_status['phase'] = 'error'
        socketio.emit('scan_error', {'error': str(e)})
    
    finally:
        loop.close()


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('scan_status', scan_status)
    emit('results_update', scan_results)


def run_dashboard(config: Config, port: int = 8888):
    """Run the dashboard server"""
    print(f"\n🌐 ScriptX Dashboard starting on http://localhost:{port}")
    print("Press Ctrl+C to stop\n")
    
    socketio.run(app, host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    run_dashboard(Config(), 8888)
