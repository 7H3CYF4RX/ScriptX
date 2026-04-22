"""
ScriptX Reporter
Multi-format report generation
"""

import json
import os
from typing import Dict, List
from datetime import datetime


class Reporter:
    """Generate reports in various formats"""
    
    def __init__(self, config):
        self.config = config
        
    def save_json(self, data: Dict, path: str):
        """Save report as JSON"""
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
    
    def save_html(self, data: Dict, path: str):
        """Save report as HTML"""
        html = self._generate_html(data)
        
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_html(self, data: Dict) -> str:
        """Generate HTML report"""
        
        vulnerabilities = data.get('xss', {}).get('vulnerabilities', {})
        reflected = vulnerabilities.get('reflected', [])
        stored = vulnerabilities.get('stored', [])
        dom = vulnerabilities.get('dom', [])
        
        total = len(reflected) + len(stored) + len(dom)
        
        vuln_rows = ""
        
        for vuln in reflected:
            vuln_rows += self._vuln_row(vuln, 'Reflected')
        
        for vuln in stored:
            vuln_rows += self._vuln_row(vuln, 'Stored')
        
        for vuln in dom:
            vuln_rows += self._vuln_row(vuln, 'DOM')
        
        if not vuln_rows:
            vuln_rows = '<tr><td colspan="5" style="text-align: center; color: #10b981;">No vulnerabilities found</td></tr>'
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScriptX Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #1e3a5f 0%, #2d1b4e 100%);
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: #a0a0a0;
            font-size: 1rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        
        .stat-card .number {{
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .stat-card .label {{
            color: #a0a0a0;
            margin-top: 5px;
        }}
        
        .stat-card.critical .number {{
            background: linear-gradient(135deg, #ef4444, #dc2626);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .section {{
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        
        .section h2 {{
            color: #00d4ff;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        th {{
            background: rgba(0, 0, 0, 0.3);
            color: #00d4ff;
        }}
        
        tr:hover {{
            background: rgba(255, 255, 255, 0.05);
        }}
        
        .severity {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
        }}
        
        .severity.critical {{
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }}
        
        .severity.high {{
            background: rgba(249, 115, 22, 0.2);
            color: #f97316;
        }}
        
        .severity.medium {{
            background: rgba(234, 179, 8, 0.2);
            color: #eab308;
        }}
        
        .type-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
        }}
        
        .type-badge.reflected {{
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
        }}
        
        .type-badge.stored {{
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }}
        
        .type-badge.dom {{
            background: rgba(168, 85, 247, 0.2);
            color: #a855f7;
        }}
        
        .payload {{
            font-family: 'Courier New', monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            word-break: break-all;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            display: block;
        }}
        
        .url {{
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ScriptX Report</h1>
            <p class="subtitle">XSS Vulnerability Scan Results</p>
            <p class="subtitle">Target: {data.get('target', 'Unknown')} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card {'critical' if total > 0 else ''}">
                <div class="number">{total}</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(reflected)}</div>
                <div class="label">Reflected XSS</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(stored)}</div>
                <div class="label">Stored XSS</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(dom)}</div>
                <div class="label">DOM XSS</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Vulnerability Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Payload</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📊 Scan Statistics</h2>
            <table>
                <tr><td>Pages Crawled</td><td>{data.get('crawl', {}).get('pages_crawled', 0)}</td></tr>
                <tr><td>Forms Found</td><td>{data.get('crawl', {}).get('forms_found', 0)}</td></tr>
                <tr><td>Parameters Tested</td><td>{data.get('crawl', {}).get('total_params', 0)}</td></tr>
                <tr><td>Scan Duration</td><td>{data.get('scan_time', 0):.2f} seconds</td></tr>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by ScriptX v1.0.0 | Advanced XSS Detection Tool</p>
        </div>
    </div>
</body>
</html>'''
        
        return html
    
    def _vuln_row(self, vuln: Dict, vuln_type: str) -> str:
        """Generate table row for vulnerability"""
        url = vuln.get('url', vuln.get('injection_url', 'N/A'))
        param = vuln.get('param', vuln.get('injection_point', 'N/A'))
        payload = vuln.get('payload', 'N/A')[:60] + ('...' if len(vuln.get('payload', '')) > 60 else '')
        severity = vuln.get('severity', 'high')
        
        type_class = vuln_type.lower()
        
        return f'''<tr>
            <td><span class="type-badge {type_class}">{vuln_type}</span></td>
            <td class="url" title="{url}">{url[:50]}{'...' if len(url) > 50 else ''}</td>
            <td>{param}</td>
            <td><code class="payload">{self._escape_html(payload)}</code></td>
            <td><span class="severity {severity}">{severity.upper()}</span></td>
        </tr>'''
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters"""
        return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))
