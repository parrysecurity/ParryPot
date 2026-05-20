import asyncio
import sys
import os
import signal
from pathlib import Path
from datetime import datetime
import socket

sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger
from dotenv import load_dotenv

load_dotenv()

# Import all components
from honeypot.engine.detector import DetectionEngine
from honeypot.engine.command_parser import CommandParser
from honeypot.engine.mitre_mapper import MITREMapper
from honeypot.listeners.ssh import SSHListener
from honeypot.listeners.http import HTTPListener
from honeypot.listeners.smb import SMBListener
from honeypot.listeners.ftp import FTPListener
from honeypot.listeners.telnet import TelnetListener
from honeypot.listeners.smtp import SMTPListener
from honeypot.listeners.dns import DNSListener
from honeypot.forensics.keystroke_logger import KeystrokeLogger
from honeypot.forensics.packet_capture import PacketCapture
from honeypot.forensics.malware_sandbox import MalwareSandbox
from honeypot.alerting.slack_alert import SlackAlert
from honeypot.alerting.teams_alert import TeamsAlert
from honeypot.alerting.email_alert import EmailAlert

# Get server IP
def get_server_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "localhost"

SERVER_IP = get_server_ip()

class HoneypotOrchestrator:
    def __init__(self):
        self.listeners = []
        self.running = False
        
        # Initialize engines
        self.detection_engine = DetectionEngine()
        self.command_parser = CommandParser()
        self.mitre_mapper = MITREMapper()
        self.keystroke_logger = KeystrokeLogger()
        self.packet_capture = PacketCapture()
        self.malware_sandbox = MalwareSandbox()
        
        # Initialize alerting
        self.alert_channels = []
        if os.getenv('SLACK_WEBHOOK_URL'):
            self.alert_channels.append(SlackAlert())
        if os.getenv('TEAMS_WEBHOOK_URL'):
            self.alert_channels.append(TeamsAlert())
        self.alert_channels.append(EmailAlert())
        
        # Initialize all listeners with fallback ports
        self.listeners = [
            SSHListener(port=22, detection_engine=self.detection_engine, 
                       keystroke_logger=self.keystroke_logger, alert_callbacks=self.alert_channels),
            HTTPListener(port=80, detection_engine=self.detection_engine, alert_callbacks=self.alert_channels),
            HTTPListener(port=443, detection_engine=self.detection_engine, alert_callbacks=self.alert_channels),
            SMBListener(port=445, detection_engine=self.detection_engine, alert_callbacks=self.alert_channels),
            FTPListener(port=21, detection_engine=self.detection_engine, alert_callbacks=self.alert_channels),
            TelnetListener(port=23, detection_engine=self.detection_engine, 
                          keystroke_logger=self.keystroke_logger, alert_callbacks=self.alert_channels),
            SMTPListener(port=25, detection_engine=self.detection_engine, alert_callbacks=self.alert_channels),
            DNSListener(port=53, detection_engine=self.detection_engine, alert_callbacks=self.alert_channels),
        ]
        
        logger.info("=" * 60)
        logger.info("All-In-One Honeypot Platform v1.0.0")
        logger.info(f"Server IP: {SERVER_IP}")
        logger.info("=" * 60)
    
    async def start(self):
        """Start all honeypot components"""
        logger.info("Starting protocol listeners...")
        
        # Start all listeners
        for listener in self.listeners:
            try:
                await listener.start()
                if listener.is_running:
                    logger.info(f"  ✓ {listener.__class__.__name__}:{listener.port}")
                else:
                    logger.warning(f"  ⚠ {listener.__class__.__name__} not running")
            except Exception as e:
                logger.error(f"  ✗ Failed to start {listener.__class__.__name__}: {e}")
        
        self.running = True
        
        # Start dashboard server
        asyncio.create_task(self._run_dashboard())
        
        logger.success("✅ All-In-One Honeypot is RUNNING!")
        logger.info("=" * 60)
        logger.info(f"📊 DASHBOARD: http://{SERVER_IP}:5000")
        logger.info(f"🌐 External Access: http://{SERVER_IP}:5000")
        logger.info("=" * 60)
        logger.info("Active Honeypot Ports:")
        for listener in self.listeners:
            if listener.is_running:
                logger.info(f"  🔓 {listener.__class__.__name__}:{listener.port}")
        logger.info("=" * 60)
        logger.info("Press Ctrl+C to stop")
        
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.shutdown()
    
    async def _run_dashboard(self):
        """Run Flask dashboard on all interfaces"""
        try:
            from flask import Flask, jsonify, render_template_string
            from flask_cors import CORS
            import json
            
            app = Flask(__name__)
            CORS(app)
            
            # Simple dashboard HTML
            DASHBOARD_HTML = '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Honeypot Dashboard</title>
                <meta charset="UTF-8">
                <style>
                    body { font-family: monospace; background: #0a0e27; color: #0f0; padding: 20px; }
                    h1 { color: #0f0; border-bottom: 1px solid #0f0; }
                    .port-list { background: #1a1a3e; padding: 15px; border-radius: 5px; margin: 10px 0; }
                    .port { color: #0f0; margin: 5px 0; }
                    .ip { color: #ff0; font-size: 18px; }
                    .footer { margin-top: 30px; color: #666; }
                </style>
            </head>
            <body>
                <h1>🔒 All-In-One Honeypot</h1>
                <p>Server IP: <span class="ip">{{ server_ip }}</span></p>
                <div class="port-list">
                    <h3>Active Honeypot Services:</h3>
                    <div class="port">📡 SSH:22 (and fallback ports)</div>
                    <div class="port">🌐 HTTP:80,443</div>
                    <div class="port">📁 SMB:445</div>
                    <div class="port">📂 FTP:21</div>
                    <div class="port">💻 Telnet:23</div>
                    <div class="port">📧 SMTP:25</div>
                    <div class="port">🔍 DNS:53</div>
                </div>
                <div class="port-list">
                    <h3>Real-time Events:</h3>
                    <div id="events">Loading...</div>
                </div>
                <div class="footer">
                    Security Research Environment - All access is logged
                </div>
                <script>
                    setInterval(() => {
                        fetch('/api/stats')
                            .then(r => r.json())
                            .then(data => {
                                document.getElementById('events').innerHTML = 
                                    'Events: ' + data.total_events + ' | Alerts: ' + data.total_alerts;
                            });
                    }, 2000);
                </script>
            </body>
            </html>
            '''
            
            @app.route('/')
            def index():
                return render_template_string(DASHBOARD_HTML, server_ip=SERVER_IP)
            
            @app.route('/health')
            def health():
                return jsonify({'status': 'healthy', 'server_ip': SERVER_IP})
            
            @app.route('/api/stats')
            def stats():
                return jsonify({'total_events': 0, 'total_alerts': 0, 'server_ip': SERVER_IP})
            
            # Run on all interfaces
            from werkzeug.serving import run_simple
            run_simple('0.0.0.0', 5000, app, use_reloader=False, use_debugger=False)
            
        except Exception as e:
            logger.error(f"Dashboard error: {e}")
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down honeypot...")
        for listener in self.listeners:
            try:
                await listener.stop()
            except:
                pass
        self.running = False
        logger.success("Honeypot shutdown complete")

async def main():
    orchestrator = HoneypotOrchestrator()
    await orchestrator.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
