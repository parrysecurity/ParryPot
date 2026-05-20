import asyncio
import json
import uuid
from datetime import datetime
from aiohttp import web
from loguru import logger

class HTTPListener:
    """HTTP/HTTPS web honeypot"""
    
    def __init__(self, port: int = 80, detection_engine=None, alert_callbacks=None):
        self.port = port
        self.detection_engine = detection_engine
        self.alert_callbacks = alert_callbacks or []
        self.app = None
        self.runner = None
        self.is_running = False
        self.request_history = []
        
        logger.info(f"HTTP Listener initialized on port {port}")
    
    async def start(self):
        """Start HTTP server"""
        try:
            self.app = web.Application()
            self.app.router.add_route('*', '/{path:.*}', self.handle_request)
            
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            site = web.TCPSite(self.runner, '0.0.0.0', self.port)
            await site.start()
            
            self.is_running = True
            logger.success(f"✅ HTTP honeypot listening on port {self.port}")
        except OSError as e:
            if "address already in use" in str(e):
                logger.warning(f"Port {self.port} is in use, trying alternative port {self.port + 1000}")
                self.port = self.port + 1000
                await self.start()
            else:
                logger.error(f"Failed to start HTTP listener: {e}")
        except Exception as e:
            logger.error(f"Failed to start HTTP listener: {e}")
    
    async def stop(self):
        """Stop HTTP server"""
        if self.runner:
            await self.runner.cleanup()
        self.is_running = False
        logger.info(f"HTTP listener on port {self.port} stopped")
    
    async def handle_request(self, request):
        """Handle all HTTP requests"""
        client_ip = request.remote
        path = request.path
        method = request.method
        
        # Get request body
        body = None
        try:
            if request.can_read_body:
                body = await request.text()
        except:
            pass
        
        # Create event
        event = {
            'event_id': str(uuid.uuid4()),
            'protocol': 'HTTP',
            'src_ip': client_ip,
            'dst_port': self.port,
            'method': method,
            'path': path,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Log request
        logger.info(f"[HTTP] {method} {path} from {client_ip}")
        
        # Store in history
        self.request_history.append(event)
        
        # Analyze with detection engine
        if self.detection_engine:
            detection = await self.detection_engine.analyze(event)
            
            if detection.get('is_malicious') and detection.get('severity') in ['CRITICAL', 'HIGH']:
                for alert in self.alert_callbacks:
                    await alert.send({
                        'title': f"🌐 Web Attack: {detection.get('attack_types', ['unknown'])[0]}",
                        'severity': detection.get('severity', 'MEDIUM'),
                        'source_ip': client_ip,
                        'path': path,
                        'details': f"Attack type: {detection.get('attack_types')}"
                    })
        
        # Return honeypot response
        html = """<!DOCTYPE html>
<html>
<head><title>Honeypot - Access Logged</title></head>
<body>
<h1>Access Logged</h1>
<p>This is a security honeypot. Your activity has been recorded.</p>
<hr>
<small>Security Research Environment</small>
</body>
</html>"""
        return web.Response(text=html, content_type='text/html')
    
    def get_stats(self):
        return {'total_requests': len(self.request_history)}
