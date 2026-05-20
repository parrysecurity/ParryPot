import aiohttp
import json
import os
from datetime import datetime
from loguru import logger

class TeamsAlert:
    """Send alerts to Microsoft Teams webhook"""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.getenv('TEAMS_WEBHOOK_URL')
        self.enabled = bool(self.webhook_url)
        if self.enabled:
            logger.info("Teams alerts enabled")
    
    async def send(self, alert: dict):
        """Send alert to Teams"""
        if not self.enabled:
            return
        
        # Determine color
        colors = {'CRITICAL': 'FF0000', 'HIGH': 'FF6600', 'MEDIUM': 'FFCC00', 'LOW': '00AA00'}
        color = colors.get(alert.get('severity', 'MEDIUM'), '999999')
        
        message = {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            'themeColor': color,
            'title': alert.get('title', 'Honeypot Alert'),
            'text': f"**Severity:** {alert.get('severity', 'UNKNOWN')}\n"
                    f"**Source IP:** {alert.get('source_ip', 'unknown')}\n"
                    f"**Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                    f"**Details:** {alert.get('details', 'No details')}"
        }
        
        if alert.get('username'):
            message['text'] += f"\n**Username:** {alert['username']}"
        
        if alert.get('command'):
            message['text'] += f"\n**Command:** `{alert['command'][:200]}`"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=message) as resp:
                    if resp.status != 200:
                        logger.error(f"Teams alert failed: {resp.status}")
        except Exception as e:
            logger.error(f"Teams alert error: {e}")
