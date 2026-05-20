import aiohttp
import json
from datetime import datetime
from loguru import logger

class SlackAlert:
    """Send alerts to Slack webhook"""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.getenv('SLACK_WEBHOOK_URL')
        self.enabled = bool(self.webhook_url)
        if self.enabled:
            logger.info("Slack alerts enabled")
        else:
            logger.warning("Slack alerts disabled (no webhook URL)")
    
    async def send(self, alert: dict):
        """Send alert to Slack"""
        if not self.enabled:
            return
        
        # Determine color based on severity
        colors = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF6600',
            'MEDIUM': '#FFCC00',
            'LOW': '#00AA00'
        }
        color = colors.get(alert.get('severity', 'MEDIUM'), '#999999')
        
        # Build message
        message = {
            'attachments': [{
                'color': color,
                'title': alert.get('title', 'Honeypot Security Alert'),
                'fields': [
                    {'title': 'Severity', 'value': alert.get('severity', 'UNKNOWN'), 'short': True},
                    {'title': 'Source IP', 'value': alert.get('source_ip', 'unknown'), 'short': True},
                    {'title': 'Time', 'value': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), 'short': True},
                    {'title': 'Details', 'value': alert.get('details', 'No details provided'), 'short': False}
                ],
                'footer': 'All-In-One Honeypot',
                'ts': int(datetime.utcnow().timestamp())
            }]
        }
        
        # Add username if present
        if alert.get('username'):
            message['attachments'][0]['fields'].append(
                {'title': 'Username', 'value': alert['username'], 'short': True}
            )
        
        # Add command if present
        if alert.get('command'):
            message['attachments'][0]['fields'].append(
                {'title': 'Command', 'value': f'```{alert["command"]}```', 'short': False}
            )
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=message) as resp:
                    if resp.status != 200:
                        logger.error(f"Slack alert failed: {resp.status}")
        except Exception as e:
            logger.error(f"Slack alert error: {e}")
    
    def set_webhook(self, url: str):
        """Set webhook URL dynamically"""
        self.webhook_url = url
        self.enabled = bool(url)
