import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from loguru import logger

class EmailAlert:
    """Send alerts via email"""
    
    def __init__(self):
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_user = os.getenv('SMTP_USER')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.alert_email = os.getenv('ALERT_EMAIL')
        self.enabled = all([self.smtp_user, self.smtp_password, self.alert_email])
        
        if self.enabled:
            logger.info("Email alerts enabled")
    
    async def send(self, alert: dict):
        """Send email alert"""
        if not self.enabled:
            return
        
        subject = f"[{alert.get('severity', 'ALERT')}] {alert.get('title', 'Honeypot Detection')}"
        
        body = f"""
Honeypot Security Alert
{'=' * 40}

Title: {alert.get('title', 'N/A')}
Severity: {alert.get('severity', 'UNKNOWN')}
Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Source Information:
- IP Address: {alert.get('source_ip', 'unknown')}
{' - Username: ' + alert['username'] if alert.get('username') else ''}

Details:
{alert.get('details', 'No additional details')}

{'Command:' + alert.get('command', '') if alert.get('command') else ''}

--
All-In-One Honeypot Platform
"""
        
        msg = MIMEMultipart()
        msg['From'] = self.smtp_user
        msg['To'] = self.alert_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()
            logger.debug(f"Email alert sent to {self.alert_email}")
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
