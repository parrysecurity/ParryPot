import asyncio
import asyncssh
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from loguru import logger

class SSHListener:
    """High-interaction SSH honeypot with full session recording"""
    
    def __init__(self, port: int = 22, detection_engine=None, packet_capture=None, 
                 keystroke_logger=None, alert_callbacks: List = None):
        self.port = port
        self.detection_engine = detection_engine
        self.packet_capture = packet_capture
        self.keystroke_logger = keystroke_logger
        self.alert_callbacks = alert_callbacks or []
        self.server = None
        self.is_running = False
        self.active_sessions = {}
        
        # Fake credentials that trigger instant alerts
        self.high_value_creds = {
            'admin': 'admin123',
            'root': 'toor',
            'administrator': 'password',
            'oracle': 'oracle',
            'postgres': 'postgres',
            'ubuntu': 'ubuntu',
        }
        
        # Fake file system content
        self.fake_files = {
            '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n',
            '/etc/shadow': 'root:$6$randomsalt$encryptedhash:19000:0:99999:7:::\n',
            '/home/ubuntu/.ssh/id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...fake-key...\n-----END RSA PRIVATE KEY-----\n',
            '/var/backups/credentials.txt': 'admin:password123\nroot:toor\ndb_admin:SecurePass123\n',
        }
        
        logger.info(f"SSH Listener initialized on port {port}")
    
    async def start(self):
        """Start SSH server"""
        try:
            # Create SSH server without banner parameter (compatibility fix)
            self.server = await asyncssh.create_server(
                lambda: SSHServerHandler(self),
                '0.0.0.0',
                self.port,
                server_host_keys=None  # Will generate ephemeral key
            )
            self.is_running = True
            logger.success(f"✅ SSH honeypot listening on port {self.port}")
        except Exception as e:
            logger.error(f"Failed to start SSH listener on port {self.port}: {e}")
            # Try alternate port if 22 is taken
            if self.port == 22:
                self.port = 2222
                try:
                    self.server = await asyncssh.create_server(
                        lambda: SSHServerHandler(self),
                        '0.0.0.0',
                        self.port,
                        server_host_keys=None
                    )
                    self.is_running = True
                    logger.success(f"✅ SSH honeypot listening on alternate port {self.port}")
                except Exception as e2:
                    logger.error(f"Failed to start SSH on alternate port: {e2}")
    
    async def stop(self):
        """Stop SSH server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.is_running = False
        logger.info(f"SSH listener on port {self.port} stopped")
    
    async def on_authentication(self, username: str, password: str, client_ip: str, client_port: int) -> Dict[str, Any]:
        """Handle authentication attempt"""
        event = {
            'event_id': str(uuid.uuid4()),
            'protocol': 'SSH',
            'src_ip': client_ip,
            'src_port': client_port,
            'dst_port': self.port,
            'username': username,
            'password': password,
            'timestamp': datetime.utcnow().isoformat(),
            'attack_type': 'credential_attempt'
        }
        
        # Check for high-value credentials
        if username in self.high_value_creds and password == self.high_value_creds[username]:
            event['attack_type'] = 'high_value_compromise'
            event['severity'] = 'CRITICAL'
            
            for alert in self.alert_callbacks:
                await alert.send({
                    'title': '🔥 CRITICAL: High-value credential used in SSH honeypot!',
                    'severity': 'CRITICAL',
                    'source_ip': client_ip,
                    'username': username,
                    'details': f'Attacker used {username}:{password} on SSH'
                })
        
        # Run detection engine
        if self.detection_engine:
            detection_result = await self.detection_engine.analyze(event)
            event['detection'] = detection_result
        
        # Always accept authentication (honeypot)
        event['authenticated'] = True
        
        return event

class SSHServerHandler(asyncssh.SSHServer):
    """Custom SSH server with command logging and deception"""
    
    def __init__(self, listener: SSHListener):
        self.listener = listener
        self.username = None
        self.client_ip = None
        self.client_port = None
        self.command_history = []
        self.session_start = None
        self.session_id = None
        
    def connection_made(self, conn):
        peername = conn.get_extra_info('peername')
        if peername:
            self.client_ip = peername[0]
            self.client_port = peername[1]
        self.session_start = datetime.utcnow()
        self.session_id = str(uuid.uuid4())[:8]
        
        # Start keystroke logging
        if self.listener.keystroke_logger:
            self.listener.keystroke_logger.start_session(self.client_ip, self.session_id)
        
        logger.info(f"[SSH] New connection from {self.client_ip}:{self.client_port} (session: {self.session_id})")
    
    def connection_lost(self, exc):
        """Handle connection lost"""
        if self.listener.keystroke_logger:
            self.listener.keystroke_logger.end_session(self.client_ip)
    
    def begin_auth(self, username):
        self.username = username
        return True
    
    def password_auth_supported(self):
        return True
    
    async def validate_password(self, username, password):
        """Always accept, but log everything"""
        event = await self.listener.on_authentication(username, password, self.client_ip, self.client_port)
        
        # Log the attempt
        logger.info(f"[SSH] Auth attempt - User: {username} | IP: {self.client_ip}")
        
        # Always return True (honeypot)
        return True
    
    def session_requested(self):
        return True
    
    async def shell_requested(self, session):
        """Start interactive shell"""
        session.write(f"\n")
        session.write(f"Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n")
        session.write(f"\n")
        session.write(f"  System information as of {datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')}\n")
        session.write(f"\n")
        session.write(f"  System load:  0.08              Processes:             245\n")
        session.write(f"  Usage of /:   15.2% of 98.33GB   Users logged in:       1\n")
        session.write(f"  Memory usage: 22%               IPv4 address:          {self.client_ip}\n")
        session.write(f"\n")
        session.write(f"Last login: {datetime.utcnow().strftime('%a %b %d %H:%M:%S')} from {self.client_ip}\n")
        session.write(f"{self.username}@ubuntu:~$ ")
        session.set_echo(True)
        self.session = session
        return True
    
    async def exec_command(self, session, command):
        """Execute and log commands"""
        command = command.strip()
        
        # Log command
        logger.info(f"[SSH] Command from {self.client_ip}: {command}")
        
        # Record in history
        self.command_history.append({
            'command': command,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Send to keystroke logger
        if self.listener.keystroke_logger:
            self.listener.keystroke_logger.log_command(self.client_ip, command)
        
        # Analyze command with detection engine
        if self.listener.detection_engine:
            event = {
                'src_ip': self.client_ip,
                'username': self.username,
                'command': command,
                'command_history': self.command_history,
                'protocol': 'SSH'
            }
            detection = await self.listener.detection_engine.analyze(event)
            
            # Generate alert for critical commands
            if detection.get('severity') in ['CRITICAL', 'HIGH']:
                for alert in self.listener.alert_callbacks:
                    await alert.send({
                        'title': f"🚨 SSH Command Alert: {detection.get('attack_types', ['unknown'])[0]}",
                        'severity': detection.get('severity', 'HIGH'),
                        'source_ip': self.client_ip,
                        'username': self.username,
                        'command': command[:200],
                        'details': f"Detection: {detection.get('attack_types')}"
                    })
        
        # Generate fake response based on command
        response = await self._generate_fake_response(command)
        session.write(response)
        
        # Show prompt for next command
        if not command.startswith('exit'):
            session.write(f"\n{self.username}@ubuntu:~$ ")
        
        return 0
    
    async def _generate_fake_response(self, command: str) -> str:
        """Generate realistic fake responses for commands"""
        cmd_lower = command.lower().strip()
        
        # Help command
        if cmd_lower == 'help' or cmd_lower == '?':
            return """Available commands: ls, cd, pwd, cat, echo, whoami, id, ps, netstat, ifconfig, ping, wget, curl, ssh, exit
"""
        
        # Whoami
        if cmd_lower == 'whoami':
            return f"{self.username}\n"
        
        # id
        if cmd_lower == 'id':
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),4(adm),24(cdrom),27(sudo)\n"
        
        # pwd
        if cmd_lower == 'pwd':
            return "/home/" + self.username + "\n"
        
        # ls
        if cmd_lower == 'ls' or cmd_lower.startswith('ls '):
            return "credentials.txt  Documents  .ssh  .bashrc  .profile\n"
        
        # cat
        if cmd_lower.startswith('cat '):
            filename = command[4:].strip()
            if filename in self.listener.fake_files:
                return self.listener.fake_files[filename]
            return f"cat: {filename}: No such file or directory\n"
        
        # echo
        if cmd_lower.startswith('echo '):
            return command[5:] + "\n"
        
        # ps
        if cmd_lower == 'ps' or cmd_lower == 'ps aux':
            return f"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  16872  5480 ?        Ss   Nov14   0:02 /sbin/init\n"
        
        # netstat
        if cmd_lower.startswith('netstat'):
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
"""
        
        # ifconfig
        if cmd_lower == 'ifconfig':
            return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255
"""
        
        # exit
        if cmd_lower == 'exit':
            return "logout\nConnection to ubuntu closed.\n"
        
        # Default response
        return f"bash: {command.split()[0] if command else 'command'}: command not found\n"
    
    def session_closed(self):
        """Session ended"""
        duration = (datetime.utcnow() - self.session_start).total_seconds() if self.session_start else 0
        logger.info(f"[SSH] Session ended - IP: {self.client_ip} | Duration: {duration:.1f}s | Commands: {len(self.command_history)}")
        
        # End keystroke logging
        if self.listener.keystroke_logger:
            self.listener.keystroke_logger.end_session(self.client_ip)
