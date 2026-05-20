import json
import os
from datetime import datetime
from collections import defaultdict
from loguru import logger

class KeystrokeLogger:
    """Log all keystrokes and commands from attacker sessions"""
    
    def __init__(self, log_dir: str = "data/logs/keystrokes"):
        self.log_dir = log_dir
        self.active_sessions = {}
        os.makedirs(log_dir, exist_ok=True)
        logger.info(f"Keystroke Logger initialized (logs: {log_dir})")
    
    def start_session(self, client_ip: str, session_id: str):
        """Start logging a new session"""
        self.active_sessions[session_id] = {
            'client_ip': client_ip,
            'start_time': datetime.utcnow().isoformat(),
            'commands': [],
            'keystrokes': []
        }
        logger.debug(f"Started keystroke session {session_id} for {client_ip}")
    
    def log_keystroke(self, session_id: str, keystroke: str):
        """Log individual keystroke"""
        if session_id in self.active_sessions:
            self.active_sessions[session_id]['keystrokes'].append({
                'char': keystroke,
                'timestamp': datetime.utcnow().isoformat()
            })
    
    def log_command(self, client_ip: str, command: str):
        """Log complete command"""
        # Find session by IP
        for session_id, session in self.active_sessions.items():
            if session['client_ip'] == client_ip:
                session['commands'].append({
                    'command': command,
                    'timestamp': datetime.utcnow().isoformat()
                })
                self._save_session(session_id)
                break
    
    def end_session(self, client_ip: str):
        """End and save session"""
        for session_id, session in self.active_sessions.items():
            if session['client_ip'] == client_ip:
                session['end_time'] = datetime.utcnow().isoformat()
                session['duration_seconds'] = (
                    datetime.fromisoformat(session['end_time']) - 
                    datetime.fromisoformat(session['start_time'])
                ).total_seconds()
                self._save_session(session_id)
                del self.active_sessions[session_id]
                logger.info(f"Saved keystroke session {session_id} - {len(session['commands'])} commands")
                break
    
    def _save_session(self, session_id: str):
        """Save session to disk"""
        if session_id in self.active_sessions:
            filename = f"{self.log_dir}/{session_id}.json"
            with open(filename, 'w') as f:
                json.dump(self.active_sessions[session_id], f, indent=2)
    
    def get_session(self, session_id: str) -> dict:
        """Retrieve a saved session"""
        filename = f"{self.log_dir}/{session_id}.json"
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        return None
    
    def list_sessions(self) -> list:
        """List all sessions"""
        sessions = []
        for f in os.listdir(self.log_dir):
            if f.endswith('.json'):
                with open(f"{self.log_dir}/{f}", 'r') as file:
                    data = json.load(file)
                    sessions.append({
                        'session_id': f.replace('.json', ''),
                        'client_ip': data.get('client_ip'),
                        'start_time': data.get('start_time'),
                        'commands_count': len(data.get('commands', []))
                    })
        return sorted(sessions, key=lambda x: x.get('start_time', ''), reverse=True)
