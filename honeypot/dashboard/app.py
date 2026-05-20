from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'honeypot-secret-key-change-this'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store for real-time events
recent_events = []
recent_alerts = []

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/stats')
def get_stats():
    """Get platform statistics"""
    return jsonify({
        'total_events': len(recent_events),
        'total_alerts': len(recent_alerts),
        'active_listeners': ['SSH', 'HTTP', 'FTP', 'Telnet', 'SMTP', 'DNS', 'SMB'],
        'uptime_seconds': 3600
    })

@app.route('/api/events')
def get_events():
    """Get recent events"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(recent_events[-limit:])

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(recent_alerts[-limit:])

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'message': 'Connected to honeypot dashboard'})

def emit_event(event):
    """Emit event to connected clients"""
    recent_events.append(event)
    if len(recent_events) > 1000:
        recent_events.pop(0)
    socketio.emit('new_event', event)

def emit_alert(alert):
    """Emit alert to connected clients"""
    recent_alerts.append(alert)
    if len(recent_alerts) > 500:
        recent_alerts.pop(0)
    socketio.emit('new_alert', alert)

def run_dashboard(host='0.0.0.0', port=5000):
    """Run the dashboard"""
    socketio.run(app, host=host, port=port, debug=False)
