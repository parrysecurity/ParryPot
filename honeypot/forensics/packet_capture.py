import asyncio
import subprocess
import os
import uuid
from datetime import datetime
from loguru import logger

class PacketCapture:
    """Capture network traffic for forensic analysis"""
    
    def __init__(self, pcap_dir: str = "data/pcaps"):
        self.pcap_dir = pcap_dir
        self.active_captures = {}
        os.makedirs(pcap_dir, exist_ok=True)
        logger.info(f"Packet Capture initialized (storage: {pcap_dir})")
    
    async def start_capture(self, filter_str: str = None, interface: str = "eth0") -> str:
        """Start packet capture for a session"""
        capture_id = str(uuid.uuid4())[:8]
        filename = f"{self.pcap_dir}/capture_{capture_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pcap"
        
        # Build tcpdump command
        cmd = ["tcpdump", "-i", interface, "-w", filename, "-C", "100", "-G", "3600"]
        if filter_str:
            cmd.extend(["-f", filter_str])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self.active_captures[capture_id] = {
                'process': process,
                'filename': filename,
                'start_time': datetime.utcnow().isoformat(),
                'filter': filter_str
            }
            
            logger.info(f"Started packet capture {capture_id} -> {filename}")
            return capture_id
            
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            return None
    
    async def stop_capture(self, capture_id: str) -> str:
        """Stop packet capture and return filename"""
        if capture_id in self.active_captures:
            capture = self.active_captures[capture_id]
            try:
                capture['process'].terminate()
                await capture['process'].wait()
                logger.info(f"Stopped packet capture {capture_id}")
                return capture['filename']
            except Exception as e:
                logger.error(f"Error stopping capture: {e}")
        return None
    
    def list_captures(self) -> list:
        """List all PCAP files"""
        captures = []
        for f in os.listdir(self.pcap_dir):
            if f.endswith('.pcap'):
                filepath = os.path.join(self.pcap_dir, f)
                captures.append({
                    'filename': f,
                    'size_bytes': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
        return sorted(captures, key=lambda x: x['modified'], reverse=True)
    
    def extract_packets(self, pcap_file: str, protocol: str = None) -> list:
        """Extract packet details from PCAP"""
        packets = []
        try:
            cmd = ["tshark", "-r", pcap_file, "-T", "json"]
            if protocol:
                cmd.extend(["-Y", protocol])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.stdout:
                import json
                packets = json.loads(result.stdout)
        except Exception as e:
            logger.error(f"Error extracting packets: {e}")
        return packets
