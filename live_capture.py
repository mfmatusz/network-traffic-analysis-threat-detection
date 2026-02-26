from scapy.all import sniff, wrpcap, get_if_list, conf
import tempfile
import os
from detection_rules import *
from read_sigma import *
from raport_generator import *
import time

class LiveCapture:
    def __init__(self, interface=None, port=None):
        self.interface = interface
        self.port = port
        self.packets = []
        self.temp_pcap = None
        
    @staticmethod
    def list_interfaces():
        """List all available network interfaces"""
        interfaces = get_if_list()
        print("Available interfaces:")
        for iface in interfaces:
            print(f"- {iface}")
        return interfaces
        
    def validate_interface(self):
        """Validate if the specified interface exists"""
        if self.interface:
            available_interfaces = get_if_list()
            if self.interface not in available_interfaces:
                raise ValueError(f"Interface {self.interface} not found. Available interfaces: {', '.join(available_interfaces)}")
        
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        self.packets.append(packet)
        
    def start_capture(self, duration=60):
        """Start capturing packets for specified duration"""
        # Validate interface if specified
        self.validate_interface()
        
        # Build capture filter
        filter_parts = []
        if self.port:
            filter_parts.append(f"port {self.port}")
            
        filter_str = " and ".join(filter_parts) if filter_parts else ""
        
        print(f"Starting capture on {self.interface or 'default interface'}"
              f"{' with filter: ' + filter_str if filter_str else ''}")
              
        try:
            # Capture packets
            captured_packets = sniff(
                iface=self.interface,
                filter=filter_str,
                timeout=duration,
                prn=self.packet_callback
            )
            
            # Create temporary file to store capture
            fd, self.temp_pcap = tempfile.mkstemp(suffix='.pcap')
            os.close(fd)
            
            # Write packets to temporary file
            wrpcap(self.temp_pcap, captured_packets)
            print(f"Captured {len(captured_packets)} packets")
            
            return self.temp_pcap
            
        except Exception as e:
            raise Exception(f"Capture failed: {str(e)}")
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_pcap and os.path.exists(self.temp_pcap):
            os.remove(self.temp_pcap)
            self.temp_pcap = None