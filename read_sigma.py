import yaml
import os
from sigma.collection import SigmaRule
from scapy.all import rdpcap, TCP, IP, ICMP
from datetime import datetime, timedelta
from collections import defaultdict
import click

def load_sigma_rule(rule_path):
    with open(rule_path, 'r') as file:
        rule_content = yaml.safe_load(file)
    rule = SigmaRule.from_dict(rule_content)
    return rule, rule_content

def process_pcap(pcap_path):
    return rdpcap(pcap_path)

def get_packet_fields(packet, fields):
    """Extracts field values from packet based on Sigma rule definition."""
    field_values = {}
    for field in fields:
        if field == 'ip_src' and packet.haslayer(IP):
            field_values[field] = packet[IP].src
        elif field == 'ip_dst' and packet.haslayer(IP):
            field_values[field] = packet[IP].dst
        elif field == 'tcp_flags' and packet.haslayer(TCP):
            field_values[field] = packet[TCP].flags
        elif field == 'ip_proto' and packet.haslayer(IP):
            field_values[field] = packet[IP].proto
        elif field == 'tcp_sport' and packet.haslayer(TCP):
            field_values[field] = packet[TCP].sport
        elif field == 'tcp_dport' and packet.haslayer(TCP):
            field_values[field] = packet[TCP].dport
        elif field == 'icmp_type' and packet.haslayer(ICMP):
            field_values[field] = packet[ICMP].type
    if packet.haslayer(TCP) or packet.haslayer(IP):
        field_values['timestamp'] = float(packet.time)
    return field_values

def matches_selection_criteria(packet_fields, selection_criteria):
    """Checks if packet fields match selection criteria from the rule."""
    for key, value in selection_criteria.items():
        if key not in packet_fields:
            return False
        if isinstance(value, list):
            if packet_fields[key] not in value:
                return False
        elif packet_fields[key] != value:
            return False
    return True

def matches_filter_criteria(packet_fields, filter_criteria):
    """Checks if packet fields match filter criteria from the rule."""
    for key, value in filter_criteria.items():
        if key in packet_fields:
            if isinstance(value, list):
                if packet_fields[key] in value:
                    return True
            elif packet_fields[key] == value:
                return True
    return False

def analyze_time_window(packets, window_size_seconds):
    """Groups packets into time windows and checks thresholds."""
    if not packets:
        return []
    
    windows = []
    current_window = []
    current_start = packets[0].get('timestamp', 0)
    
    for packet in sorted(packets, key=lambda x: x.get('timestamp', 0)):
        if packet.get('timestamp', 0) - current_start <= window_size_seconds:
            current_window.append(packet)
        else:
            if current_window:
                windows.append(current_window)
            current_window = [packet]
            current_start = packet.get('timestamp', 0)
    
    if current_window:
        windows.append(current_window)
    
    return windows

def detect_with_sigma(rule, rule_content, pcap_data):
    detections = []
    
    detection_rules = rule_content.get('detection', {})
    selection_criteria = detection_rules.get('selection', {})
    filter_criteria = detection_rules.get('filter', {})
    condition = detection_rules.get('condition', '')
    fields = rule_content.get('fields', [])
    level = rule_content.get('level', 'unknown')
    
    packets_by_source = defaultdict(list)
    
    # First pass - collect all relevant packets
    for packet in pcap_data:
        packet_fields = get_packet_fields(packet, fields)
        
        if matches_selection_criteria(packet_fields, selection_criteria):
            if not matches_filter_criteria(packet_fields, filter_criteria):
                source_ip = packet_fields.get('ip_src')
                if source_ip:
                    packets_by_source[source_ip].append(packet_fields)
    
    # Second pass - analyze collected packets
    for source_ip, packets in packets_by_source.items():
        if 'count' in condition:
            try:
                threshold = int(condition.split('>')[-1].strip().split()[0])
                
                # Check if we need to analyze time windows
                if 'within' in condition:
                    window_size = int(condition.split('within')[1].split()[0])
                    windows = analyze_time_window(packets, window_size)
                    
                    for window in windows:
                        if len(window) > threshold:
                            unique_ports = set(p.get('tcp_dport') for p in window if 'tcp_dport' in p)
                            detection = {
                                'title': rule.title,
                                'source_ip': source_ip,
                                'detection_type': f"Threshold exceeded: {len(window)} events within {window_size} seconds (threshold: {threshold})",
                                'packet_count': len(window),
                                'level': level,
                                'fields_detected': {
                                    'unique_ports': list(unique_ports),
                                    'start_time': datetime.fromtimestamp(window[0].get('timestamp')).strftime('%Y-%m-%d %H:%M:%S'),
                                    'end_time': datetime.fromtimestamp(window[-1].get('timestamp')).strftime('%Y-%m-%d %H:%M:%S')
                                }
                            }
                            detections.append(detection)
                else:
                    if len(packets) > threshold:
                        unique_ports = set(p.get('tcp_dport') for p in packets if 'tcp_dport' in p)
                        detection = {
                            'title': rule.title,
                            'source_ip': source_ip,
                            'detection_type': f"Threshold exceeded: {len(packets)} unusual port connections (threshold: {threshold})",
                            'packet_count': len(packets),
                            'level': level,
                            'fields_detected': {
                                'unique_ports': list(unique_ports),
                                'time_range': f"{datetime.fromtimestamp(packets[0].get('timestamp')).strftime('%Y-%m-%d %H:%M:%S')} - {datetime.fromtimestamp(packets[-1].get('timestamp')).strftime('%Y-%m-%d %H:%M:%S')}"
                            }
                        }
                        detections.append(detection)
            except (ValueError, IndexError) as e:
                print(f"Error processing condition: {str(e)}")
                continue
    
    return detections

def get_yaml_files_in_directory(directory_path):
    return [os.path.join(directory_path, f) for f in os.listdir(directory_path) if f.endswith('.yml')]

def run_sigma_analysis(pcap_path, rule_dir='/home/maciej/semester5/flow_analysis/sigma_rules'):
    """Function for use in the main application component"""
    rule_files = get_yaml_files_in_directory(rule_dir)
    pcap_data = process_pcap(pcap_path)
    all_detections = []
    
    for rule_file in rule_files:
        try:
            rule, rule_content = load_sigma_rule(rule_file)
            detections = detect_with_sigma(rule, rule_content, pcap_data)
            all_detections.extend(detections)
        except Exception as e:
            print(f"Error processing rule file {rule_file}: {str(e)}")
            continue
    
    return all_detections

def print_detections(detections):
    """Displays detections in a readable format"""
    abuseIPs = {}
    if detections:
        print(f"\n=== Sigma Analysis Results ({len(detections)} detections found) ===")
        for detection in detections:
            print("\n=== Detection ===")
            print(f"Rule title: {detection['title']}")
            print(f"Severity level: {detection['level']}")
            print(f"Detection type: {detection['detection_type']}")
            print(f"Source IP: {detection['source_ip']}")
            abuseIPs[detection['source_ip']] = abuseIPs.get(detection['source_ip'], 1)
            print(f"Packet count: {detection['packet_count']}")
            print("Detected fields:")
            for field, value in detection['fields_detected'].items():
                print(f"  - {field}: {value}")                        
    else:
        print("\n=== Sigma Analysis Results: No detections found ===")
    print(abuseIPs)
    return abuseIPs

def main(pcap_file, overall=False):
    """Main function for Click integration"""
    detections = run_sigma_analysis(pcap_file)
    print_detections(detections)
    return detections

if __name__ == "__main__":
    main()