from nfstream import NFStreamer
from scapy.all import rdpcap, TCP, ICMP, IP
from raport_generator import plot_bar_chart

# Global threat counter
threat_count = {}

def increment_threat_count(threat_type):
    """Increments the count of a specific threat type."""
    threat_count[threat_type] = threat_count.get(threat_type, 0) + 1


# Function to find the perspective IP
def find_perspective_ip_nfstream(pcap):
    streamer = NFStreamer(source=pcap, statistical_analysis=True)
    ip_counts = {}
    for flow in streamer:
        ip_counts[flow.src_ip] = ip_counts.get(flow.src_ip, 0) + flow.bidirectional_packets
        ip_counts[flow.dst_ip] = ip_counts.get(flow.dst_ip, 0) + flow.bidirectional_packets
    if ip_counts:
        perspective_ip = max(ip_counts, key=ip_counts.get)
        print(f"Most likely perspective IP: {perspective_ip}")
        return perspective_ip
    print("No flows found.")
    return None

# Large flows detection on ports 80 and 443
def detect_large_flow(pcap, ip_to_remove=None, chart=False):
    streamer = NFStreamer(source=pcap, statistical_analysis=True)
    large_flows = {}
    for flow in streamer:
        if ip_to_remove and flow.src_ip == ip_to_remove:
            continue
        if flow.dst_port in [80, 443] and flow.src2dst_bytes > 1_000_000:
            increment_threat_count("large_flow")
            large_flows[flow.src_ip] = large_flows.get(flow.src_ip, 0) + 1
            print(f"ALERT: Suspicious large flow to port {flow.dst_port} from {flow.src_ip}, Count: {large_flows[flow.src_ip]}")
    if chart and large_flows:
        plot_bar_chart(large_flows, "Large Flows Detected", "Source IP", "Count", pcap)
    return large_flows

# Asymmetrical flow detection
def asymmetrical_flow(pcap, chart=False):
    streamer = NFStreamer(source=pcap)
    asym_flows = {}
    for flow in streamer:
        if flow.bidirectional_packets > 1000 and flow.dst2src_packets < 10:
            increment_threat_count("asymmetrical_flow")
            asym_flows[flow.src_ip] = asym_flows.get(flow.src_ip, 0) + 1
            print(f"ALERT: Possible DDoS attack detected from {flow.src_ip} to {flow.dst_ip}")
    if chart and asym_flows:
        plot_bar_chart(asym_flows, "Asymmetrical Flows Detected", "Source IP", "Count", pcap)
    return asym_flows

# Unusual ports usage detection
def unusual_ports_flow(pcap, ip_to_remove=None, chart=False):
    packets = rdpcap(pcap)
    unusual_flows = {}
    common_ports = [80, 443, 22, 53]
    
    # First, count all unusual port connections
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if ip_to_remove and pkt[IP].src == ip_to_remove:
                continue
                
            src_ip = pkt[IP].src
            dst_port = pkt[TCP].dport
            
            if dst_port not in common_ports:
                key = (src_ip, dst_port)
                unusual_flows[key] = unusual_flows.get(key, 0) + 1

    # Then print only the final counts
    for (src_ip, dst_port), count in unusual_flows.items():
        increment_threat_count("unusual_ports")
        print(f"ALERT: Unusual port usage detected: to port {dst_port} by {src_ip}, Count: {count}")

    if chart and unusual_flows:
        plot_bar_chart(unusual_flows, "Unusual Ports Detected", "(Source, Destination Ports)", "Count", pcap)

    # Convert to format needed for map function
    unusual = {}
    for key in unusual_flows:
        un_ip, un_port = key
        unusual[un_ip] = unusual.get(un_ip, 0) + unusual_flows[key]

    # Filter out IPs that don't meet threshold
    unusual = {ip: count for ip, count in unusual.items() if count > 5}
    
    return unusual

# DNS users detection
def find_DNS_users(pcap, ip_to_remove=None, chart=False):
    streamer = NFStreamer(source=pcap, statistical_analysis=True)
    dns_flows = streamer.to_pandas()
    dns_flows = dns_flows[(dns_flows['application_name'] == 'DNS') & (dns_flows['src_ip'] != ip_to_remove)]
    top_clients = dns_flows['src_ip'].value_counts()
    dns_users = {}
    for client, count in top_clients.items():
        increment_threat_count("dns_user")
        dns_users[client] = count
        print(f"DNS user: {client}, Count: {count}")
    if chart and dns_users:
        plot_bar_chart(dns_users, "DNS Users Detected", "Client IP", "Count", pcap)
    return dns_users

# SYN Flood detection 
def detect_SYN_flood(pcap, ip_to_remove=None, chart=False):
    packets = rdpcap(pcap)
    syn_ip_counts = {}
    for pkt in packets:
        if ip_to_remove and pkt.haslayer(IP) and pkt[IP].src == ip_to_remove:
            continue
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            src_ip = pkt[IP].src
            syn_ip_counts[src_ip] = syn_ip_counts.get(src_ip, 0) + 1
    syn_floods = {ip: count for ip, count in syn_ip_counts.items() if count > 500}
    for ip, count in syn_floods.items():
        increment_threat_count("syn_flood")
        print(f"ALERT: SYN flood detected from IP: {ip}, Count: {count}")
    if chart and syn_floods:
        plot_bar_chart(syn_floods, "SYN Flood Detected", "Source IP", "Count", pcap)
    return syn_floods

# HTTP GET detection
def detect_http_get(pcap, ip_to_remove=None, chart=False):
    packets = rdpcap(pcap)
    http_get_counts = {}
    for pkt in packets:
        if ip_to_remove and pkt.haslayer(IP) and pkt[IP].src == ip_to_remove:
            continue
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
            if b"GET" in bytes(pkt.payload):
                src_ip = pkt[IP].src
                http_get_counts[src_ip] = http_get_counts.get(src_ip, 0) + 1
    for src_ip, count in http_get_counts.items():
        increment_threat_count("http_get")
        print(f"ALERT: HTTP GET requests from {src_ip}: {count}")
    if chart and http_get_counts:
        plot_bar_chart(http_get_counts, "HTTP GET Requests Detected", "Source IP", "Count", pcap)
    return http_get_counts

# Ping Flood detection
def detect_ping_flood(pcap, ip_to_remove=None, chart=False):
    packets = rdpcap(pcap)
    ping_ip_counts = {}
    for pkt in packets:
        if ip_to_remove and pkt.haslayer(IP) and pkt[IP].src == ip_to_remove:
            continue
        if pkt.haslayer(ICMP):
            src_ip = pkt[IP].src
            ping_ip_counts[src_ip] = ping_ip_counts.get(src_ip, 0) + 1
    ping_floods = {ip: count for ip, count in ping_ip_counts.items() if count > 1000}
    for ip, count in ping_floods.items():
        increment_threat_count("ping_flood")
        print(f"ALERT: Ping flood detected from IP: {ip}, Count: {count}")
    if chart and ping_floods:
        plot_bar_chart(ping_floods, "Ping Flood Detected", "Source IP", "Count", pcap)
    return ping_floods

# Scanning ports detection
def detect_ports_scanner(pcap, ip_to_remove=None, chart=False):
    packets = rdpcap(pcap)
    syn_scan_results = {}
    for pkt in packets:
        if ip_to_remove and pkt.haslayer(IP) and pkt[IP].src == ip_to_remove:
            continue
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            src_ip = pkt[IP].src
            dst_port = pkt[TCP].dport
            if src_ip not in syn_scan_results:
                syn_scan_results[src_ip] = []
            if dst_port not in syn_scan_results[src_ip]:
                syn_scan_results[src_ip].append(dst_port)
    port_scans = {ip: len(ports) for ip, ports in syn_scan_results.items() if len(ports) >= 10}
    for ip, port_count in port_scans.items():
        increment_threat_count("port_scan")
    if chart and port_scans:
        plot_bar_chart(port_scans, "Port Scanners Detected", "Source IP", "Port Count", pcap)
    return port_scans

# Final report
def generate_final_report(pcap, chart=False):
    print("\nFinal IPs Threat Report:")
    for threat, count in threat_count.items():
        print(f"{threat}: {count}")
    if chart and threat_count:
        plot_bar_chart(threat_count, "Threat Summary", "Threat Type", "Count", pcap)
