import os
from nfstream import NFStreamer
import matplotlib.pyplot as plt
import requests
import folium
import pandas as pd


# Utility function to create directories
def create_dir(base_name, sub_dir=None):
    dir_name = f"{base_name}-wrapped"
    if sub_dir:
        dir_name = os.path.join(dir_name, sub_dir)
    os.makedirs(dir_name, exist_ok=True)
    return dir_name


# Raw data from flow into charts
def charts(pcap):
    base_name = os.path.basename(pcap)
    output_dir = create_dir(base_name, 'data')
    
    streamer = NFStreamer(source=pcap, statistical_analysis=True)
    data = streamer.to_pandas()

    # Remove columns with one unique value or missing data
    data = data.loc[:, data.nunique() > 1]
    
    columns = ['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'bidirectional_bytes']
    for column in columns:
        if column in data:
            data[column].value_counts().plot(kind='bar')
            plt.title(f'{column} distribution')
            plt.ylabel('')
            plt.savefig(os.path.join(output_dir, f'{column}.png'))
            plt.close()


# Generates a bar chart
def plot_bar_chart(data, title, xlabel, ylabel, pcap):
    base_name = os.path.basename(pcap)
    output_dir = create_dir(base_name, 'results')
    
    plt.figure(figsize=(10, 6))
    keys = [str(key) for key in data.keys()]
    values = list(data.values())
    
    plt.bar(keys, values, color='blue')
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'{title}.png'))
    plt.close()


# Check IP reputation using AbuseIPDB API
def check_ip_reputation(pcap, chart=False):
    base_name = os.path.basename(pcap)
    output_dir = create_dir(base_name, 'jsons')
    
    API_KEY = "1ebfb290f89429819ebc4ba50a003052e13e4c09ee1fe29dfef14e6a6b34221cf5b68ae8d4d272b2"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    
    streamer = NFStreamer(source=pcap, statistical_analysis=True)
    unique_ips = {flow.src_ip for flow in streamer}
    unique_ips.update({flow.dst_ip for flow in streamer})
    abuseIPs = {}

    for ip in unique_ips:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
        data = response.json()
        

        if data['data']['abuseConfidenceScore'] >= 30:
            print(f'AbuseIPDB considers {ip} as dangerous!')
            if ip in abuseIPs:
                abuseIPs[ip] += 1
            else:
                abuseIPs[ip] = 1
        
        
        with open(os.path.join(output_dir, f"{ip}_reputation.json"), "w") as f:
            f.write(str(data))

    if abuseIPs and chart:
        plot_bar_chart(abuseIPs, "Dangerous IPs Detected By AbuseIPDB", "Source IP", "Count", pcap)
    
    print(abuseIPs)

    return abuseIPs

def generate_ip_location_map(*args, pcap):
    base_name = os.path.basename(pcap)
    output_dir = create_dir(base_name, 'results')
    output_file = os.path.join(output_dir, "map.html")
    
    API_KEY = "58b265d90882f5"
    map_center = [0, 0]
    m = folium.Map(location=map_center, zoom_start=2)

    unique_ips = set()  # Getting rid of the duplicates

    # Validating arguments and collecting keys
    for a in args:
        if isinstance(a, dict):
            unique_ips.update(a.keys())
        else:
            print(f"WARNING: Skipping non-dict argument: {a}")

    print(f"Unique IPs from alerts: {unique_ips}")

    for ip in unique_ips:
        try:
            response = requests.get(f"https://ipinfo.io/{ip}", headers={"Authorization": f"Bearer {API_KEY}"})
            data = response.json()

            loc = data.get("loc")
            if loc:
                lat, lon = map(float, loc.split(","))
                folium.Marker(location=[lat, lon], popup=f"IP: {ip}").add_to(m)
        except Exception as e:
            print(f"ERROR: cannot process {ip}: {e}")

    m.save(output_file)
    print(f"Map written to {output_file}")

def generate_analysis_report(pcap_file, results_dict, output_dir='reports'):
    """Generate comprehensive analysis report"""
    # Create reports directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate timestamp for the report
    timestamp = pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(output_dir, f'analysis_report_{timestamp}.txt')
    
    with open(report_file, 'w') as f:
        # Header
        f.write("=== Network Traffic Analysis Report ===\n")
        f.write(f"Generated at: {pd.Timestamp.now()}\n")
        f.write(f"Analyzed file: {pcap_file}\n\n")
        
        # Large Flows Analysis
        if 'large_flows' in results_dict:
            f.write("=== Large Flows Detection ===\n")
            for ip, count in results_dict['large_flows'].items():
                f.write(f"IP {ip}: {count} large flows detected\n")
            f.write("\n")
        
        # Asymmetrical Flows
        if 'asymmetrical_flows' in results_dict:
            f.write("=== Asymmetrical Flows Detection ===\n")
            for ip, count in results_dict['asymmetrical_flows'].items():
                f.write(f"IP {ip}: {count} asymmetrical flows detected\n")
            f.write("\n")
        
        # Unusual Ports
        if 'unusual_ports' in results_dict:
            f.write("=== Unusual Ports Usage ===\n")
            for ip, count in results_dict['unusual_ports'].items():
                f.write(f"IP {ip}: {count} connections to unusual ports\n")
            f.write("\n")
        
        # DNS Users
        if 'dns_users' in results_dict:
            f.write("=== DNS Usage Analysis ===\n")
            for ip, count in results_dict['dns_users'].items():
                f.write(f"IP {ip}: {count} DNS queries\n")
            f.write("\n")
        
        # SYN Flood
        if 'syn_flood' in results_dict:
            f.write("=== SYN Flood Detection ===\n")
            for ip, count in results_dict['syn_flood'].items():
                f.write(f"IP {ip}: {count} SYN packets sent\n")
            f.write("\n")
        
        # HTTP GET
        if 'http_get' in results_dict:
            f.write("=== HTTP GET Requests Analysis ===\n")
            for ip, count in results_dict['http_get'].items():
                f.write(f"IP {ip}: {count} GET requests\n")
            f.write("\n")
        
        # Ping Flood
        if 'ping_flood' in results_dict:
            f.write("=== Ping Flood Detection ===\n")
            for ip, count in results_dict['ping_flood'].items():
                f.write(f"IP {ip}: {count} ICMP packets sent\n")
            f.write("\n")
        
        # Port Scanning
        if 'port_scanning' in results_dict:
            f.write("=== Port Scanning Detection ===\n")
            for ip, ports in results_dict['port_scanning'].items():
                f.write(f"IP {ip}: scanned {ports} unique ports\n")
            f.write("\n")
        
        # Sigma Detections
        if 'sigma_detections' in results_dict:
            f.write("=== Sigma Rules Detections ===\n")
            f.write(results_dict['sigma_detections'])
            f.write("\n")
        
        # Summary
        f.write("=== Summary of Detections ===\n")
        total_alerts = sum(len(detections) for detections in results_dict.values() if isinstance(detections, dict))
        f.write(f"Total number of alerts: {total_alerts}\n")
        f.write(f"Number of detection types triggered: {len(results_dict)}\n")
    
    print(f"\nDetailed report saved to: {report_file}")
    return report_file

