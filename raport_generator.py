import os
from nfstream import NFStreamer
import matplotlib.pyplot as plt
import requests
import folium


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
        

        if data['data']['abuseConfidenceScore'] >= 30: # or data['data']['totalReports'] >= 50: # You can change that
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

    unique_ips = set()  # Zbiór, aby uniknąć duplikatów

    # Walidacja argumentów i zbieranie kluczy
    for a in args:
        if isinstance(a, dict):  # Sprawdzenie, czy `a` jest słownikiem
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

