import click
from detection_rules import *
from raport_generator import *
from read_sigma import *
from live_capture import LiveCapture

@click.command()
@click.argument('pcap_file', type=click.Path(exists=True), required=False)
@click.option('--live', is_flag=True, help='Enable live capture mode')
@click.option('--list-interfaces', is_flag=True, help='List available network interfaces')
@click.option('--interface', help='Network interface to capture from (e.g., eth0)')
@click.option('--port', type=int, help='Port to capture on')
@click.option('--duration', type=int, default=60, help='Duration of capture in seconds')
@click.option('--overall', is_flag=True, help='Perform overall execution. This option will also provide results charts and location map.')
@click.option('--generate-data-charts', is_flag=True, help="Generate charts from PCAP data.")
@click.option('--get-reputation-ip', is_flag=True, help="Check reputation from IPs.")
@click.option('--generate-map', is_flag=True, help="Generate map with IPs.")
@click.option('--find-perspective-ip', is_flag=True, help="Find the most likely perspective IP.")
@click.option('--large-flow', is_flag=True, help="Detect large network flows.")
@click.option('--asymmetrical-flows', is_flag=True, help="Detect asymmetrical flows.")
@click.option('--unusual-ports', is_flag=True, help="Detect unusual port usage.")
@click.option('--dns-users', is_flag=True, help="Find DNS users.")
@click.option('--syn-flood', is_flag=True, help="Detect potential SYN flood attacks.")
@click.option('--http-get', is_flag=True, help="Detect HTTP GET requests.")
@click.option('--ping-flood', is_flag=True, help="Detect Ping flood attacks.")
@click.option('--ports-scanner', is_flag=True, help="Detect port scanning.")
@click.option('--ip-to-remove', default=None, help="Specify an IP to exclude from analysis.")
@click.option('--chart', default=False, help="Generate result charts.")
@click.option('--sigma-analysis', is_flag=True, help="Perform Sigma rules analysis.")

def main(pcap_file, live, list_interfaces, interface, port, duration, chart, overall, generate_data_charts, 
         get_reputation_ip, generate_map, find_perspective_ip, large_flow, asymmetrical_flows, 
         unusual_ports, dns_users, syn_flood, http_get, ping_flood, 
         ports_scanner, ip_to_remove, sigma_analysis):
    """
    Comprehensive tool for analyzing PCAP files and live network traffic.
    
    Can be used in two modes:
    1. PCAP file analysis: Provide a pcap file path
    2. Live capture: Use --live flag with optional --interface and --port options
    
    For listing available network interfaces, use --list-interfaces
    
    For PCAP analysis, if you want to filter packets and exclude packets where your probable IP is source:
    1. Use '--find-perspective-ip' first (or check your IP manually)
    2. Use '--ip-to-remove <IP> --overall'
    
    Examples:
        # List available interfaces
        python flows_analyzer.py --list-interfaces
        
        # Capture from specific interface
        python flows_analyzer.py --live --interface eth0 --overall
        
        # Capture specific port
        python flows_analyzer.py --live --interface eth0 --port 80 --overall
        
    ATTENTION! Perspective IP may be wrong, because it simply checks what IP is the most frequent in pcap file packets.
    We highly suggest checking your IP manually.
    """
    
    # Handle interface listing
    if list_interfaces:
        LiveCapture.list_interfaces()
        return
        
    if live and pcap_file:
        print("Error: Cannot specify both live capture and pcap file")
        return
        
    if not live and not pcap_file:
        print("Error: Must specify either --live or provide a pcap file")
        return
        
    # Handle live capture
    temp_pcap = None
    if live:
        try:
            capture = LiveCapture(interface=interface, port=port)
            temp_pcap = capture.start_capture(duration)
            print(f"Live capture completed. Analyzing captured traffic...")
            pcap_file = temp_pcap
        except Exception as e:
            print(f"Error during live capture: {str(e)}")
            return

    try:
        if overall:
            chart = True
            print("Executing all analyses...")
            print("Generating data charts...")
            charts(pcap_file)
            print("Checking IP reputations...")
            #reputation = check_ip_reputation(pcap_file, chart)
            if find_perspective_ip:
                print("Finding perspective IP...")
                find_perspective_ip_nfstream(pcap_file)
            print("Detecting large flows...")
            large = detect_large_flow(pcap_file, ip_to_remove, chart)
            print("Detecting asymmetrical flows...")
            assymetrical = asymmetrical_flow(pcap_file, chart)
            print("Detecting unusual port usage...")
            unusual = unusual_ports_flow(pcap_file, ip_to_remove, chart)
            print("Finding DNS users...")
            dns = find_DNS_users(pcap_file, ip_to_remove, chart)
            print("Detecting SYN flood attacks...")
            syn = detect_SYN_flood(pcap_file, ip_to_remove, chart)
            print("Detecting HTTP GET requests...")
            http = detect_http_get(pcap_file, ip_to_remove, chart)
            print("Detecting Ping flood attacks...")
            ping = detect_ping_flood(pcap_file, ip_to_remove, chart)
            print("Detecting port scanning...")
            ports = detect_ports_scanner(pcap_file, ip_to_remove, chart)
            print("Sigma detection...")
            sigma_detections = run_sigma_analysis(pcap_file)
            sigma = print_detections(sigma_detections)
            print("Generating map and saving to HTML...")
            generate_ip_location_map(#reputation, 
                                    large, assymetrical, unusual, dns, syn, http, ping, ports, sigma, pcap=pcap_file)

            generate_final_report(pcap_file, chart)
            return

        if generate_data_charts:
            print("Generating data charts...")
            charts(pcap_file)
        
        if get_reputation_ip:
            print("Checking IP reputations...")
            check_ip_reputation(pcap_file)

        if find_perspective_ip:
            print("Finding perspective IP...")
            find_perspective_ip_nfstream(pcap_file)

        if large_flow:
            print("Detecting large flows...")
            detect_large_flow(pcap_file, ip_to_remove, chart)

        if asymmetrical_flows:
            print("Detecting asymmetrical flows...")
            asymmetrical_flow(pcap_file, ip_to_remove, chart)

        if unusual_ports:
            print("Detecting unusual port usage...")
            unusual_ports_flow(pcap_file, ip_to_remove, chart)

        if dns_users:
            print("Finding DNS users...")
            find_DNS_users(pcap_file, ip_to_remove, chart)

        if syn_flood:
            print("Detecting SYN flood attacks...")
            detect_SYN_flood(pcap_file, ip_to_remove, chart)

        if http_get:
            print("Detecting HTTP GET requests...")
            detect_http_get(pcap_file, ip_to_remove, chart)

        if ping_flood:
            print("Detecting Ping flood attacks...")
            detect_ping_flood(pcap_file, ip_to_remove, chart)

        if ports_scanner:
            print("Detecting port scanning...")
            detect_ports_scanner(pcap_file, ip_to_remove, chart)
        
        if sigma_analysis:
            print("Sigma detection...")
            sigma_detections = run_sigma_analysis(pcap_file)
            sigma = print_detections(sigma_detections)

        if not any([overall, get_reputation_ip, generate_data_charts, find_perspective_ip, 
                   large_flow, asymmetrical_flows, unusual_ports, dns_users, syn_flood, 
                   http_get, ping_flood, ports_scanner, sigma_analysis]):
            print("No operation selected. Use --help for options.")

    finally:
        # Cleanup temporary file if it was a live capture
        if live and temp_pcap:
            try:
                os.remove(temp_pcap)
            except Exception as e:
                print(f"Warning: Could not remove temporary capture file: {str(e)}")

if __name__ == "__main__":
    main()