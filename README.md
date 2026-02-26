# Network Traffic Analysis & Threat Detection

A comprehensive tool for analyzing PCAP files and live network traffic to detect potential threats.

## Features

- **PCAP File Analysis** – analyze captured traffic from `.pcap` files
- **Live Capture** – capture and analyze live network traffic
- **Detection Rules** – rule-based detection for:
  - Large flows (ports 80/443)
  - Asymmetrical flows (potential DDoS)
  - Unusual port usage
  - DNS heavy users
  - SYN flood attacks
  - HTTP GET flood
  - Ping (ICMP) flood
  - Port scanning
- **Sigma Rules Analysis** – apply custom YAML-based Sigma rules
- **IP Reputation Check** – query AbuseIPDB for malicious IPs
- **Geolocation Map** – generate an interactive HTML map of detected IPs
- **ML Classifier** (`ml_flows_analyzer.py`) – train/predict with a Random Forest model

## Requirements

```bash
pip install -r requirements.txt
```

## Usage

### List available network interfaces

```bash
python flows_analyzer.py --list-interfaces
```

### Analyze a PCAP file (all detections)

```bash
python flows_analyzer.py traffic.pcap --overall
```

### Analyze a PCAP file excluding your own IP

```bash
python flows_analyzer.py traffic.pcap --find-perspective-ip
python flows_analyzer.py traffic.pcap --overall --ip-to-remove 192.168.1.10
```

### Run individual detections

```bash
python flows_analyzer.py traffic.pcap --syn-flood
python flows_analyzer.py traffic.pcap --ports-scanner
python flows_analyzer.py traffic.pcap --sigma-analysis
```

### Live capture

```bash
python flows_analyzer.py --live --interface eth0 --overall
python flows_analyzer.py --live --interface eth0 --port 80 --duration 120 --overall
```

### ML-based classification

```bash
# Train a model
python ml_flows_analyzer.py train normal.pcap malicious.pcap

# Predict on new capture
python ml_flows_analyzer.py predict traffic.pcap flow_classifier.joblib
```

## API Keys

To enable IP reputation checks and geolocation mapping, add your API keys in `raport_generator.py`:

- **AbuseIPDB** – `check_ip_reputation()` function
- **ipinfo.io** – `generate_ip_location_map()` function

## Sigma Rules

Custom Sigma rules are stored in the `sigma_rules/` directory as YAML files. The tool automatically loads all `.yml` files from that directory.
