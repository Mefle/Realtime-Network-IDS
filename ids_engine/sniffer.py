from scapy.all import sniff, TCP, IP, ICMP
from collections import defaultdict
import requests
import time
import os
import sys

API_URL = "http://127.0.0.1:5000/alerts"

TIME_WINDOW = 10

SYN_FLOOD_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 15
ICMP_SWEEP_THRESHOLD = 8

syn_counts = defaultdict(int)
port_scans = defaultdict(set)
icmp_sweeps = defaultdict(set)

last_reset = time.time()

last_alert_time = defaultdict(float)
ALERT_COOLDOWN = 15


def should_send_alert(source_ip, threat_type):
    key = f"{source_ip}-{threat_type}"
    current_time = time.time()

    if current_time - last_alert_time[key] >= ALERT_COOLDOWN:
        last_alert_time[key] = current_time
        return True

    return False


def report_alert(source_ip, threat_type, description, severity="Medium",
                 destination_ip=None, destination_port=None, protocol=None):

    payload = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "threat_type": threat_type,
        "severity": severity,
        "description": description
    }

    try:
        response = requests.post(API_URL, json=payload)

        if response.status_code == 201:
            print(f"[*] Alert reported: {threat_type} | Source: {source_ip} | Severity: {severity}")
        else:
            print(f"[!] Failed to report alert: HTTP {response.status_code} - {response.text}")

        sys.stdout.flush()

    except Exception as e:
        print(f"[!] Error reporting alert: {e}")
        sys.stdout.flush()


def analyze_tcp_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport
    flags = packet[TCP].flags

    # SYN without ACK = connection attempt
    if flags & 0x02 and not (flags & 0x10):
        syn_counts[src_ip] += 1
        port_scans[src_ip].add(dst_port)

        # Prevent terminal spam
        if syn_counts[src_ip] % 10 == 0:
            print(f"[TCP] SYN activity | {src_ip} -> {dst_ip} | Count: {syn_counts[src_ip]}")
            sys.stdout.flush()


def analyze_icmp_packet(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    icmp_type = packet[ICMP].type

    if icmp_type == 8:
        icmp_sweeps[src_ip].add(dst_ip)

        if len(icmp_sweeps[src_ip]) % 3 == 0:
            print(f"[ICMP] Echo activity | {src_ip} | Unique destinations: {len(icmp_sweeps[src_ip])}")
            sys.stdout.flush()


def evaluate_alerts():
    for ip, count in syn_counts.items():
        if count > SYN_FLOOD_THRESHOLD:
            if should_send_alert(ip, "SYN Flood"):
                report_alert(
                    source_ip=ip,
                    destination_ip=None,
                    destination_port=None,
                    protocol="TCP",
                    threat_type="SYN Flood",
                    severity="High",
                    description=f"Detected {count} SYN packets within {TIME_WINDOW} seconds. Possible SYN flood attack."
                )

    for ip, ports in port_scans.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            if should_send_alert(ip, "Port Scan"):
                sorted_ports = sorted(list(ports))
                report_alert(
                    source_ip=ip,
                    destination_ip=None,
                    destination_port=None,
                    protocol="TCP",
                    threat_type="Port Scan",
                    severity="Medium",
                    description=f"Detected connection attempts to {len(ports)} unique TCP ports within {TIME_WINDOW} seconds. Scanned ports: {sorted_ports[:20]}"
                )

    for ip, destinations in icmp_sweeps.items():
        if len(destinations) > ICMP_SWEEP_THRESHOLD:
            if should_send_alert(ip, "ICMP Ping Sweep"):
                report_alert(
                    source_ip=ip,
                    destination_ip=None,
                    destination_port=None,
                    protocol="ICMP",
                    threat_type="ICMP Ping Sweep",
                    severity="Medium",
                    description=f"Detected ICMP echo requests to {len(destinations)} unique destinations within {TIME_WINDOW} seconds. Possible host discovery activity."
                )


def reset_counters():
    syn_counts.clear()
    port_scans.clear()
    icmp_sweeps.clear()


def packet_callback(packet):
    global last_reset

    if IP in packet:
        if TCP in packet:
            analyze_tcp_packet(packet)

        if ICMP in packet:
            analyze_icmp_packet(packet)

    current_time = time.time()

    if current_time - last_reset >= TIME_WINDOW:
        evaluate_alerts()
        reset_counters()
        last_reset = current_time


def main():
    interface = os.environ.get("IDS_INTERFACE", "lo")

    print("=" * 60)
    print("Real-Time Network Intrusion Detection System Started")
    print("=" * 60)
    print(f"[*] Monitoring interface: {interface}")
    print(f"[*] Backend API: {API_URL}")
    print(f"[*] Time window: {TIME_WINDOW} seconds")
    print("[*] Detection rules enabled:")
    print(f"    - SYN Flood threshold: more than {SYN_FLOOD_THRESHOLD} SYN packets")
    print(f"    - Port Scan threshold: more than {PORT_SCAN_THRESHOLD} unique ports")
    print(f"    - ICMP Sweep threshold: more than {ICMP_SWEEP_THRESHOLD} unique destinations")
    print("=" * 60)
    sys.stdout.flush()

    try:
        sniff(prn=packet_callback, store=0, iface=interface)
    except PermissionError:
        print("[!] Permission denied. Try running with sudo:")
        print("    sudo -E venv/bin/python sniffer.py")
    except Exception as e:
        print(f"[!] Sniffer error: {e}")


if __name__ == "__main__":
    main()