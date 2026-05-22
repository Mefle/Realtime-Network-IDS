from scapy.all import IP, TCP, ICMP, send
import time
import random

TARGET_IP = "127.0.0.1"


def simulate_port_scan():
    print("[*] Starting Port Scan Simulation...")
    for port in range(1, 25):
        packet = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(packet, verbose=False)
        time.sleep(0.05)
    print("[*] Port Scan Simulation Complete.")


def simulate_syn_flood():
    print("[*] Starting SYN Flood Simulation...")
    for _ in range(70):
        random_port = random.randint(20, 1000)
        packet = IP(dst=TARGET_IP)/TCP(dport=random_port, flags="S")
        send(packet, verbose=False)
    print("[*] SYN Flood Simulation Complete.")


def simulate_icmp_sweep():
    print("[*] Starting ICMP Ping Sweep Simulation...")
    fake_targets = [
        "127.0.0.1",
        "127.0.0.2",
        "127.0.0.3",
        "127.0.0.4",
        "127.0.0.5",
        "127.0.0.6",
        "127.0.0.7",
        "127.0.0.8",
        "127.0.0.9",
        "127.0.0.10"
    ]

    for ip in fake_targets:
        packet = IP(dst=ip)/ICMP()
        send(packet, verbose=False)
        time.sleep(0.05)

    print("[*] ICMP Ping Sweep Simulation Complete.")


if __name__ == "__main__":
    print("=" * 50)
    print("Launching IDS Attack Simulation Suite")
    print("=" * 50)

    simulate_port_scan()
    time.sleep(3)

    simulate_syn_flood()
    time.sleep(3)

    simulate_icmp_sweep()

    print("=" * 50)
    print("All attack simulations completed.")
    print("=" * 50)