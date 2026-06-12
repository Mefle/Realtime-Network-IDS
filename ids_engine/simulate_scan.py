from scapy.all import IP, TCP, ICMP, send
import time
import random

TARGET_IP = "127.0.0.1"


def simulate_syn_flood():
    print("[*] Starting SYN Flood Simulation...")

    for i in range(100):
        #src_ip = f"192.168.1.{random.randint(2, 200)}"
        src_ip = f"192.168.1.9"
        dst_port = 80

        packet = IP(src=src_ip, dst=TARGET_IP) / TCP(dport=dst_port, flags="S")
        send(packet, verbose=False)

        # burst behavior
        if i % 15 == 0:
            time.sleep(0.1)

    print("[*] SYN Flood Simulation Complete.")
    

def simulate_port_scan():
    print("[*] Starting Port Scan Simulation...")

    attacker_ip = f"192.168.1.{random.randint(2, 200)}"

    for port in range(1, 40):
        packet = IP(src=attacker_ip, dst=TARGET_IP) / TCP(dport=port, flags="S")
        send(packet, verbose=False)

        time.sleep(random.uniform(0.01, 0.08))

    print("[*] Port Scan Simulation Complete.")


def simulate_icmp_sweep():
    print("[*] Starting ICMP Ping Sweep Simulation...")

    attacker_ip = f"192.168.1.{random.randint(2, 200)}"

    for i in range(1, 16):
        target_ip = f"127.0.0.{i}"

        packet = IP(src=attacker_ip, dst=target_ip) / ICMP()
        send(packet, verbose=False)
        time.sleep(0.05)

    print("[*] ICMP Ping Sweep Simulation Complete.")


if __name__ == "__main__":
    print("=" * 60)
    print("Launching IDS Attack Simulation Suite")
    print("=" * 60)

    simulate_port_scan()
    time.sleep(2)

    simulate_syn_flood()
    time.sleep(2)

    simulate_icmp_sweep()

    print("=" * 60)
    print("All attack simulations completed successfully.")
    print("=" * 60)
