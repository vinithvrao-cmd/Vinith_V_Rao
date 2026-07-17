#!/usr/bin/env python3
import socket
import sys
import re
from datetime import datetime

# Formatting colors for Kali Linux Terminal
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

def print_banner():
    print(BLUE + "=" * 60 + RESET)
    print(GREEN + "    SECURECORE: NETWORK SCANNER & LOG ANALYZER ENGINE    " + RESET)
    print(BLUE + "=" * 60 + RESET)
    print(f"Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

def scan_target(target_ip):
    """Offensive Module: Performs a multi-port TCP handshake scan."""
    print(BLUE + f"[*] Initiating TCP Port Scan on target: {target_ip}" + RESET)
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print(RED + "[!] Error: Invalid IP address target." + RESET)
        return

    open_ports = []
    for port, service in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(GREEN + f"  [+] Port {port:<5} [OPEN]  --> Service: {service}" + RESET)
            open_ports.append(port)
        s.close()
        
    if not open_ports:
        print(YELLOW + "  [-] No common open ports discovered." + RESET)
    print(BLUE + "[*] Scan complete.\n" + RESET)

def analyze_auth_logs(log_path="/var/log/auth.log"):
    """Defensive Module: Parses Linux system logs to discover SSH brute-force attacks."""
    print(BLUE + f"[*] Initiating Log Analysis Engine on: {log_path}" + RESET)
    failed_attempts = {}
    threshold = 5

    try:
        with open(log_path, 'r') as file:
            for line in file:
                if "Failed password for" in line:
                    ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        print(GREEN + f"[+] Log Analysis Complete. Analyzing Thresholds (> {threshold} attempts)..." + RESET)
        malicious_activity_found = False
        
        for ip, count in failed_attempts.items():
            if count > threshold:
                print(RED + f"  [ALERT] Potential SSH Brute-Force Detected! Source IP: {ip} | Failed Attempts: {count}" + RESET)
                malicious_activity_found = True
                
        if not malicious_activity_found:
            print(GREEN + "  [-] No anomalous authentication anomalies detected." + RESET)

    except FileNotFoundError:
        print(RED + f"[!] Error: Target log file '{log_path}' not found." + RESET)
    print(BLUE + "=" * 60 + RESET)

if __name__ == "__main__":
    print_banner()
    
    print("Select Mode:")
    print("1. Offensive Module (Target Port Scanner)")
    print("2. Defensive Module (Auth Log Threat Hunting)")
    print("3. Full Engine Audit (Both)")
    
    choice = input("\nEnter option (1-3): ").strip()
    
    if choice in ['1', '3']:
        target = input("Enter target IP to scan (e.g., 127.0.0.1): ").strip()
        scan_target(target)
        
    if choice in ['2', '3']:
        log_file = input("Enter log file path [Default: /var/log/auth.log]: ").strip()
        if not log_file:
            log_file = "/var/log/auth.log"
        analyze_auth_logs(log_file)
