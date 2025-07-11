#!/usr/bin/env python3
# NullTrace - IP Recon Tool by Nullgrimoire

import socket
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "SMB",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP"
}

def print_banner():
    banner = r"""
            ╔═╗┬ ┬┬  ┬┬  ┬┬─┐┬─┐┌─┐┌─┬┐
            ║ ╦│ ││  ││  │├┬┘├┬┘├─┤ │
            ╚═╝└─┘┴─┘┴┴─┘┴┴└─┴└─┴ ┴ ┴
       ╔═╗┌─┐┬─┐┬─┐  ▄▀▄ ▄▀▀ █▄─▄█ █▀▀
       ║  ├┤ ├┬┘├┬┘  █▀█ ▀▄▄ █─█─█ █─█
       ╚═╝└─┘┴└─┴└─  ▀─▀ ▀▀▀ ▀───▀ ▀▀▀
         ────────────────╢╣───────────────
         NullTrace – Network Recon Ritual
    """
    print(banner)
def scan_port(ip, port, timeout=1):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024).decode(errors='ignore').strip()
            except:
                banner = "No banner"
            return {
                "port": port,
                "service": COMMON_PORTS.get(port, "Unknown"),
                "banner": banner
            }
    except:
        return None

def scan_target(ip, ports):
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
    return results

def save_report(ip, data, output_file):
    report = {
        "target": ip,
        "timestamp": datetime.now().isoformat(),
        "open_ports": data
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved to {output_file}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NullTrace - Basic Network Reconnaissance Tool")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--output", default="recon.json", help="Output file (JSON)")
    parser.add_argument("--ports", nargs="*", type=int, help="Custom ports to scan")
    args = parser.parse_args()

    target_ip = args.target
    ports = args.ports if args.ports else list(COMMON_PORTS.keys())

    print(f"[*] Scanning {target_ip} on {len(ports)} ports...")
    results = scan_target(target_ip, ports)

    for r in results:
        print(f"[+] {r['port']:5}/tcp - {r['service']:8} - {r['banner']}")

    save_report(target_ip, results, args.output)

if __name__ == "__main__":
    main()
