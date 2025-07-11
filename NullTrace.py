#!/usr/bin/env python3
# NullTrace - IP Recon Tool by Nullgrimoire

import argparse
import json
from datetime import datetime
from scanner import scan_target, COMMON_PORTS
from colorama import Fore, Style, init

init(autoreset=True)

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
    print(Fore.MAGENTA + banner + Style.RESET_ALL)

def save_report(ip, data, output_file):
    report = {
        "target": ip,
        "timestamp": datetime.now().isoformat(),
        "open_ports": data
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(Fore.GREEN + f"\n[+] Report saved to {output_file}" + Style.RESET_ALL)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NullTrace - Basic Network Reconnaissance Tool")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--output", default="recon.json", help="Output file (JSON)")
    parser.add_argument("--ports", nargs="*", type=int, help="Custom ports to scan")
    args = parser.parse_args()

    target_ip = args.target
    ports = args.ports if args.ports else list(COMMON_PORTS.keys())

    print(Fore.CYAN + f"[*] Scanning {target_ip} on {len(ports)} ports..." + Style.RESET_ALL)
    results = scan_target(target_ip, ports)

    for r in results:
        print(Fore.GREEN + f"[+] {r['port']:5}/tcp - {r['service']:8} - {r['banner']}" + Style.RESET_ALL)

    save_report(target_ip, results, args.output)

if __name__ == "__main__":
    main()
