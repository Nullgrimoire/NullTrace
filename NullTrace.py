#!/usr/bin/env python3
# NullTrace - IP Recon Tool by Nullgrimoire

import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner import scan_target, COMMON_PORTS
from output import save_report
from hints import get_hint
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

def format_result(r, brief=False):
    if brief:
        return f"[+] {r['port']:5}/tcp - {r['service']:8}"
    hint = get_hint(r['banner'])
    extra = f" ({hint})" if hint else ""
    return f"[+] {r['port']:5}/tcp - {r['service']:8} - {r['banner']}{extra}"

def run_scan_for_ip(ip, ports, brief, output_path=None):
    print(Fore.CYAN + f"[*] Scanning {ip} on {len(ports)} ports..." + Style.RESET_ALL)
    results = scan_target(str(ip), ports)
    for r in results:
        print(Fore.GREEN + format_result(r, brief) + Style.RESET_ALL)
    if output_path:
        save_report(str(ip), results, output_path)
    return {"ip": str(ip), "open_ports": results}

def threaded_scan(net, ports, brief, output_template, summary_path):
    summary = []
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {
            executor.submit(run_scan_for_ip, ip, ports, brief, output_template.replace(".json", f"_{ip}.json")): ip
            for ip in net
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                summary.append(result)

    if summary_path:
        try:
            from output import write_combined_report
            write_combined_report(summary_path, summary)
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write summary: {e}" + Style.RESET_ALL)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NullTrace - Basic Network Reconnaissance Tool")
    parser.add_argument("--target", help="Target IP address, hostname, or CIDR block")
    parser.add_argument("--output", default="recon.json", help="Output file (JSON, disabled in test mode)")
    parser.add_argument("--ports", nargs="*", type=int, help="Custom ports to scan")
    parser.add_argument("--test", action="store_true", help="Run against a known safe test target (scanme.nmap.org)")
    parser.add_argument("--brief", action="store_true", help="Only show open ports without banner details")
    args = parser.parse_args()

    ports = args.ports if args.ports else list(COMMON_PORTS.keys())

    if args.test:
        target_ip = "scanme.nmap.org"
        print(Fore.YELLOW + "[*] Test mode enabled: scanning scanme.nmap.org" + Style.RESET_ALL)
        run_scan_for_ip(target_ip, ports, args.brief)
        print(Fore.YELLOW + "\n[✓] Test complete — NullTrace is working as intended." + Style.RESET_ALL)
        return

    if not args.target:
        print(Fore.RED + "[!] You must specify --target or use --test" + Style.RESET_ALL)
        return

    try:
        net = ipaddress.ip_network(args.target, strict=False)
        threaded_scan(net, ports, args.brief, args.output, "recon_all.json")
    except ValueError:
        run_scan_for_ip(args.target, ports, args.brief, args.output)

if __name__ == "__main__":
    main()
