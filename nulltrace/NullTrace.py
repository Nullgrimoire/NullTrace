#!/usr/bin/env python3
# NullTrace - IP Recon Tool by Nullgrimoire

import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from nulltrace.scanner import scan_target, COMMON_PORTS
from nulltrace.output import save_report, write_combined_report, write_markdown_report
from nulltrace.hints import get_hint
from nulltrace import __version__
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
    try:
        resolved_ip = socket.gethostbyname(ip)
    except socket.gaierror:
        print(Fore.RED + f"[!] Could not resolve hostname: {ip}" + Style.RESET_ALL)
        return {"ip": ip, "open_ports": [], "error": "DNS resolution failed"}
    print(Fore.CYAN + f"[*] Scanning {resolved_ip} on {len(ports)} ports..." + Style.RESET_ALL)
    results = scan_target(str(resolved_ip), ports)
    for r in results:
        print(Fore.GREEN + format_result(r, brief) + Style.RESET_ALL)
    if output_path:
        save_report(str(resolved_ip), results, output_path)
    return {"ip": str(resolved_ip), "open_ports": results}

def threaded_scan(net, ports, brief, output_template, summary_path, md_path=None):
    summary = []
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {
            executor.submit(run_scan_for_ip, ip, ports, brief, output_template.replace(".json", f"_{ip}.json")): ip
            for ip in net
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    summary.append(result)
            except Exception as e:
                ip = futures[future]
                print(Fore.RED + f"[!] Scan failed for {ip}: {e}" + Style.RESET_ALL)
                summary.append({"ip": str(ip), "open_ports": [], "error": str(e)})

    if summary_path:
        write_combined_report(summary_path, summary)
    if md_path:
        write_markdown_report(md_path, summary)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NullTrace - Basic Network Reconnaissance Tool")
    parser.add_argument("--target", help="Target IP address, hostname, or CIDR block")
    parser.add_argument("--output", default="recon.json", help="Output file (JSON, disabled in test mode)")
    parser.add_argument("--ports", nargs="*", type=int, help="Custom ports to scan")
    parser.add_argument("--test", action="store_true", help="Run against a known safe test target (scanme.nmap.org)")
    parser.add_argument("--brief", action="store_true", help="Only show open ports without banner details")
    parser.add_argument("--format", choices=["json", "md"], help="Output format for combined report")
    parser.add_argument("--version", action="store_true", help="Show NullTrace version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"NullTrace version: {__version__}")
        return

    ports = args.ports if args.ports else list(COMMON_PORTS.keys())

    if args.test:
        target_ip = "scanme.nmap.org"
        print(Fore.YELLOW + "[*] Test mode enabled: scanning scanme.nmap.org" + Style.RESET_ALL)
        result = run_scan_for_ip(target_ip, ports, args.brief)
        print(Fore.YELLOW + "\n[✓] Test complete — NullTrace is working as intended." + Style.RESET_ALL)
        if args.format == "md":
            write_markdown_report("recon.md", [result])
        return

    if not args.target:
        print(Fore.RED + "[!] You must specify --target or use --test" + Style.RESET_ALL)
        return

    try:
        net = ipaddress.ip_network(args.target, strict=False)
        md_path = "recon.md" if args.format == "md" else None
        threaded_scan(net, ports, args.brief, args.output, "recon_all.json", md_path)
    except ValueError:
        result = run_scan_for_ip(args.target, ports, args.brief, args.output)
        if args.format == "md":
            write_markdown_report("recon.md", [result])

if __name__ == "__main__":
    main()
