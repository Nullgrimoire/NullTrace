import json
from datetime import datetime
from colorama import Fore, Style

def save_report(ip, data, output_file):
    report = {
        "target": ip,
        "timestamp": datetime.now().isoformat(),
        "open_ports": data
    }
    try:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(Fore.GREEN + f"\n[+] Report saved to {output_file}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to save report: {e}" + Style.RESET_ALL)

def write_combined_report(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(Fore.GREEN + f"\n[+] Combined report saved to {path}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to write combined report: {e}" + Style.RESET_ALL)

def write_markdown_report(path, data):
    try:
        with open(path, "w") as f:
            f.write(f"# NullTrace Scan Report\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            for host in data:
                f.write(f"## Target: {host['ip']}\n")
                if not host['open_ports']:
                    f.write("No open ports found.\n\n")
                    continue
                f.write("| Port | Service | Banner |\n")
                f.write("|------|---------|--------|\n")
                for port in host['open_ports']:
                    p = port['port']
                    s = port['service']
                    b = port['banner'].replace("|", "/")
                    f.write(f"| {p}/tcp | {s} | {b} |\n")
                f.write("\n")
        print(Fore.GREEN + f"[+] Markdown report saved to {path}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to write markdown report: {e}" + Style.RESET_ALL)
