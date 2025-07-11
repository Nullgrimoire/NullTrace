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
