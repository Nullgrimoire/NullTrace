import socket
from concurrent.futures import ThreadPoolExecutor
from banners import probe_service

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

def scan_port(ip, port, timeout=1):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return probe_service(ip, port, timeout)
    except:
        return None

def scan_target(ip, ports, timeout=1):
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port, timeout) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
    return results
