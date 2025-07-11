import socket
from concurrent.futures import ThreadPoolExecutor
from nulltrace.banners import probe_service

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

def scan_port(ip, port, timeout=1, verify_cert=True):
    try:
        # Validate port range
        if not isinstance(port, int) or not (0 < port < 65536):
            return None
        with socket.create_connection((ip, port), timeout=timeout):
            return probe_service(ip, port, timeout, verify_cert=verify_cert)
    except (socket.timeout, socket.error, ValueError, OSError):
        # Ignore connection errors, bad ports, and timeouts
        return None
    except Exception:
        # Catch-all for any other unexpected errors
        return None

def scan_target(ip, ports, timeout=1, verify_cert=True):
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port, timeout, verify_cert=verify_cert) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
    return results
