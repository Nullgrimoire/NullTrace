import socket
import ssl
import re
import requests

def probe_service(ip, port, timeout=1, verify_cert=True):
    try:
        if port == 21:
            return probe_ftp(ip, port, timeout)
        elif port == 22:
            return probe_ssh(ip, port, timeout)
        elif port in (80, 8080):
            return probe_http(ip, port, timeout, ssl_enabled=False, verify_cert=verify_cert)
        elif port == 443:
            return probe_http(ip, port, timeout, ssl_enabled=True, verify_cert=verify_cert)
        elif port == 3306:
            return probe_mysql(ip, port, timeout)
        else:
            return generic_banner(ip, port, timeout)
    except Exception as e:
        return {
            "port": port,
            "service": "Unknown",
            "banner": f"Error: {str(e)}"
        }

def generic_banner(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return {
                "port": port,
                "service": "Unknown",
                "banner": banner or "No banner"
            }
    except Exception as e:
        return {
            "port": port,
            "service": "Unknown",
            "banner": f"Error: {str(e)}"
        }

def probe_ftp(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return {
                "port": port,
                "service": "FTP",
                "banner": banner or "No banner"
            }
    except Exception as e:
        return {
            "port": port,
            "service": "FTP",
            "banner": f"Error: {str(e)}"
        }

def probe_ssh(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return {
                "port": port,
                "service": "SSH",
                "banner": banner or "No banner"
            }
    except Exception as e:
        return {
            "port": port,
            "service": "SSH",
            "banner": f"Error: {str(e)}"
        }

def probe_http(ip, port, timeout, ssl_enabled, verify_cert=True):
    try:
        proto = "https" if ssl_enabled else "http"
        url = f"{proto}://{ip}:{port}"
        response = requests.get(url, timeout=timeout, verify=verify_cert)
        server = response.headers.get("Server", "Unknown")
        title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else "No title"
        return {
            "port": port,
            "service": "HTTPS" if ssl_enabled else "HTTP",
            "banner": f"{server} | {title}"
        }
    except Exception as e:
        return {
            "port": port,
            "service": "HTTPS" if ssl_enabled else "HTTP",
            "banner": f"Error: {str(e)}"
        }

def probe_mysql(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return {
                "port": port,
                "service": "MySQL",
                "banner": banner or "No banner"
            }
    except Exception as e:
        return {
            "port": port,
            "service": "MySQL",
            "banner": f"Error: {str(e)}"
        }
