import json
from pathlib import Path

DEFAULT_HINTS = {
    "vsftpd 2.3.4": "Check for backdoor CVE-2011-2523",
    "OpenSSH_6.6.1": "Check for outdated SSH version; weak algorithms may be supported",
    "Apache/2.2": "Check for default files or outdated modules",
    "MySQL": "Attempt login with default creds, then check version for vulns",
    "phpMyAdmin": "Check for default creds and known RCEs",
    "Microsoft-IIS/7.5": "Check for WebDAV and known exploits",
    "SMB": "Check for SMBv1 and EternalBlue (CVE-2017-0144)",
    "OpenSMTPD": "Check for command injection (CVE-2020-7247)"
}

HINTS_PATH = Path("hints.json")

def load_hints():
    if HINTS_PATH.exists():
        try:
            with open(HINTS_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return DEFAULT_HINTS
    return DEFAULT_HINTS

HINTS = load_hints()

def get_hint(banner: str) -> str:
    for keyword, hint in HINTS.items():
        if keyword.lower() in banner.lower():
            return hint
    return ""
