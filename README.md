# NullTrace

> Network recon ritual tool – IP scanner, banner grabber, and hint engine for pentesters, red teamers, and OSCP labs.

## Features
- Multi-threaded port scanning
- CIDR & subnet support (e.g., `192.168.1.0/24`)
- Protocol-aware banner grabbing
- JSON and Markdown report output
- Modular hints engine via `hints.json`
- Built-in test mode for safe scanning
- Color-coded CLI output
- Robust error handling (DNS, socket, thread safety)
- Version reporting (`--version`)

## Installation
```bash
pip install .
```
Or to run manually:
```bash
git clone https://github.com/youruser/NullTrace
cd NullTrace
python3 -m nulltrace.NullTrace --target 10.10.10.10
```

## Usage Examples

### Basic Single Host
```bash
nulltrace --target 10.10.10.10
```

### CIDR Scan
```bash
nulltrace --target 192.168.1.0/24
```

### Custom Ports + Brief Output
```bash
nulltrace --target 10.0.0.5 --ports 21 22 80 443 --brief
```

### Markdown Output
```bash
nulltrace --target 10.0.0.5 --format md
```

### Test Mode
```bash
nulltrace --test
```

### Output Files
- Per host: `recon_<ip>.json`
- All results: `recon_all.json`
- Markdown summary: `recon.md`

## How Hints Work
If a banner matches any keyword in `hints.json`, a recommendation is shown:
```bash
[+] 21/tcp - FTP - vsftpd 2.3.4 (Check for backdoor CVE-2011-2523)
```
You can edit `hints.json` to expand or update detection logic.

## License
MIT License

---
Built by Nullgrimoire ☠️
