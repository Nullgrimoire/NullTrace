import pytest
import socket
from nulltrace.scanner import scan_port, scan_target, COMMON_PORTS
from nulltrace.output import save_report, write_combined_report, write_markdown_report
from nulltrace.hints import get_hint, DEFAULT_HINTS
from nulltrace.banners import probe_service, generic_banner, probe_ftp, probe_ssh, probe_http, probe_mysql

# Dummy IP for local tests (should be safe to scan)
DUMMY_IP = '127.0.0.1'

# --- Scanner Tests ---
def test_scan_port_valid_closed():
    # Should return None for closed port
    assert scan_port(DUMMY_IP, 1) is None

def test_scan_port_invalid_port():
    # Should return None for invalid port
    assert scan_port(DUMMY_IP, -1) is None
    assert scan_port(DUMMY_IP, 70000) is None
    assert scan_port(DUMMY_IP, 'notaport') is None

def test_scan_target_mixed_ports():
    results = scan_target(DUMMY_IP, [1, 80, 65535, -1])
    assert isinstance(results, list)

# --- Banner Grabber Tests ---
def test_probe_service_closed_port():
    # Should return error dict for closed port
    result = probe_service(DUMMY_IP, 1)
    assert isinstance(result, dict)
    assert 'Error' in result['banner'] or result['banner'] == 'No banner'

def test_generic_banner_closed():
    result = generic_banner(DUMMY_IP, 1, 1)
    assert isinstance(result, dict)
    assert 'Error' in result['banner'] or result['banner'] == 'No banner'

def test_probe_ftp_closed():
    result = probe_ftp(DUMMY_IP, 1, 1)
    assert isinstance(result, dict)
    assert 'Error' in result['banner'] or result['banner'] == 'No banner'

def test_probe_ssh_closed():
    result = probe_ssh(DUMMY_IP, 1, 1)
    assert isinstance(result, dict)
    assert 'Error' in result['banner'] or result['banner'] == 'No banner'

def test_probe_http_closed():
    result = probe_http(DUMMY_IP, 1, 1, False)
    assert isinstance(result, dict)
    assert 'Error' in result['banner'] or result['banner'] == 'No banner'

def test_probe_mysql_closed():
    result = probe_mysql(DUMMY_IP, 1, 1)
    assert isinstance(result, dict)
    assert 'Error' in result['banner'] or result['banner'] == 'No banner'

# --- Hints Engine Tests ---
def test_get_hint_match():
    for banner in DEFAULT_HINTS.keys():
        assert get_hint(banner) == DEFAULT_HINTS[banner]

def test_get_hint_no_match():
    assert get_hint('TotallyUnknownBanner') == ''

# --- Output Tests ---
def test_save_report_creates_file(tmp_path):
    data = [{"port": 22, "service": "SSH", "banner": "OpenSSH_6.6.1"}]
    output_file = tmp_path / "report.json"
    save_report(DUMMY_IP, data, str(output_file))
    assert output_file.exists()
    assert output_file.read_text().startswith('{')

def test_write_combined_report(tmp_path):
    data = [{"ip": DUMMY_IP, "open_ports": []}]
    output_file = tmp_path / "combined.json"
    write_combined_report(str(output_file), data)
    assert output_file.exists()
    assert output_file.read_text().startswith('[')

def test_write_markdown_report(tmp_path):
    data = [{"ip": DUMMY_IP, "open_ports": []}]
    output_file = tmp_path / "report.md"
    write_markdown_report(str(output_file), data)
    assert output_file.exists()
    assert output_file.read_text().startswith('# NullTrace Scan Report')

# --- DNS Resolution Error Handling ---
def test_dns_resolution_error(monkeypatch):
    def fake_gethostbyname(ip):
        raise socket.gaierror
    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)
    from nulltrace.NullTrace import run_scan_for_ip
    result = run_scan_for_ip("notarealhost.local", [80], False)
    assert result["error"] == "DNS resolution failed"
