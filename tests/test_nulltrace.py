import pytest
from nulltrace.scanner import scan_target, COMMON_PORTS
from nulltrace.output import save_report
from nulltrace.hints import get_hint

# Dummy IP for local tests (should be safe to scan)
DUMMY_IP = '127.0.0.1'

# Test scan_target returns a list (may be empty if no ports open)
def test_scan_target_returns_list():
    results = scan_target(DUMMY_IP, [80, 22])
    assert isinstance(results, list)

# Test get_hint returns a string
def test_get_hint_returns_string():
    hint = get_hint('OpenSSH_6.6.1')
    assert isinstance(hint, str)

# Test save_report creates a file
def test_save_report_creates_file(tmp_path):
    data = [{"port": 22, "service": "SSH", "banner": "OpenSSH_6.6.1"}]
    output_file = tmp_path / "report.json"
    save_report(DUMMY_IP, data, str(output_file))
    assert output_file.exists()
    assert output_file.read_text().startswith('{')
