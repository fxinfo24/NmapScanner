import pytest
from unittest.mock import patch, MagicMock
import asyncio
import json
from NmapScanner import (
    validate_ip,
    validate_port_range,
    validate_target,
    cached_scan,
    async_scan,
    save_results,
    perform_scan,
)

# Mocking the nmap.PortScanner class
@pytest.fixture
def mock_nmap_scanner():
    with patch("nmap.PortScanner") as mock_scanner:
        yield mock_scanner

# Mocking asyncio.to_thread for async scanning
@pytest.fixture
def mock_async_to_thread():
    with patch("asyncio.to_thread") as mock_to_thread:
        yield mock_to_thread

# Mocking file operations for save_results
@pytest.fixture
def mock_file_operations():
    with patch("builtins.open", create=True) as mock_open:
        yield mock_open

# Parameterized test for validate_ip function
@pytest.mark.parametrize("ip, expected", [
    ("192.168.1.1", "192.168.1.1"),
    ("10.0.0.1", "10.0.0.1"),
    ("256.256.256.256", pytest.raises(argparse.ArgumentTypeError)),
    ("invalid_ip", pytest.raises(argparse.ArgumentTypeError)),
])
def test_validate_ip(ip, expected):
    if isinstance(expected, pytest.raises):
        with expected:
            validate_ip(ip)
    else:
        assert validate_ip(ip) == expected

# Parameterized test for validate_port_range function
@pytest.mark.parametrize("port_range, expected", [
    ("20-80", "20-80"),
    ("1-65535", "1-65535"),
    ("0-100", pytest.raises(argparse.ArgumentTypeError)),
    ("100-50", pytest.raises(argparse.ArgumentTypeError)),
])
def test_validate_port_range(port_range, expected):
    if isinstance(expected, pytest.raises):
        with expected:
            validate_port_range(port_range)
    else:
        assert validate_port_range(port_range) == expected

# Parameterized test for validate_target function
@pytest.mark.parametrize("target, expected", [
    ("192.168.1.1", "192.168.1.1"),
    ("192.168.1.0/24", "192.168.1.0/24"),
    ("invalid_target", pytest.raises(argparse.ArgumentTypeError)),
])
def test_validate_target(target, expected):
    if isinstance(expected, pytest.raises):
        with expected:
            validate_target(target)
    else:
        assert validate_target(target) == expected

# Test for cached_scan function
def test_cached_scan(mock_nmap_scanner):
    mock_instance = mock_nmap_scanner.return_value
    mock_instance.scan.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}

    result = cached_scan("192.168.1.1", "80", "syn")
    assert result == {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}
    mock_instance.scan.assert_called_once_with(hosts="192.168.1.1", ports="80", arguments="-sS -T4 -v")

# Test for async_scan function
@pytest.mark.asyncio
async def test_async_scan(mock_async_to_thread, mock_nmap_scanner):
    mock_instance = mock_nmap_scanner.return_value
    mock_instance.scan.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}
    mock_async_to_thread.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}

    targets = ["192.168.1.1", "192.168.1.2"]
    results = await async_scan(targets, "80", "syn")
    assert len(results) == 2
    assert results[0] == {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}
    assert results[1] == {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}

# Test for save_results function
@pytest.mark.parametrize("format, expected_extension", [
    ("json", ".json"),
    ("csv", ".csv"),
])
def test_save_results(mock_file_operations, format, expected_extension):
    results = {"192.168.1.1": {"tcp": {80: {"state": "open", "name": "http"}}}}
    save_results(results, "output", format)

    mock_file_operations.assert_called_once_with(f"output{expected_extension}", "w")
    if format == "json":
        mock_file_operations().write.assert_called_once_with(json.dumps(results, indent=4))
    elif format == "csv":
        mock_file_operations().write.assert_called()  # CSV writing logic is more complex

# Test for perform_scan function
def test_perform_scan(mock_nmap_scanner):
    mock_instance = mock_nmap_scanner.return_value
    mock_instance.scan.return_value = {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}

    results = perform_scan("192.168.1.1", "80", "syn")
    assert results == {"192.168.1.1": {"scan": {"192.168.1.1": {"tcp": {80: {"state": "open"}}}}}}
    mock_instance.scan.assert_called_once_with(hosts="192.168.1.1", ports="80", arguments="-sS -T4 -v")