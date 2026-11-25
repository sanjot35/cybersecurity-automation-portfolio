"""
tests/conftest.py — Pytest fixtures for threat hunt testing

Provides realistic sample events and anomalies for all test modules.
"""

import pytest
import sys
import os

# Add parent directory to path to import backend module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.anomaly import AnomalyDetector


@pytest.fixture
def sample_events():
    """
    20 realistic mock QRadar events covering:
    - PowerShell execution (T1059.001)
    - PSExec lateral movement (T1570)
    - Mimikatz credential access (T1003.001)
    - Off-hours activity
    - High fan-out patterns
    - Rare process executions
    """
    return [
        # PowerShell execution events (high frequency from user1)
        {
            "event_name": "Process Created",
            "username": "user1",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.1.50",
            "category": "Execution",
            "devicetime": "2026-05-28T14:30:00",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File script.ps1",
            "hostname": "WORKSTATION-01",
            "process_name": "powershell.exe",
        },
        {
            "event_name": "Process Created",
            "username": "user1",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.1.51",
            "category": "Execution",
            "devicetime": "2026-05-28T14:31:00",
            "command_line": "powershell.exe -EncodedCommand aQBlAHgA",
            "hostname": "WORKSTATION-01",
            "process_name": "powershell.exe",
        },
        {
            "event_name": "Process Created",
            "username": "user1",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.1.52",
            "category": "Execution",
            "devicetime": "2026-05-28T14:32:00",
            "command_line": "powershell.exe Invoke-Command -ComputerName SERVER-01",
            "hostname": "WORKSTATION-01",
            "process_name": "powershell.exe",
        },
        {
            "event_name": "Process Created",
            "username": "user1",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.1.53",
            "category": "Execution",
            "devicetime": "2026-05-28T14:33:00",
            "command_line": "powershell.exe -Command Get-Process",
            "hostname": "WORKSTATION-01",
            "process_name": "powershell.exe",
        },
        {
            "event_name": "Process Created",
            "username": "user1",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.1.54",
            "category": "Execution",
            "devicetime": "2026-05-28T14:34:00",
            "command_line": "powershell.exe -NoProfile -WindowStyle Hidden",
            "hostname": "WORKSTATION-01",
            "process_name": "powershell.exe",
        },
        {
            "event_name": "Process Created",
            "username": "user1",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.1.55",
            "category": "Execution",
            "devicetime": "2026-05-28T14:35:00",
            "command_line": "powershell.exe -Command Invoke-Expression",
            "hostname": "WORKSTATION-01",
            "process_name": "powershell.exe",
        },
        # PSExec lateral movement
        {
            "event_name": "Remote Execution",
            "username": "admin",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.2.10",
            "category": "Lateral Movement",
            "devicetime": "2026-05-28T15:00:00",
            "command_line": "psexec.exe \\\\SERVER-02 -u admin -p pass cmd.exe",
            "hostname": "SERVER-02",
            "process_name": "psexec.exe",
        },
        {
            "event_name": "Remote Execution",
            "username": "admin",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.2.11",
            "category": "Lateral Movement",
            "devicetime": "2026-05-28T15:01:00",
            "command_line": "psexec.exe \\\\SERVER-03 cmd.exe",
            "hostname": "SERVER-03",
            "process_name": "psexec.exe",
        },
        # Mimikatz credential dumping (off-hours)
        {
            "event_name": "Credential Access",
            "username": "admin",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.2.10",
            "category": "Credential Access",
            "devicetime": "2026-05-28T03:15:00",
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "hostname": "SERVER-02",
            "process_name": "mimikatz.exe",
        },
        {
            "event_name": "LSASS Access",
            "username": "admin",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.2.10",
            "category": "Credential Access",
            "devicetime": "2026-05-28T03:16:00",
            "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
            "hostname": "SERVER-02",
            "process_name": "procdump.exe",
        },
        # Normal activity from user2 (low frequency)
        {
            "event_name": "Process Created",
            "username": "user2",
            "sourceip": "10.0.1.101",
            "destinationip": None,
            "category": "Execution",
            "devicetime": "2026-05-28T10:00:00",
            "command_line": "chrome.exe",
            "hostname": "WORKSTATION-02",
            "process_name": "chrome.exe",
        },
        {
            "event_name": "Process Created",
            "username": "user2",
            "sourceip": "10.0.1.101",
            "destinationip": None,
            "category": "Execution",
            "devicetime": "2026-05-28T10:05:00",
            "command_line": "outlook.exe",
            "hostname": "WORKSTATION-02",
            "process_name": "outlook.exe",
        },
        # Rare process execution
        {
            "event_name": "Process Created",
            "username": "user3",
            "sourceip": "10.0.1.102",
            "destinationip": None,
            "category": "Execution",
            "devicetime": "2026-05-28T11:00:00",
            "command_line": "suspicious_tool.exe --dump-creds",
            "hostname": "WORKSTATION-03",
            "process_name": "suspicious_tool.exe",
        },
        # High fan-out: single source hitting many destinations
        {
            "event_name": "Network Connection",
            "username": "scanner",
            "sourceip": "10.0.1.200",
            "destinationip": "10.0.2.1",
            "category": "Discovery",
            "devicetime": "2026-05-28T16:00:00",
            "command_line": None,
            "hostname": "SCANNER-01",
            "process_name": "nmap.exe",
        },
        {
            "event_name": "Network Connection",
            "username": "scanner",
            "sourceip": "10.0.1.200",
            "destinationip": "10.0.2.2",
            "category": "Discovery",
            "devicetime": "2026-05-28T16:00:01",
            "command_line": None,
            "hostname": "SCANNER-01",
            "process_name": "nmap.exe",
        },
        {
            "event_name": "Network Connection",
            "username": "scanner",
            "sourceip": "10.0.1.200",
            "destinationip": "10.0.2.3",
            "category": "Discovery",
            "devicetime": "2026-05-28T16:00:02",
            "command_line": None,
            "hostname": "SCANNER-01",
            "process_name": "nmap.exe",
        },
        {
            "event_name": "Network Connection",
            "username": "scanner",
            "sourceip": "10.0.1.200",
            "destinationip": "10.0.2.4",
            "category": "Discovery",
            "devicetime": "2026-05-28T16:00:03",
            "command_line": None,
            "hostname": "SCANNER-01",
            "process_name": "nmap.exe",
        },
        {
            "event_name": "Network Connection",
            "username": "scanner",
            "sourceip": "10.0.1.200",
            "destinationip": "10.0.2.5",
            "category": "Discovery",
            "devicetime": "2026-05-28T16:00:04",
            "command_line": None,
            "hostname": "SCANNER-01",
            "process_name": "nmap.exe",
        },
        {
            "event_name": "Network Connection",
            "username": "scanner",
            "sourceip": "10.0.1.200",
            "destinationip": "10.0.2.6",
            "category": "Discovery",
            "devicetime": "2026-05-28T16:00:05",
            "command_line": None,
            "hostname": "SCANNER-01",
            "process_name": "nmap.exe",
        },
        # Off-hours activity (late night)
        {
            "event_name": "Process Created",
            "username": "user4",
            "sourceip": "10.0.1.103",
            "destinationip": None,
            "category": "Execution",
            "devicetime": "2026-05-28T23:45:00",
            "command_line": "cmd.exe /c whoami",
            "hostname": "WORKSTATION-04",
            "process_name": "cmd.exe",
        },
    ]


@pytest.fixture
def sample_anomalies(sample_events):
    """
    Generate anomalies from sample_events using the real AnomalyDetector.
    
    This fixture depends on sample_events and processes them through
    the actual anomaly detection logic to produce realistic test data.
    """
    detector = AnomalyDetector()
    anomalies = detector.detect(sample_events)
    return anomalies

# Made with Bob
