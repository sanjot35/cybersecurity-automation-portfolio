#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple Demo: AI-Powered Threat Hunt
Shows the complete flow from natural language to attack chain visualization
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta
from typing import Any

# Fix Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

# Mock data for demonstration
MOCK_EVENTS = [
    {
        "event_name": "Process Created",
        "username": "admin",
        "sourceip": "10.0.1.50",
        "destinationip": "10.0.1.100",
        "category": "Process Execution",
        "devicetime": (datetime.now() - timedelta(hours=2)).isoformat(),
        "command_line": "powershell.exe -encodedcommand JABzAD0ATgBlAHcALQBQAFMAUwBlAHMAcwBpAG8AbgA=",
        "hostname": "WORKSTATION-01",
        "process_name": "powershell.exe"
    },
    {
        "event_name": "Network Connection",
        "username": "admin",
        "sourceip": "10.0.1.50",
        "destinationip": "10.0.1.101",
        "category": "Network Activity",
        "devicetime": (datetime.now() - timedelta(hours=2, minutes=5)).isoformat(),
        "command_line": "powershell.exe Invoke-Command -ComputerName SERVER-02 -ScriptBlock {whoami}",
        "hostname": "WORKSTATION-01",
        "process_name": "powershell.exe"
    },
    {
        "event_name": "Logon",
        "username": "admin",
        "sourceip": "10.0.1.50",
        "destinationip": "10.0.1.102",
        "category": "Authentication",
        "devicetime": (datetime.now() - timedelta(hours=1, minutes=45)).isoformat(),
        "command_line": "net use \\\\SERVER-03\\admin$ /user:admin",
        "hostname": "SERVER-03",
        "process_name": "net.exe"
    },
    {
        "event_name": "Process Created",
        "username": "admin",
        "sourceip": "10.0.1.50",
        "destinationip": "10.0.1.103",
        "category": "Process Execution",
        "devicetime": (datetime.now() - timedelta(hours=1, minutes=30)).isoformat(),
        "command_line": "powershell.exe New-PSSession -ComputerName SERVER-04",
        "hostname": "SERVER-04",
        "process_name": "powershell.exe"
    },
    {
        "event_name": "Process Created",
        "username": "admin",
        "sourceip": "10.0.1.50",
        "destinationip": "10.0.1.104",
        "category": "Process Execution",
        "devicetime": (datetime.now() - timedelta(hours=1, minutes=15)).isoformat(),
        "command_line": "powershell.exe Invoke-Mimikatz -DumpCreds",
        "hostname": "SERVER-05",
        "process_name": "powershell.exe"
    },
]


def print_header(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def print_step(step_num: int, title: str):
    """Print a step indicator"""
    print(f"\n{'─' * 80}")
    print(f"STEP {step_num}: {title}")
    print('─' * 80)


def convert_to_aql(query_text: str, days: int = 7) -> str:
    """
    Simulates LLM conversion of natural language to AQL query
    """
    print_step(1, "Converting Natural Language to SIEM Query (AQL)")
    
    print(f"📝 Input Prompt: \"{query_text}\"")
    print(f"⏱️  Time Window: Last {days} days\n")
    
    # Simulate LLM processing
    print("🤖 LLM Processing...")
    print("   - Analyzing threat hypothesis")
    print("   - Identifying key indicators: PowerShell, lateral movement")
    print("   - Mapping to QRadar AQL syntax")
    
    aql_query = f"""SELECT QIDNAME(qid) as event_name, username, sourceip, destinationip,
       CATEGORYNAME(category) as category, devicetime,
       "Command Line" as command_line, hostname, "Process Name" as process_name
FROM events
WHERE devicetime > NOW() - {days} DAYS
  AND (
    LOWER("Process Name") LIKE '%powershell%'
    OR LOWER("Command Line") LIKE '%-encodedcommand%'
    OR LOWER("Command Line") LIKE '%invoke-command%'
    OR LOWER("Command Line") LIKE '%new-pssession%'
  )
  AND (
    logontype = '3'
    OR LOWER("Command Line") LIKE '%net use%'
    OR LOWER("Command Line") LIKE '%psexec%'
  )
ORDER BY devicetime DESC"""
    
    print("\n✅ AQL Query Generated:\n")
    print("┌" + "─" * 78 + "┐")
    for line in aql_query.split('\n'):
        print(f"│ {line:<76} │")
    print("└" + "─" * 78 + "┘")
    
    return aql_query


def correlate_logs(aql_query: str) -> list[dict[str, Any]]:
    """
    Simulates executing AQL query against QRadar and correlating logs
    """
    print_step(2, "Correlating Logs from SIEM")
    
    print("🔍 Executing AQL query against IBM QRadar...")
    print("   - Initiating search job")
    print("   - Polling for results (search_id: abc-123-def)")
    print("   - Fetching event data\n")
    
    print(f"✅ Retrieved {len(MOCK_EVENTS)} matching events\n")
    
    print("📊 Event Summary:")
    print(f"   • Total Events: {len(MOCK_EVENTS)}")
    print(f"   • Unique Hosts: {len(set(e['hostname'] for e in MOCK_EVENTS))}")
    print(f"   • Unique Users: {len(set(e['username'] for e in MOCK_EVENTS))}")
    print(f"   • Source IPs: {len(set(e['sourceip'] for e in MOCK_EVENTS))}")
    print(f"   • Destination IPs: {len(set(e['destinationip'] for e in MOCK_EVENTS))}")
    
    return MOCK_EVENTS


def detect_anomalies(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Simulates anomaly detection on correlated events
    """
    print_step(3, "Identifying Anomalies")
    
    print("🔬 Running anomaly detection algorithms...")
    print("   - Z-score frequency analysis")
    print("   - Rare process detection")
    print("   - Off-hours activity detection")
    print("   - High fan-out detection\n")
    
    anomalies = [
        {
            "event": events[0],
            "reason": "Encoded PowerShell command detected (Base64 obfuscation)",
            "severity": "high",
            "zscore": 3.2
        },
        {
            "event": events[1],
            "reason": "Remote PowerShell execution via Invoke-Command",
            "severity": "high",
            "zscore": 2.8
        },
        {
            "event": events[2],
            "reason": "High fan-out: 10.0.1.50 communicated with 5 distinct destinations",
            "severity": "high"
        },
        {
            "event": events[4],
            "reason": "Credential dumping tool detected (Mimikatz pattern)",
            "severity": "critical",
            "zscore": 4.5
        }
    ]
    
    print(f"⚠️  Flagged {len(anomalies)} anomalous events:\n")
    
    for i, anomaly in enumerate(anomalies, 1):
        severity_icon = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢"
        }.get(anomaly["severity"], "⚪")
        
        print(f"{severity_icon} Anomaly #{i} [{anomaly['severity'].upper()}]")
        print(f"   Host: {anomaly['event']['hostname']}")
        print(f"   User: {anomaly['event']['username']}")
        print(f"   Reason: {anomaly['reason']}")
        if anomaly.get("zscore"):
            print(f"   Z-Score: {anomaly['zscore']}")
        print()
    
    return anomalies


def build_attack_chain(events: list[dict[str, Any]], anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Simulates building MITRE ATT&CK mapped attack chain
    """
    print_step(4, "Visualizing Attack Chain")
    
    print("🗺️  Mapping events to MITRE ATT&CK framework...")
    print("   - Pattern matching against technique database")
    print("   - Clustering by tactic phase")
    print("   - Building kill chain sequence\n")
    
    attack_chain = {
        "steps": [
            {
                "step": 1,
                "tactic": "Execution",
                "techniques": [
                    {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "description": "Adversary executed PowerShell commands",
                        "evidence": ["WORKSTATION-01", "SERVER-04"]
                    }
                ],
                "source_hosts": ["10.0.1.50"],
                "dest_hosts": ["10.0.1.100", "10.0.1.101"],
                "timestamp_first": events[0]["devicetime"],
                "timestamp_last": events[1]["devicetime"]
            },
            {
                "step": 2,
                "tactic": "Lateral Movement",
                "techniques": [
                    {
                        "technique_id": "T1021.006",
                        "technique_name": "Windows Remote Management",
                        "description": "PowerShell remoting via WinRM",
                        "evidence": ["SERVER-02", "SERVER-04"]
                    },
                    {
                        "technique_id": "T1021.002",
                        "technique_name": "SMB/Windows Admin Shares",
                        "description": "Network share access for lateral movement",
                        "evidence": ["SERVER-03"]
                    }
                ],
                "source_hosts": ["10.0.1.50"],
                "dest_hosts": ["10.0.1.101", "10.0.1.102", "10.0.1.103"],
                "timestamp_first": events[1]["devicetime"],
                "timestamp_last": events[3]["devicetime"]
            },
            {
                "step": 3,
                "tactic": "Credential Access",
                "techniques": [
                    {
                        "technique_id": "T1003.001",
                        "technique_name": "LSASS Memory",
                        "description": "Credential dumping via Mimikatz",
                        "evidence": ["SERVER-05"]
                    }
                ],
                "source_hosts": ["10.0.1.50"],
                "dest_hosts": ["10.0.1.104"],
                "timestamp_first": events[4]["devicetime"],
                "timestamp_last": events[4]["devicetime"]
            }
        ],
        "source_ips": ["10.0.1.50"],
        "affected_hosts": ["WORKSTATION-01", "SERVER-02", "SERVER-03", "SERVER-04", "SERVER-05"],
        "techniques_summary": ["T1059.001", "T1021.006", "T1021.002", "T1003.001"]
    }
    
    print("✅ Attack Chain Constructed:\n")
    print("┌" + "─" * 78 + "┐")
    print("│" + " " * 25 + "MITRE ATT&CK KILL CHAIN" + " " * 30 + "│")
    print("├" + "─" * 78 + "┤")
    
    for step in attack_chain["steps"]:
        print(f"│ Step {step['step']}: {step['tactic']:<68} │")
        for tech in step["techniques"]:
            print(f"│   └─ {tech['technique_id']}: {tech['technique_name']:<58} │")
        print("│" + " " * 78 + "│")
    
    print("├" + "─" * 78 + "┤")
    print(f"│ 🎯 Attack Origin: {attack_chain['source_ips'][0]:<60} │")
    print(f"│ 💻 Affected Hosts: {len(attack_chain['affected_hosts'])} systems compromised{' ' * 38} │")
    print(f"│ 🔍 Techniques Used: {', '.join(attack_chain['techniques_summary']):<55} │")
    print("└" + "─" * 78 + "┘")
    
    return attack_chain


def generate_summary(query_text: str, aql_query: str, events: list[dict], 
                    anomalies: list[dict], attack_chain: dict):
    """
    Generate final summary of the threat hunt
    """
    print_header("THREAT HUNT SUMMARY")
    
    print(f"🔍 Original Query: \"{query_text}\"\n")
    
    print("📈 Results:")
    print(f"   • AQL Query: Generated successfully")
    print(f"   • Events Retrieved: {len(events)}")
    print(f"   • Anomalies Detected: {len(anomalies)}")
    print(f"   • Attack Chain Steps: {len(attack_chain['steps'])}")
    print(f"   • MITRE Techniques: {len(attack_chain['techniques_summary'])}\n")
    
    print("🚨 Key Findings:")
    print(f"   • Lateral movement detected from {attack_chain['source_ips'][0]}")
    print(f"   • {len(attack_chain['affected_hosts'])} systems compromised")
    print(f"   • Credential theft attempt identified (Mimikatz)")
    print(f"   • PowerShell remoting used for propagation\n")
    
    print("🎯 Recommended Actions:")
    print("   1. Isolate source IP: 10.0.1.50")
    print("   2. Reset credentials for user 'admin'")
    print("   3. Scan affected hosts for persistence mechanisms")
    print("   4. Review PowerShell execution policies")
    print("   5. Enable enhanced logging for lateral movement detection\n")
    
    print("📊 Confidence Score: 87% (High)")
    print("⏱️  Analysis completed in 2.3 seconds")


async def run_demo():
    """
    Main demo execution
    """
    print_header("AI-POWERED THREAT HUNT DEMO")
    print("Demonstrating: Natural Language → SIEM Query → Log Correlation → Anomaly Detection → Attack Chain\n")
    
    # Get user input
    print("Please enter your threat hunting query:")
    print("Example: Find suspicious lateral movement using PowerShell in last 7 days\n")
    query_text = input("Your query: ").strip()
    
    if not query_text:
        query_text = "Find suspicious lateral movement using PowerShell in last 7 days"
        print(f"Using default query: {query_text}\n")
    
    # Ask for time window
    days_input = input("Time window in days (default: 7): ").strip()
    days = int(days_input) if days_input.isdigit() else 7
    
    print()  # Add spacing
    
    # Step 1: Convert to AQL
    aql_query = convert_to_aql(query_text, days)
    await asyncio.sleep(1)  # Simulate processing time
    
    # Step 2: Correlate logs
    events = correlate_logs(aql_query)
    await asyncio.sleep(1)
    
    # Step 3: Detect anomalies
    anomalies = detect_anomalies(events)
    await asyncio.sleep(1)
    
    # Step 4: Build attack chain
    attack_chain = build_attack_chain(events, anomalies)
    await asyncio.sleep(1)
    
    # Final summary
    generate_summary(query_text, aql_query, events, anomalies, attack_chain)
    
    print("\n" + "=" * 80)
    print("Demo completed successfully! 🎉")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(run_demo())

# Made with Bob
