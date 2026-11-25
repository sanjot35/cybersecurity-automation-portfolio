#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Intelligent Demo: AI-Powered Threat Hunt
Dynamically generates responses based on user input query
"""

import asyncio
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List
import re

# Fix Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')


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


def analyze_query(query_text: str) -> Dict[str, Any]:
    """
    Analyze the user query to determine threat type and generate appropriate response
    """
    query_lower = query_text.lower()
    
    # Detect threat type based on keywords
    threat_profile = {
        "type": "generic",
        "indicators": [],
        "tactics": [],
        "techniques": []
    }
    
    # PowerShell / Lateral Movement
    if any(k in query_lower for k in ["powershell", "lateral", "movement", "psexec", "winrm"]):
        threat_profile["type"] = "lateral_movement"
        threat_profile["indicators"] = ["powershell", "remote execution", "network logon"]
        threat_profile["tactics"] = ["Execution", "Lateral Movement", "Credential Access"]
        threat_profile["techniques"] = ["T1059.001", "T1021.006", "T1021.002", "T1003.001"]
    
    # Malicious IPs / Network threats
    elif any(k in query_lower for k in ["malicious ip", "suspicious ip", "threat ip", "bad ip", "c2", "command and control"]):
        threat_profile["type"] = "malicious_ips"
        threat_profile["indicators"] = ["known malicious IPs", "C2 communication", "data exfiltration"]
        threat_profile["tactics"] = ["Command and Control", "Exfiltration", "Initial Access"]
        threat_profile["techniques"] = ["T1071.001", "T1041", "T1566.001"]
    
    # Ransomware
    elif any(k in query_lower for k in ["ransom", "encrypt", "crypto", "shadow copy"]):
        threat_profile["type"] = "ransomware"
        threat_profile["indicators"] = ["file encryption", "shadow copy deletion", "backup deletion"]
        threat_profile["tactics"] = ["Impact", "Defense Evasion", "Execution"]
        threat_profile["techniques"] = ["T1486", "T1490", "T1059.001"]
    
    # Privilege Escalation
    elif any(k in query_lower for k in ["privilege", "escalation", "elevation", "admin"]):
        threat_profile["type"] = "privilege_escalation"
        threat_profile["indicators"] = ["token manipulation", "UAC bypass", "scheduled tasks"]
        threat_profile["tactics"] = ["Privilege Escalation", "Persistence", "Defense Evasion"]
        threat_profile["techniques"] = ["T1134", "T1548.002", "T1053.005"]
    
    # Data Exfiltration
    elif any(k in query_lower for k in ["exfil", "data theft", "data transfer", "upload"]):
        threat_profile["type"] = "exfiltration"
        threat_profile["indicators"] = ["large data transfers", "unusual protocols", "cloud uploads"]
        threat_profile["tactics"] = ["Exfiltration", "Collection", "Command and Control"]
        threat_profile["techniques"] = ["T1041", "T1567", "T1071"]
    
    return threat_profile


def generate_aql(query_text: str, days: int, threat_profile: Dict) -> str:
    """
    Generate AQL query based on threat profile
    """
    print_step(1, "Converting Natural Language to SIEM Query (AQL)")
    
    print(f"📝 Input Prompt: \"{query_text}\"")
    print(f"⏱️  Time Window: Last {days} days\n")
    
    print("🤖 Watsonx AI Processing...")
    print(f"   - Analyzing threat hypothesis: {threat_profile['type'].replace('_', ' ').title()}")
    print(f"   - Identifying key indicators: {', '.join(threat_profile['indicators'])}")
    print("   - Mapping to QRadar AQL syntax")
    
    # Generate appropriate AQL based on threat type
    if threat_profile["type"] == "malicious_ips":
        aql_query = f"""SELECT sourceip, destinationip, QIDNAME(qid) as event_name,
       username, CATEGORYNAME(category) as category, devicetime,
       destinationport, protocol, bytesreceived, bytessent
FROM events
WHERE devicetime > NOW() - {days} DAYS
  AND (
    sourceip IN (SELECT ip FROM reference_set WHERE name='Threat_Intelligence_IPs')
    OR destinationip IN (SELECT ip FROM reference_set WHERE name='Threat_Intelligence_IPs')
    OR CATEGORYNAME(category) LIKE '%Suspicious%'
    OR CATEGORYNAME(category) LIKE '%Malware%'
  )
ORDER BY devicetime DESC"""
    
    elif threat_profile["type"] == "ransomware":
        aql_query = f"""SELECT QIDNAME(qid) as event_name, username, sourceip, hostname,
       "Command Line" as command_line, "Process Name" as process_name,
       devicetime, CATEGORYNAME(category) as category
FROM events
WHERE devicetime > NOW() - {days} DAYS
  AND (
    LOWER("Command Line") LIKE '%vssadmin%delete%'
    OR LOWER("Command Line") LIKE '%wbadmin%delete%'
    OR LOWER("Command Line") LIKE '%bcdedit%recoveryenabled%no%'
    OR LOWER("Command Line") LIKE '%.encrypt%'
    OR LOWER("Process Name") LIKE '%crypt%'
  )
ORDER BY devicetime DESC"""
    
    elif threat_profile["type"] == "privilege_escalation":
        aql_query = f"""SELECT QIDNAME(qid) as event_name, username, sourceip, hostname,
       "Command Line" as command_line, "Process Name" as process_name,
       devicetime, CATEGORYNAME(category) as category
FROM events
WHERE devicetime > NOW() - {days} DAYS
  AND (
    LOWER("Command Line") LIKE '%runas%'
    OR LOWER("Command Line") LIKE '%schtasks%/create%'
    OR LOWER("Command Line") LIKE '%seimpersonateprivilege%'
    OR QIDNAME(qid) LIKE '%Privilege%Escalation%'
  )
ORDER BY devicetime DESC"""
    
    elif threat_profile["type"] == "exfiltration":
        aql_query = f"""SELECT sourceip, destinationip, QIDNAME(qid) as event_name,
       username, destinationport, protocol, bytessent,
       devicetime, CATEGORYNAME(category) as category
FROM events
WHERE devicetime > NOW() - {days} DAYS
  AND bytessent > 10485760
  AND (
    destinationport IN (443, 80, 8080, 22)
    OR CATEGORYNAME(category) LIKE '%Data%Transfer%'
  )
ORDER BY bytessent DESC"""
    
    else:  # lateral_movement (default)
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


def generate_mock_events(threat_profile: Dict) -> List[Dict[str, Any]]:
    """
    Generate mock events based on threat profile
    """
    if threat_profile["type"] == "malicious_ips":
        return [
            {
                "event_name": "Suspicious Network Connection",
                "username": "system",
                "sourceip": "192.168.1.100",
                "destinationip": "185.220.101.45",  # Known malicious IP
                "category": "Suspicious Traffic",
                "devicetime": (datetime.now() - timedelta(hours=3)).isoformat(),
                "destinationport": "443",
                "protocol": "TCP",
                "bytessent": "15728640",
                "hostname": "WORKSTATION-05"
            },
            {
                "event_name": "C2 Communication Detected",
                "username": "user01",
                "sourceip": "192.168.1.105",
                "destinationip": "45.142.212.61",  # C2 server
                "category": "Malware Communication",
                "devicetime": (datetime.now() - timedelta(hours=2, minutes=30)).isoformat(),
                "destinationport": "8080",
                "protocol": "TCP",
                "bytessent": "8388608",
                "hostname": "WORKSTATION-08"
            },
            {
                "event_name": "Data Exfiltration Attempt",
                "username": "admin",
                "sourceip": "192.168.1.110",
                "destinationip": "103.253.145.12",  # Suspicious IP
                "category": "Data Transfer",
                "devicetime": (datetime.now() - timedelta(hours=1, minutes=45)).isoformat(),
                "destinationport": "443",
                "protocol": "HTTPS",
                "bytessent": "52428800",
                "hostname": "SERVER-DB-01"
            },
            {
                "event_name": "Threat Intelligence Match",
                "username": "system",
                "sourceip": "192.168.1.115",
                "destinationip": "91.219.236.197",  # Known botnet
                "category": "Threat Intelligence",
                "devicetime": (datetime.now() - timedelta(hours=1)).isoformat(),
                "destinationport": "6667",
                "protocol": "IRC",
                "bytessent": "2097152",
                "hostname": "WORKSTATION-12"
            }
        ]
    
    elif threat_profile["type"] == "ransomware":
        return [
            {
                "event_name": "Shadow Copy Deletion",
                "username": "admin",
                "sourceip": "10.0.2.50",
                "destinationip": None,
                "category": "System Modification",
                "devicetime": (datetime.now() - timedelta(hours=2)).isoformat(),
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "hostname": "FILE-SERVER-01",
                "process_name": "vssadmin.exe"
            },
            {
                "event_name": "Backup Deletion",
                "username": "admin",
                "sourceip": "10.0.2.50",
                "destinationip": None,
                "category": "System Modification",
                "devicetime": (datetime.now() - timedelta(hours=1, minutes=55)).isoformat(),
                "command_line": "wbadmin delete catalog -quiet",
                "hostname": "FILE-SERVER-01",
                "process_name": "wbadmin.exe"
            },
            {
                "event_name": "File Encryption Activity",
                "username": "admin",
                "sourceip": "10.0.2.50",
                "destinationip": None,
                "category": "File Modification",
                "devicetime": (datetime.now() - timedelta(hours=1, minutes=30)).isoformat(),
                "command_line": "encrypt.exe -r C:\\Users\\",
                "hostname": "FILE-SERVER-01",
                "process_name": "encrypt.exe"
            },
            {
                "event_name": "Ransom Note Created",
                "username": "admin",
                "sourceip": "10.0.2.50",
                "destinationip": None,
                "category": "File Creation",
                "devicetime": (datetime.now() - timedelta(hours=1)).isoformat(),
                "command_line": "cmd.exe /c echo Your files are encrypted > README.txt",
                "hostname": "FILE-SERVER-01",
                "process_name": "cmd.exe"
            }
        ]
    
    else:  # Default: lateral movement
        return [
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
            }
        ]


def correlate_logs(aql_query: str, threat_profile: Dict) -> List[Dict[str, Any]]:
    """
    Simulate log correlation based on threat type
    """
    print_step(2, "Correlating Logs from SIEM")
    
    print("🔍 Executing AQL query against IBM QRadar...")
    print("   - Initiating search job")
    print("   - Polling for results (search_id: " + f"hunt-{threat_profile['type']}-{datetime.now().strftime('%H%M%S')}" + ")")
    print("   - Fetching event data\n")
    
    events = generate_mock_events(threat_profile)
    
    print(f"✅ Retrieved {len(events)} matching events\n")
    
    print("📊 Event Summary:")
    print(f"   • Total Events: {len(events)}")
    print(f"   • Unique Hosts: {len(set(e.get('hostname', 'N/A') for e in events))}")
    print(f"   • Unique Users: {len(set(e.get('username', 'N/A') for e in events))}")
    if any('sourceip' in e for e in events):
        print(f"   • Source IPs: {len(set(e.get('sourceip', 'N/A') for e in events if e.get('sourceip')))}")
    if any('destinationip' in e for e in events):
        print(f"   • Destination IPs: {len(set(e.get('destinationip', 'N/A') for e in events if e.get('destinationip')))}")
    
    return events


def detect_anomalies(events: List[Dict], threat_profile: Dict) -> List[Dict]:
    """
    Generate anomalies based on threat profile
    """
    print_step(3, "Identifying Anomalies")
    
    print("🔬 Running anomaly detection algorithms...")
    print("   - Z-score frequency analysis")
    print("   - Rare process detection")
    print("   - Off-hours activity detection")
    print("   - Threat intelligence correlation\n")
    
    if threat_profile["type"] == "malicious_ips":
        anomalies = [
            {
                "event": events[0],
                "reason": "Connection to known malicious IP (185.220.101.45) - Threat Intelligence match",
                "severity": "critical",
                "zscore": 5.2
            },
            {
                "event": events[1],
                "reason": "C2 communication pattern detected - Beaconing behavior to 45.142.212.61",
                "severity": "critical",
                "zscore": 4.8
            },
            {
                "event": events[2],
                "reason": "Large data transfer (50MB) to suspicious external IP",
                "severity": "high",
                "zscore": 3.5
            },
            {
                "event": events[3],
                "reason": "IRC protocol usage to known botnet IP (91.219.236.197)",
                "severity": "high",
                "zscore": 4.1
            }
        ]
    
    elif threat_profile["type"] == "ransomware":
        anomalies = [
            {
                "event": events[0],
                "reason": "Shadow copy deletion - Classic ransomware preparation",
                "severity": "critical",
                "zscore": 5.5
            },
            {
                "event": events[1],
                "reason": "Backup catalog deletion - Data recovery prevention",
                "severity": "critical",
                "zscore": 5.3
            },
            {
                "event": events[2],
                "reason": "Mass file encryption activity detected",
                "severity": "critical",
                "zscore": 6.0
            },
            {
                "event": events[3],
                "reason": "Ransom note creation - Active ransomware infection",
                "severity": "critical",
                "zscore": 5.8
            }
        ]
    
    else:  # lateral_movement
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
                "reason": "Administrative share access for lateral movement",
                "severity": "medium",
                "zscore": 2.3
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
        print(f"   Host: {anomaly['event'].get('hostname', 'N/A')}")
        print(f"   User: {anomaly['event'].get('username', 'N/A')}")
        print(f"   Reason: {anomaly['reason']}")
        if anomaly.get("zscore"):
            print(f"   Z-Score: {anomaly['zscore']}")
        print()
    
    return anomalies


def build_attack_chain(events: List[Dict], anomalies: List[Dict], threat_profile: Dict) -> Dict:
    """
    Build attack chain based on threat profile
    """
    print_step(4, "Visualizing Attack Chain")
    
    print("🗺️  Mapping events to MITRE ATT&CK framework...")
    print(f"   - Identified threat type: {threat_profile['type'].replace('_', ' ').title()}")
    print("   - Pattern matching against technique database")
    print("   - Clustering by tactic phase")
    print("   - Building kill chain sequence\n")
    
    if threat_profile["type"] == "malicious_ips":
        attack_chain = {
            "steps": [
                {
                    "step": 1,
                    "tactic": "Initial Access",
                    "techniques": [
                        {
                            "technique_id": "T1566.001",
                            "technique_name": "Spearphishing Attachment",
                            "description": "Initial compromise vector"
                        }
                    ]
                },
                {
                    "step": 2,
                    "tactic": "Command and Control",
                    "techniques": [
                        {
                            "technique_id": "T1071.001",
                            "technique_name": "Web Protocols",
                            "description": "C2 communication over HTTPS"
                        },
                        {
                            "technique_id": "T1573",
                            "technique_name": "Encrypted Channel",
                            "description": "Encrypted C2 traffic"
                        }
                    ]
                },
                {
                    "step": 3,
                    "tactic": "Exfiltration",
                    "techniques": [
                        {
                            "technique_id": "T1041",
                            "technique_name": "Exfiltration Over C2 Channel",
                            "description": "Data exfiltration to malicious IPs"
                        }
                    ]
                }
            ],
            "source_ips": ["192.168.1.100", "192.168.1.105", "192.168.1.110"],
            "malicious_ips": ["185.220.101.45", "45.142.212.61", "103.253.145.12", "91.219.236.197"],
            "affected_hosts": ["WORKSTATION-05", "WORKSTATION-08", "SERVER-DB-01", "WORKSTATION-12"],
            "techniques_summary": ["T1566.001", "T1071.001", "T1573", "T1041"]
        }
    
    elif threat_profile["type"] == "ransomware":
        attack_chain = {
            "steps": [
                {
                    "step": 1,
                    "tactic": "Execution",
                    "techniques": [
                        {
                            "technique_id": "T1059.001",
                            "technique_name": "PowerShell",
                            "description": "Ransomware execution via PowerShell"
                        }
                    ]
                },
                {
                    "step": 2,
                    "tactic": "Defense Evasion",
                    "techniques": [
                        {
                            "technique_id": "T1070.001",
                            "technique_name": "Clear Windows Event Logs",
                            "description": "Evidence removal"
                        }
                    ]
                },
                {
                    "step": 3,
                    "tactic": "Impact",
                    "techniques": [
                        {
                            "technique_id": "T1490",
                            "technique_name": "Inhibit System Recovery",
                            "description": "Shadow copy and backup deletion"
                        },
                        {
                            "technique_id": "T1486",
                            "technique_name": "Data Encrypted for Impact",
                            "description": "File encryption"
                        }
                    ]
                }
            ],
            "source_ips": ["10.0.2.50"],
            "affected_hosts": ["FILE-SERVER-01"],
            "techniques_summary": ["T1059.001", "T1070.001", "T1490", "T1486"]
        }
    
    else:  # lateral_movement
        attack_chain = {
            "steps": [
                {
                    "step": 1,
                    "tactic": "Execution",
                    "techniques": [
                        {
                            "technique_id": "T1059.001",
                            "technique_name": "PowerShell",
                            "description": "Adversary executed PowerShell commands"
                        }
                    ]
                },
                {
                    "step": 2,
                    "tactic": "Lateral Movement",
                    "techniques": [
                        {
                            "technique_id": "T1021.006",
                            "technique_name": "Windows Remote Management",
                            "description": "PowerShell remoting via WinRM"
                        },
                        {
                            "technique_id": "T1021.002",
                            "technique_name": "SMB/Windows Admin Shares",
                            "description": "Network share access"
                        }
                    ]
                }
            ],
            "source_ips": ["10.0.1.50"],
            "affected_hosts": ["WORKSTATION-01", "SERVER-02", "SERVER-03"],
            "techniques_summary": ["T1059.001", "T1021.006", "T1021.002"]
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
    print(f"│ 🎯 Attack Origin: {', '.join(attack_chain['source_ips'][:2]):<58} │")
    print(f"│ 💻 Affected Hosts: {len(attack_chain['affected_hosts'])} systems compromised{' ' * 38} │")
    print(f"│ 🔍 Techniques: {', '.join(attack_chain['techniques_summary'][:3]):<60} │")
    
    if threat_profile["type"] == "malicious_ips":
        print(f"│ 🚨 Malicious IPs: {len(attack_chain.get('malicious_ips', []))} threat intelligence matches{' ' * 32} │")
    
    print("└" + "─" * 78 + "┘")
    
    return attack_chain


def generate_summary(query_text: str, events: List[Dict], anomalies: List[Dict], 
                    attack_chain: Dict, threat_profile: Dict):
    """
    Generate threat hunt summary
    """
    print_header("THREAT HUNT SUMMARY")
    
    print(f"🔍 Original Query: \"{query_text}\"")
    print(f"🎯 Threat Type: {threat_profile['type'].replace('_', ' ').title()}\n")
    
    print("📈 Results:")
    print(f"   • AQL Query: Generated successfully via Watsonx AI")
    print(f"   • Events Retrieved: {len(events)}")
    print(f"   • Anomalies Detected: {len(anomalies)}")
    print(f"   • Attack Chain Steps: {len(attack_chain['steps'])}")
    print(f"   • MITRE Techniques: {len(attack_chain['techniques_summary'])}\n")
    
    # Threat-specific findings
    if threat_profile["type"] == "malicious_ips":
        print("🚨 Key Findings:")
        print(f"   • {len(attack_chain.get('malicious_ips', []))} malicious IPs identified")
        print(f"   • C2 communication detected from {len(attack_chain['source_ips'])} internal hosts")
        print(f"   • Data exfiltration attempts observed")
        print(f"   • Threat intelligence matches confirmed\n")
        
        print("🎯 Recommended Actions:")
        print("   1. Block malicious IPs at firewall immediately")
        print("   2. Isolate affected workstations from network")
        print("   3. Scan for malware on compromised systems")
        print("   4. Review firewall logs for additional connections")
        print("   5. Update threat intelligence feeds\n")
    
    elif threat_profile["type"] == "ransomware":
        print("🚨 Key Findings:")
        print(f"   • Active ransomware infection on {attack_chain['affected_hosts'][0]}")
        print(f"   • Shadow copies and backups deleted")
        print(f"   • File encryption in progress")
        print(f"   • Ransom note deployed\n")
        
        print("🎯 Recommended Actions:")
        print("   1. IMMEDIATELY isolate affected server from network")
        print("   2. Do NOT pay ransom - contact incident response team")
        print("   3. Restore from offline backups if available")
        print("   4. Scan entire network for ransomware indicators")
        print("   5. Review backup and disaster recovery procedures\n")
    
    else:  # lateral_movement
        print("🚨 Key Findings:")
        print(f"   • Lateral movement detected from {attack_chain['source_ips'][0]}")
        print(f"   • {len(attack_chain['affected_hosts'])} systems compromised")
        print(f"   • PowerShell remoting used for propagation")
        print(f"   • Administrative credentials likely compromised\n")
        
        print("🎯 Recommended Actions:")
        print("   1. Isolate source IP immediately")
        print("   2. Reset credentials for affected accounts")
        print("   3. Scan affected hosts for persistence mechanisms")
        print("   4. Review PowerShell execution policies")
        print("   5. Enable enhanced logging for lateral movement detection\n")
    
    print("📊 Confidence Score: 89% (High)")
    print("⏱️  Analysis completed in 2.7 seconds")


async def run_demo():
    """
    Main demo execution with intelligent query analysis
    """
    print_header("AI-POWERED THREAT HUNT DEMO")
    print("Powered by IBM Watsonx AI + QRadar SIEM")
    print("Demonstrating: Natural Language → SIEM Query → Log Correlation → Anomaly Detection → Attack Chain\n")
    
    # Get user input
    print("Please enter your threat hunting query:")
    print("Examples:")
    print("  - Find suspicious lateral movement using PowerShell in last 7 days")
    print("  - Find all the malicious IPs")
    print("  - Detect ransomware activity in the last 24 hours")
    print("  - Show privilege escalation attempts\n")
    
    query_text = input("Your query: ").strip()
    
    if not query_text:
        query_text = "Find suspicious lateral movement using PowerShell in last 7 days"
        print(f"Using default query: {query_text}\n")
    
    days_input = input("Time window in days (default: 7): ").strip()
    days = int(days_input) if days_input.isdigit() else 7
    
    print()
    
    # Analyze query to determine threat type
    threat_profile = analyze_query(query_text)
    
    # Step 1: Generate AQL
    aql_query = generate_aql(query_text, days, threat_profile)
    await asyncio.sleep(1)
    
    # Step 2: Correlate logs
    events = correlate_logs(aql_query, threat_profile)
    await asyncio.sleep(1)
    
    # Step 3: Detect anomalies
    anomalies = detect_anomalies(events, threat_profile)
    await asyncio.sleep(1)
    
    # Step 4: Build attack chain
    attack_chain = build_attack_chain(events, anomalies, threat_profile)
    await asyncio.sleep(1)
    
    # Final summary
    generate_summary(query_text, events, anomalies, attack_chain, threat_profile)
    
    print("\n" + "=" * 80)
    print("Demo completed successfully! 🎉")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(run_demo())

# Made with Bob
