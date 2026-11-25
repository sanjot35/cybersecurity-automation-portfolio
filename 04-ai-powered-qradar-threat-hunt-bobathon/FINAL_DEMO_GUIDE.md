# 🎯 Final Demo Guide - Intelligent AI Threat Hunt

## ✨ NEW: Intelligent Demo with Dynamic Response

The **intelligent_demo.py** now dynamically generates different responses based on your input query!

## 🚀 Quick Start

```bash
.venv\Scripts\python.exe intelligent_demo.py
```

## 📝 Supported Query Types

### 1. **Malicious IPs / Network Threats**
**Try:** `Find all the malicious IPs`

**Output:**
- AQL query targeting threat intelligence IPs
- Events showing C2 communication
- Anomalies: Threat intelligence matches, beaconing behavior
- Attack Chain: Initial Access → Command & Control → Exfiltration
- Techniques: T1566.001, T1071.001, T1573, T1041

### 2. **Lateral Movement (PowerShell)**
**Try:** `Find suspicious lateral movement using PowerShell in last 7 days`

**Output:**
- AQL query for PowerShell + lateral movement indicators
- Events showing remote execution
- Anomalies: Encoded commands, remote PowerShell
- Attack Chain: Execution → Lateral Movement
- Techniques: T1059.001, T1021.006, T1021.002

### 3. **Ransomware Activity**
**Try:** `Detect ransomware activity in the last 24 hours`

**Output:**
- AQL query for ransomware indicators
- Events showing shadow copy deletion, encryption
- Anomalies: Backup deletion, file encryption
- Attack Chain: Execution → Defense Evasion → Impact
- Techniques: T1059.001, T1070.001, T1490, T1486

### 4. **Privilege Escalation**
**Try:** `Show privilege escalation attempts`

**Output:**
- AQL query for privilege escalation patterns
- Events showing token manipulation, UAC bypass
- Anomalies: Scheduled task creation, runas usage
- Attack Chain: Privilege Escalation → Persistence
- Techniques: T1134, T1548.002, T1053.005

### 5. **Data Exfiltration**
**Try:** `Find data exfiltration attempts`

**Output:**
- AQL query for large data transfers
- Events showing unusual uploads
- Anomalies: Large outbound transfers
- Attack Chain: Collection → Exfiltration → C2
- Techniques: T1041, T1567, T1071

## 🎬 Demo Flow

For each query type, the system will:

1. **🤖 Watsonx AI Processing**
   - Analyzes your threat hypothesis
   - Identifies threat type (malicious IPs, ransomware, lateral movement, etc.)
   - Generates appropriate AQL query

2. **🔍 Log Correlation**
   - Executes query against QRadar
   - Retrieves relevant events
   - Shows event statistics

3. **⚠️ Anomaly Detection**
   - Runs multiple detection algorithms
   - Flags suspicious events with severity
   - Provides Z-scores and reasoning

4. **🗺️ Attack Chain Visualization**
   - Maps to MITRE ATT&CK framework
   - Shows kill chain progression
   - Lists techniques and tactics

5. **📊 Threat Summary**
   - Key findings specific to threat type
   - Actionable recommendations
   - Confidence score

## 💡 Example Session

```
Your query: Find all the malicious IPs
Time window: 7

STEP 1: Converting Natural Language to SIEM Query (AQL)
🤖 Watsonx AI Processing...
   - Analyzing threat hypothesis: Malicious Ips
   - Identifying key indicators: known malicious IPs, C2 communication, data exfiltration
   - Mapping to QRadar AQL syntax

✅ AQL Query Generated:
SELECT sourceip, destinationip, QIDNAME(qid) as event_name,
       username, CATEGORYNAME(category) as category, devicetime,
       destinationport, protocol, bytesreceived, bytessent
FROM events
WHERE devicetime > NOW() - 7 DAYS
  AND (
    sourceip IN (SELECT ip FROM reference_set WHERE name='Threat_Intelligence_IPs')
    OR destinationip IN (SELECT ip FROM reference_set WHERE name='Threat_Intelligence_IPs')
    OR CATEGORYNAME(category) LIKE '%Suspicious%'
    OR CATEGORYNAME(category) LIKE '%Malware%'
  )
ORDER BY devicetime DESC

STEP 2: Correlating Logs from SIEM
✅ Retrieved 4 matching events
   • Destination IPs: 4 malicious IPs identified

STEP 3: Identifying Anomalies
⚠️ Flagged 4 anomalous events:
🔴 Anomaly #1 [CRITICAL]
   Reason: Connection to known malicious IP (185.220.101.45)
🔴 Anomaly #2 [CRITICAL]
   Reason: C2 communication pattern detected

STEP 4: Visualizing Attack Chain
✅ Attack Chain Constructed:
Step 1: Initial Access
  └─ T1566.001: Spearphishing Attachment
Step 2: Command and Control
  └─ T1071.001: Web Protocols
  └─ T1573: Encrypted Channel
Step 3: Exfiltration
  └─ T1041: Exfiltration Over C2 Channel

THREAT HUNT SUMMARY
🚨 Key Findings:
   • 4 malicious IPs identified
   • C2 communication detected from 3 internal hosts
   • Data exfiltration attempts observed
   • Threat intelligence matches confirmed

🎯 Recommended Actions:
   1. Block malicious IPs at firewall immediately
   2. Isolate affected workstations from network
   3. Scan for malware on compromised systems
   4. Review firewall logs for additional connections
   5. Update threat intelligence feeds
```

## 🔧 Features

✅ **Dynamic Query Analysis** - Automatically detects threat type from your input
✅ **Contextual AQL Generation** - Creates appropriate queries for each threat
✅ **Threat-Specific Events** - Shows relevant mock data for each scenario
✅ **Adaptive Anomaly Detection** - Flags appropriate anomalies per threat type
✅ **Custom Attack Chains** - Builds MITRE kill chains specific to the threat
✅ **Actionable Recommendations** - Provides threat-specific response actions

## 📚 Comparison with Other Demos

| Feature | simple_demo.py | run_simple_demo.py | intelligent_demo.py |
|---------|---------------|-------------------|---------------------|
| User Input | ✅ Interactive | ❌ Hardcoded | ✅ Interactive |
| Dynamic Response | ❌ Fixed | ❌ Fixed | ✅ Adaptive |
| Multiple Threat Types | ❌ One type | ❌ One type | ✅ 5+ types |
| Custom AQL per Query | ❌ | ❌ | ✅ |
| Threat-Specific Recommendations | ❌ | ❌ | ✅ |

## 🎓 Best For

- **Demonstrations** - Shows AI adapting to different queries
- **Training** - Teaches different threat hunting scenarios
- **Presentations** - Impressive dynamic responses
- **Testing** - Validates system handles various threat types

## 🚀 Next Steps

1. Try different query types to see adaptive responses
2. Modify threat profiles in the code for custom scenarios
3. Integrate with real backend API for live data
4. Extend with more threat types (APT, insider threats, etc.)

---

**Powered by IBM Watsonx AI + QRadar SIEM** 🔒