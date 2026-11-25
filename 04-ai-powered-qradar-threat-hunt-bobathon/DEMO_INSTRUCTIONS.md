# Simple Demo Instructions

## AI-Powered Threat Hunt Demo

This demo showcases the complete workflow of the AI-powered threat hunting system, from natural language input to attack chain visualization.

## What the Demo Shows

The demo takes a simple prompt:
```
"Find suspicious lateral movement using PowerShell in last 7 days"
```

And demonstrates the complete pipeline:

1. **Converts to SIEM Query (AQL)** - Uses LLM to translate natural language into QRadar AQL syntax
2. **Correlates Logs** - Executes the query against QRadar and retrieves matching events
3. **Identifies Anomalies** - Applies multiple detection algorithms (z-score, rare process, off-hours, fan-out)
4. **Visualizes Attack Chain** - Maps events to MITRE ATT&CK framework and builds kill chain

## Running the Demo

### Prerequisites
- Python 3.8 or higher
- Virtual environment activated (if using one)

### Two Ways to Run

#### Option 1: Interactive Mode (simple_demo.py)
Prompts you to enter the query:

```bash
# Windows
.venv\Scripts\python.exe simple_demo.py

# Linux/Mac
.venv/bin/python simple_demo.py
```

Then enter: `Find suspicious lateral movement using PowerShell in last 7 days`

#### Option 2: Non-Interactive Mode (run_simple_demo.py)
Runs automatically with the predefined query:

```bash
# Windows
.venv\Scripts\python.exe run_simple_demo.py

# Linux/Mac
.venv/bin/python run_simple_demo.py
```

Or with a custom query:

```bash
.venv\Scripts\python.exe run_simple_demo.py "Find suspicious lateral movement using PowerShell in last 7 days" 7
```

## Demo Output

The demo will display:

### Step 1: Query Conversion
- Shows the natural language input
- Displays the generated AQL query with proper syntax highlighting
- Demonstrates LLM processing steps

### Step 2: Log Correlation
- Simulates QRadar search execution
- Shows event retrieval statistics
- Displays summary of correlated events

### Step 3: Anomaly Detection
- Lists all detected anomalies with severity levels
- Shows detection reasoning for each anomaly
- Includes z-scores where applicable

### Step 4: Attack Chain Visualization
- Displays MITRE ATT&CK mapped kill chain
- Shows progression through tactics (Execution → Lateral Movement → Credential Access)
- Lists specific techniques used (T1059.001, T1021.006, T1021.002, T1003.001)

### Final Summary
- Complete hunt results
- Key findings and recommendations
- Confidence score and timing

## Sample Output

```
================================================================================
  AI-POWERED THREAT HUNT DEMO
================================================================================

STEP 1: Converting Natural Language to SIEM Query (AQL)
────────────────────────────────────────────────────────
📝 Input Prompt: "Find suspicious lateral movement using PowerShell in last 7 days"
⏱️  Time Window: Last 7 days

✅ AQL Query Generated:
┌──────────────────────────────────────────────────────┐
│ SELECT QIDNAME(qid) as event_name, username, ...    │
│ FROM events                                          │
│ WHERE devicetime > NOW() - 7 DAYS                    │
│   AND (LOWER("Process Name") LIKE '%powershell%'... │
└──────────────────────────────────────────────────────┘

STEP 2: Correlating Logs from SIEM
────────────────────────────────────
✅ Retrieved 5 matching events
📊 Event Summary:
   • Total Events: 5
   • Unique Hosts: 4
   • Affected Users: 1

STEP 3: Identifying Anomalies
────────────────────────────────
⚠️  Flagged 4 anomalous events:
🟠 Anomaly #1 [HIGH] - Encoded PowerShell command detected
🟠 Anomaly #2 [HIGH] - Remote PowerShell execution
🟠 Anomaly #3 [HIGH] - High fan-out detected
🔴 Anomaly #4 [CRITICAL] - Credential dumping tool (Mimikatz)

STEP 4: Visualizing Attack Chain
────────────────────────────────────
✅ Attack Chain Constructed:
┌──────────────────────────────────────────────────────┐
│         MITRE ATT&CK KILL CHAIN                      │
├──────────────────────────────────────────────────────┤
│ Step 1: Execution                                    │
│   └─ T1059.001: PowerShell                          │
│ Step 2: Lateral Movement                             │
│   └─ T1021.006: Windows Remote Management           │
│   └─ T1021.002: SMB/Windows Admin Shares            │
│ Step 3: Credential Access                            │
│   └─ T1003.001: LSASS Memory                        │
└──────────────────────────────────────────────────────┘

🎯 Attack Origin: 10.0.1.50
💻 Affected Hosts: 5 systems compromised
🔍 Techniques Used: T1059.001, T1021.006, T1021.002, T1003.001
```

## Key Features Demonstrated

1. **Natural Language Processing**: Converts plain English to technical SIEM queries
2. **Log Correlation**: Aggregates events from multiple sources
3. **Anomaly Detection**: Multiple algorithms working in parallel
4. **MITRE ATT&CK Mapping**: Automatic technique identification
5. **Kill Chain Visualization**: Clear attack progression timeline
6. **Actionable Intelligence**: Specific recommendations for response

## Customization

To modify the demo scenario, edit the `MOCK_EVENTS` list in `simple_demo.py`:

```python
MOCK_EVENTS = [
    {
        "event_name": "Process Created",
        "username": "admin",
        "sourceip": "10.0.1.50",
        # ... add your custom events
    }
]
```

## Integration with Real System

This demo uses mock data. To integrate with the real backend:

1. Start the FastAPI backend: `uvicorn backend.main:app --reload`
2. Use the `/hunt` endpoint with the same query
3. The real system will query actual QRadar and return live results

## Troubleshooting

### Unicode Errors on Windows
The script automatically handles Windows console encoding. If you still see errors, try:
```bash
chcp 65001  # Set console to UTF-8
python simple_demo.py
```

### Python Not Found
Make sure Python is in your PATH or use the full path to the Python executable.

## Next Steps

- Review the full backend implementation in `backend/`
- Explore the web dashboard in `frontend/dashboard.html`
- Run the test suite: `pytest tests/ -v`
- Check the API documentation: `http://localhost:8000/docs` (when backend is running)

## Support

For questions or issues, refer to the main README.md or the project documentation.