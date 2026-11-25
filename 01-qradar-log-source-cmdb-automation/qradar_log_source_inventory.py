import requests
import urllib3
import pandas as pd
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================================================
# QRadar API Details
# ==================================================

BASE_URL = "https://x.x.x.x/api/config/event_sources/log_source_management/log_sources"

HEADERS = {
    "Version": "24.0",
    "SEC": "YOUR_QRADAR_SEC_TOKEN",  # Replace with your QRadar SEC token
    "Accept": "application/json"
}

# Required Log Source Type IDs
# 11 = Linux
# 12 = Windows
# 24 = Solaris
# 85 = AIX
# 210 = VMware
# 4026 = FortiGate
required_type_ids = [11, 12, 24, 85, 210, 4026]

# ==================================================
# Fetch QRadar Log Sources
# ==================================================

log_sources = []

start = 0
page_size = 100

while True:

    headers = HEADERS.copy()
    headers["Range"] = f"items={start}-{start + page_size - 1}"

    response = requests.get(
        BASE_URL,
        headers=headers,
        
    )

    if response.status_code != 200:
        print(f"API Error: {response.status_code}")
        print(response.text)
        break

    data = response.json()

    # Exit when no more records
    if not data:
        break

    for ls in data:

        # Filter required Log Source Types
        if ls.get("type_id") not in required_type_ids:
            continue

        last_event_time = ls.get("last_event_time")

        if last_event_time:
            last_event = datetime.fromtimestamp(
                last_event_time / 1000
            ).strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_event = ""

        log_sources.append({
            "ID": ls.get("id"),
            "Name": ls.get("name"),
            "Enabled": ls.get("enabled"),
            "Type ID": ls.get("type_id"),
            "Last Event Time": last_event
        })

    start += page_size

# ==================================================
# Create DataFrame
# ==================================================

df = pd.DataFrame(log_sources)

# Sort by Name (optional)
df = df.sort_values(by="Name")

# ==================================================
# Save to Excel
# ==================================================

output_file = "./input.xlsx"

df.to_excel(output_file, index=False)

print(f"Successfully exported {len(df)} log sources.")
