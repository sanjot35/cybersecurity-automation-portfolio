import requests
import datetime
import time

# Convert start date to epoch milliseconds
start_dt = datetime.datetime.strptime("13-05-2026 00:00:00", "%d-%m-%Y %H:%M:%S")
start_epoch_ms = int(start_dt.timestamp() * 1000)

# QRadar offenses API endpoint
url = "https://x.x.x.x/api/siem/offenses"

headers = {
    "Version": "24.0",
    "SEC": "YOUR_QRADAR_SEC_TOKEN",
    "Accept": "application/json"
}

# Filter offenses from given start time till now
params = {
    "filter": f"start_time >= {start_epoch_ms}"
}

response = requests.get(url, headers=headers, params=params)

if response.status_code == 200:
    offenses = response.json()
    print(f"Total offenses fetched: {len(offenses)}")
    print(offenses)
else:
    print(f"Error: {response.status_code} - {response.text}")