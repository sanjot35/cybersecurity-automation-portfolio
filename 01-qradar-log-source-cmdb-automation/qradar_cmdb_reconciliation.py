import requests
import urllib3
import pandas as pd
import re
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================================================
# QRadar API Details
# ==================================================

BASE_URL = "https://x.x.x.x/api/config/event_sources/log_source_management/log_sources"

HEADERS = {
    "Version": "24.0",
    "SEC": "YOUR_QRADAR_SEC_TOKEN",       # Replace with your QRadar SEC Token
    "Accept": "application/json"
}

# Required Log Source Types
# 11 = Linux
# 12 = Windows
# 24 = Solaris
# 85 = AIX
# 210 = VMware
# 4026 = FortiGate

required_type_ids = [11, 12, 24, 85, 210, 4026]

# ==================================================
# Read CMDB
# ==================================================

cmdb_file = "./input.xlsx"

df = pd.read_excel(cmdb_file)

if "Qradar Last Report Date" not in df.columns:
    df["Qradar Last Report Date"] = ""

# ==================================================
# Fetch QRadar Log Sources
# ==================================================

qradar_log_sources = []

start = 0
page_size = 100

while True:

    request_headers = HEADERS.copy()
    request_headers["Range"] = f"items={start}-{start + page_size - 1}"

    try:

        response = requests.get(
            BASE_URL,
            headers=request_headers,
            
            timeout=60
        )

        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        print(f"QRadar API Error : {e}")
        break

    data = response.json()

    if not data:
        break

    for log_source in data:

        enabled = log_source.get("enabled", False)

        if not enabled:
            continue

        type_id = log_source.get("type_id")

        if type_id not in required_type_ids:
            continue

        name = str(log_source.get("name", "")).strip()

        last_event_time = log_source.get("last_event_time")

        if last_event_time:

            last_dt = datetime.fromtimestamp(
                last_event_time / 1000
            )

            last_reporting = last_dt.strftime("%Y-%m-%d")

        else:

            last_dt = datetime.min
            last_reporting = ""

        qradar_log_sources.append({
            "id": log_source.get("id"),
            "name": name,
            "name_lower": name.lower(),
            "enabled": enabled,
            "type_id": type_id,
            "last_dt": last_dt,
            "last_reporting": last_reporting
        })

    start += page_size

print(f"\nFetched {len(qradar_log_sources)} enabled QRadar Log Sources.")

# ==================================================
# Debug Data
# ==================================================

debug_rows = []

# ==================================================
# Match Hostname / IP
# ==================================================

for index, row in df.iterrows():

    hostname = str(row.get("Host name", "")).strip()
    ip = str(row.get("IP Address", "")).strip()

    if hostname.lower() == "nan":
        hostname = ""

    if ip.lower() == "nan":
        ip = ""

    matches = []

    for source in qradar_log_sources:

        hostname_match = False
        ip_match = False

        # ------------------------------------------
        # Hostname Match
        # ------------------------------------------

        if hostname:

            hostname_pattern = rf"\b{re.escape(hostname.lower())}\b"

            if re.search(hostname_pattern, source["name_lower"]):
                hostname_match = True

        # ------------------------------------------
        # Exact IP Match
        # Matches only @190.1.6.2@
        # Avoids matching 190.1.6.210
        # ------------------------------------------

        if ip:

            if f"@{ip}@" in source["name"]:
                ip_match = True

        if hostname_match or ip_match:

            match_type = []

            if hostname_match:
                match_type.append("Hostname")

            if ip_match:
                match_type.append("IP")

            matches.append(source)

            debug_rows.append({
                "CMDB Host": hostname,
                "CMDB IP": ip,
                "QRadar ID": source["id"],
                "QRadar Log Source": source["name"],
                "Enabled": source["enabled"],
                "Type ID": source["type_id"],
                "Last Event Date": source["last_reporting"],
                "Matched By": ", ".join(match_type),
                "Selected": "No"
            })

    # ------------------------------------------
    # Pick Latest Reporting Log Source
    # ------------------------------------------

    if matches:

        latest_match = max(
            matches,
            key=lambda x: x["last_dt"]
        )

        df.at[
            index,
            "Qradar Last Report Date"
        ] = latest_match["last_reporting"]

        # Mark selected match

        for debug in reversed(debug_rows):

            if (
                debug["CMDB Host"] == hostname
                and debug["QRadar ID"] == latest_match["id"]
            ):

                debug["Selected"] = "Yes"
                break

        print("=" * 90)
        print(f"Host Name   : {hostname}")
        print(f"IP Address  : {ip}")
        print(f"QRadar ID   : {latest_match['id']}")
        print(f"Log Source  : {latest_match['name']}")
        print(f"Last Report : {latest_match['last_reporting']}")
        print("=" * 90)

# ==================================================
# Save Updated CMDB
# ==================================================

updated_cmdb = "./input.xlsx"

df.to_excel(updated_cmdb, index=False)

print(f"\nUpdated CMDB saved to:\n{updated_cmdb}")

# ==================================================
# Save Debug Report
# ==================================================

debug_df = pd.DataFrame(debug_rows)

debug_file = "./input.xlsx"

debug_df.to_excel(debug_file, index=False)

print(f"\nDebug report saved to:\n{debug_file}")

print("\nCompleted Successfully.")