import requests
import urllib3
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# QRadar API URL
base_url = "https://x.x.x.x/api/config/event_sources/log_source_management/log_sources"

headers = {
    "Version": "24.0",
    "SEC": "YOUR_QRADAR_SEC_TOKEN",
    "Accept": "application/json"
}

# Required Log Source Type IDs
required_type_ids = [11, 12, 24, 85, 210, 4026]

# Pagination variables
start = 0
page_size = 100

# Create Excel Workbook
workbook = Workbook()
sheet = workbook.active
sheet.title = "QRadar Log Sources"

# Excel Headers
headers_excel = [
    "Type ID",
    "Log Source Name",
    "Last Reporting Time"
]

sheet.append(headers_excel)

# Make header bold
for cell in sheet[1]:
    cell.font = Font(bold=True)

try:

    while True:

        # Pagination
        headers["Range"] = f"items={start}-{start + page_size - 1}"

        response = requests.get(base_url, headers=headers)

        if response.status_code != 200:
            print("Failed:", response.status_code)
            print(response.text)
            break

        data = response.json()

        # Stop if no more data
        if not data:
            break

        for log_source in data:

            # Only enabled log sources
            if not log_source.get("enabled", False):
                continue

            type_id = log_source.get("type_id")

            # Filter required type IDs only
            if type_id not in required_type_ids:
                continue

            name = log_source.get("name", "N/A")

            # Last reporting time
            last_event_time = log_source.get("last_event_time")

            if last_event_time:
                last_reporting = datetime.fromtimestamp(
                    last_event_time / 1000
                ).strftime("%Y-%m-%d %H:%M:%S")
            else:
                last_reporting = "N/A"

            # Add row to Excel
            sheet.append([
                type_id,
                name,
                last_reporting
            ])

            # Optional console output
            print(type_id, name, last_reporting)

        # Next page
        start += page_size

    # Adjust column widths
    sheet.column_dimensions["A"].width = 15
    sheet.column_dimensions["B"].width = 60
    sheet.column_dimensions["C"].width = 25

    # Save Excel file
    excel_file = "QRadar_Enabled_Log_Sources.xlsx"
    workbook.save(excel_file)

    print(f"\nExcel file created successfully: {excel_file}")

except requests.exceptions.RequestException as e:
    print("Request Error:", e)