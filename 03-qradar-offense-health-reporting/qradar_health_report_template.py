from docx import Document

doc = Document()
doc.add_heading('QRadar Health Status & Capability Report', 0)
doc.add_paragraph('Prepared by: SOC Team')
doc.add_paragraph('Client: [Client Name]')
doc.add_paragraph('Date: [DD/MM/YYYY]')
doc.add_paragraph('QRadar Version: 7.5.0 UP8 (example)')
doc.add_paragraph('Report Period: [Start Date] – [End Date]')
doc.add_paragraph()

# 1. Executive Summary
doc.add_heading('1. Executive Summary', level=1)
doc.add_paragraph(
    'This report outlines the current health status of the QRadar deployment, covering system performance, log source ingestion, EPS utilization, and the platform’s capability to onboard additional log sources such as AD audit logs, firewalls, and other infrastructure components.'
)

# 2. QRadar Deployment Overview
doc.add_heading('2. QRadar Deployment Overview', level=1)
table = doc.add_table(rows=1, cols=6)
table.style = 'Table Grid'
hdr = table.rows[0].cells
hdr[0].text = 'Component'
hdr[1].text = 'Hostname'
hdr[2].text = 'IP Address'
hdr[3].text = 'Type'
hdr[4].text = 'Status'
hdr[5].text = 'Version'
rows = [
    ['Console', 'qradar-console', '192.168.0.10', 'Console', 'Online', '7.5.0 UP8'],
    ['Event Processor 1', 'ep-node1', '192.168.0.11', 'Event Processor', 'Online', '7.5.0 UP8'],
    ['Event Collector 1', 'ec-node1', '192.168.0.12', 'Event Collector', 'Online', '7.5.0 UP8']
]
for r in rows:
    row = table.add_row().cells
    for i, val in enumerate(r):
        row[i].text = val

# 3. System Health Parameters
doc.add_heading('3. System Health Parameters', level=1)
doc.add_heading('3.1 CPU & Memory Utilization', level=2)
table = doc.add_table(rows=1, cols=3)
table.style = 'Table Grid'
hdr = table.rows[0].cells
hdr[0].text = 'Component'
hdr[1].text = 'Avg CPU Usage (%)'
hdr[2].text = 'Avg RAM Usage (%)'
rows = [['Console', '45', '60'], ['Event Processor 1', '70', '75'], ['Event Collector 1', '50', '65']]
for r in rows:
    row = table.add_row().cells
    for i, val in enumerate(r):
        row[i].text = val

doc.add_heading('3.2 Disk Usage', level=2)
table = doc.add_table(rows=1, cols=4)
table.style = 'Table Grid'
hdr = table.rows[0].cells
hdr[0].text = 'Component'
hdr[1].text = 'Partition'
hdr[2].text = 'Usage (%)'
hdr[3].text = 'Status'
rows = [['Console', '/store/ariel', '65%', 'Normal'], ['Event Processor', '/var/log', '85%', 'Warning']]
for r in rows:
    row = table.add_row().cells
    for i, val in enumerate(r):
        row[i].text = val

# 4. Event Processing Metrics
doc.add_heading('4. Event Processing Metrics', level=1)
doc.add_paragraph('EPS:')
table = doc.add_table(rows=1, cols=2)
table.style = 'Table Grid'
hdr = table.rows[0].cells
hdr[0].text = 'Parameter'
hdr[1].text = 'Value'
eps_data = [
    ['Licensed EPS', '5,000 EPS'],
    ['Average EPS (Last 7 Days)', '3,200 EPS'],
    ['Peak EPS', '4,500 EPS'],
    ['License Utilization (%)', '64%']
]
for r in eps_data:
    row = table.add_row().cells
    row[0].text = r[0]
    row[1].text = r[1]

doc.add_paragraph('FPM:')
table = doc.add_table(rows=1, cols=2)
table.style = 'Table Grid'
hdr = table.rows[0].cells
hdr[0].text = 'Parameter'
hdr[1].text = 'Value'
fpm_data = [['Licensed FPM', '20,000 FPM'], ['Average FPM', '12,000 FPM']]
for r in fpm_data:
    row = table.add_row().cells
    row[0].text = r[0]
    row[1].text = r[1]

# 5. Log Source Summary
doc.add_heading('5. Log Source Summary', level=1)
table = doc.add_table(rows=4, cols=2)
table.style = 'Table Grid'
table.cell(0, 0).text = 'Total Configured Sources'
table.cell(0, 1).text = '185'
table.cell(1, 0).text = 'Active Log Sources'
table.cell(1, 1).text = '178'
table.cell(2, 0).text = 'Inactive Log Sources'
table.cell(2, 1).text = '5'
table.cell(3, 0).text = 'Failing Log Sources'
table.cell(3, 1).text = '2'

doc.add_paragraph('Top 5 Log Source Types:')
table = doc.add_table(rows=1, cols=2)
table.style = 'Table Grid'
hdr = table.rows[0].cells
hdr[0].text = 'Source Type'
hdr[1].text = 'Count'
top_sources = [['Windows AD Audit', '60'], ['Firewall Logs', '40'], ['Linux Syslog', '30'],
               ['Endpoint Security', '20'], ['VPN Logs', '15']]
for r in top_sources:
    row = table.add_row().cells
    row[0].text = r[0]
    row[1].text = r[1]

# 6. Offense Summary
doc.add_heading('6. Offense Summary', level=1)
table = doc.add_table(rows=3, cols=2)
table.style = 'Table Grid'
table.cell(0, 0).text = 'Total Offenses (last week)'
table.cell(0, 1).text = '120'
table.cell(1, 0).text = 'Top Offense Category'
table.cell(1, 1).text = 'Brute Force Detection'
table.cell(2, 0).text = 'Avg Offenses per Day'
table.cell(2, 1).text = '18'

# 7. Ariel Query Health
doc.add_heading('7. Ariel Query Health', level=1)
table = doc.add_table(rows=3, cols=2)
table.style = 'Table Grid'
table.cell(0, 0).text = 'Avg Query Time'
table.cell(0, 1).text = '8 seconds'
table.cell(1, 0).text = 'Slowest Query'
table.cell(1, 1).text = '25 seconds'
table.cell(2, 0).text = 'Data Retention Period'
table.cell(2, 1).text = '30 days'

# 8. Additional Log Sources
doc.add_heading('8. Analysis of Capability for Additional Log Sources', level=1)
doc.add_paragraph('Supported and Already Ingested:\n- AD Audit Logs\n- Firewall Logs\n- EDR via API')
doc.add_paragraph('Additional Log Sources:')
table = doc.add_table(rows=1, cols=4)
table.style = 'Table Grid'
hdr = table.rows[0].cells
hdr[0].text = 'Log Source Type'
hdr[1].text = 'Supported DSM'
hdr[2].text = 'Ingestion Method'
hdr[3].text = 'Status/Notes'
additional_logs = [
    ['Exchange Online Logs', '✅', 'API', 'Supported'],
    ['Custom App Logs', '⚠️ Partial', 'Syslog/File', 'May need Custom DSM'],
    ['Legacy Devices', '❌', 'N/A', 'Not supported']
]
for r in additional_logs:
    row = table.add_row().cells
    for i, val in enumerate(r):
        row[i].text = val

# 9. Recommendations
doc.add_heading('9. Recommendations', level=1)
doc.add_paragraph('- Disk Alert: Increase disk or archive older data.\n'
                  '- EPS Forecasting: Can handle +1,500 EPS.\n'
                  '- Offense Tuning: Reduce false positives.\n'
                  '- Log Source Optimization: Disable inactive sources.\n'
                  '- Custom DSM: Prepare for unsupported logs.')

# 10. Conclusion
doc.add_heading('10. Conclusion', level=1)
doc.add_paragraph(
    'The QRadar platform is stable and within operational thresholds. It is capable of handling additional log sources like AD audit logs and firewall traffic, with appropriate tuning and scaling considerations.'
)

doc.save("QRadar_Health_Status_Report.docx")
print("Word document created: QRadar_Health_Status_Report.docx")


