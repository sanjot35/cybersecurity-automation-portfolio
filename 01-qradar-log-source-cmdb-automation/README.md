# QRadar Log Source Inventory & CMDB Reconciliation

This repository contains my Python scripts for QRadar log source inventory and CMDB reconciliation.

## Included scripts
- `qradar_log_source_inventory.py` — retrieves QRadar log sources through the Log Source Management API, filters selected log source types, paginates results, and exports inventory to Excel.
- `qradar_enabled_log_sources.py` — exports enabled log sources for selected types, including last reporting time, to an Excel workbook.
- `qradar_cmdb_reconciliation.py` — matches CMDB hostnames/IPs against QRadar log source names, updates the CMDB with the latest reporting date, and generates a matching/debug report.

## Skills demonstrated
QRadar REST API usage, pagination, filtering, Excel reporting, hostname/IP matching, regex matching, CMDB reconciliation, and debugging output.

## Setup / configuration
Update the QRadar base URL and provide a valid SEC token using a secure configuration method before running. Use a test environment and authorized API permissions.

## Important
These are portfolio copies of scripts I authored. Before public release, review the code and ensure it is approved for sharing. Use secure TLS certificate validation; do not disable certificate verification. Do not upload real CMDBs, hostnames, IPs, QRadar exports, or client-specific configuration.
