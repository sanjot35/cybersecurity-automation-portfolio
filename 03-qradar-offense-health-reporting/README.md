# QRadar Offense & Health Reporting

This repository contains my QRadar offense retrieval and health-report document-generation scripts.

## Included scripts
- `qradar_offense_fetch.py` — retrieves offenses from QRadar beginning at a specified timestamp using the Offenses API.
- `qradar_health_report_template.py` — generates a Word report template covering deployment overview, CPU/memory, disk usage, EPS/FPM, log source summary, offense summary, Ariel query health, additional log source capability, recommendations, and conclusion.

## Skills demonstrated
QRadar REST API, time filtering, JSON response handling, Python `python-docx`, structured reporting, and operational health documentation.

## Important distinction
The health-report script currently fills the document using example/static values. It is a report-generation template, not a live QRadar health-data collector. Replace all example values with validated data before using the report operationally.

## Security
Use authorized QRadar access, secure token handling, TLS verification, and synthetic sample data in any public demonstration.
