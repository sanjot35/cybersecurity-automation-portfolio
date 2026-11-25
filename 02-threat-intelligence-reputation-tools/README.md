# Threat Intelligence Reputation Tools

This repository contains my Python GUI tools for IP and file-hash reputation enrichment.

## Included scripts
- `ip_reputation_gui.py` — reads IP addresses from an Excel sheet and queries VirusTotal and AbuseIPDB; writes reputation, ISP, domain, and abuse-confidence information back to Excel.
- `hash_reputation_gui.py` — reads hashes from an Excel sheet and queries VirusTotal for MD5, SHA-256, analysis reputation, and file-type information.
- `hash_to_md5_slack_notification.py` — converts file hashes to MD5 using VirusTotal and posts a summary through a Slack webhook.

## Skills demonstrated
Python, Tkinter, REST API integration, JSON parsing, Excel input/output, indicator enrichment, and workflow notification.

## Configuration
Use your own API keys and Slack webhook through environment variables or a local configuration file excluded from Git. Never hardcode or commit secrets.

## Limitations
Reputation results are enrichment signals, not definitive proof of maliciousness. Handle API rate limits and errors, and validate output before using it in incident response.

## Public-release note
The uploaded `IP_Repo_Tool.py` and `IP_Repo_EXE_TOOL.py` copies are identical; this repository includes one copy to avoid duplication.
