# Threat Intelligence Reputation Tools

This repository contains my Python GUI tools for IP and file-hash reputation enrichment.

## Included scripts
- `ip_reputation_gui.py` — reads IP addresses from an Excel sheet and queries VirusTotal and AbuseIPDB; writes reputation, ISP, domain, and abuse-confidence information back to Excel.
- `hash_reputation_gui.py` — reads hashes from an Excel sheet and queries VirusTotal for MD5, SHA-256, analysis reputation, and file-type information.
- `hash_to_md5_slack_notification.py` — converts file hashes to MD5 using VirusTotal and posts a summary through a Slack webhook.
