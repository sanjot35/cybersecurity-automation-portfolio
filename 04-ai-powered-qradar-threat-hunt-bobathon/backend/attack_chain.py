"""
attack_chain.py — MITRE ATT&CK mapping and kill chain builder

Maps raw events + anomalies to MITRE ATT&CK techniques,
then assembles them into an ordered kill chain (by tactic phase).
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from .models import Anomaly, AttackChain, Event, KillChainStep, MitreTechnique

logger = logging.getLogger("threat-hunt.chain")

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique lookup
# Keyed on (pattern_in_command_line_or_process_name, match_type)
# match_type: "cmd" = match against command_line, "proc" = match against process_name
# ---------------------------------------------------------------------------
TECHNIQUE_RULES: list[dict] = [
    # Execution
    {
        "id": "T1059.001", "name": "PowerShell", "tactic": "Execution",
        "patterns": [r"powershell", r"pwsh", r"-encodedcommand", r"invoke-expression"],
        "field": "cmd_or_proc",
    },
    {
        "id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution",
        "patterns": [r"\bcmd\.exe\b", r"\bcmd\b.*\/c\b"],
        "field": "cmd_or_proc",
    },
    {
        "id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution",
        "patterns": [r"wmic", r"wmiexec", r"invoke-wmimethod"],
        "field": "cmd_or_proc",
    },
    {
        "id": "T1053.005", "name": "Scheduled Task", "tactic": "Execution",
        "patterns": [r"schtasks", r"at\.exe", r"taskschd"],
        "field": "cmd_or_proc",
    },

    # Lateral Movement
    {
        "id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
        "patterns": [r"net use", r"net view", r"\\\\.*\\(admin\$|c\$|ipc\$)"],
        "field": "cmd",
    },
    {
        "id": "T1021.006", "name": "Windows Remote Management", "tactic": "Lateral Movement",
        "patterns": [r"winrm", r"new-pssession", r"invoke-command.*-computername", r"wsman"],
        "field": "cmd",
    },
    {
        "id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
        "patterns": [r"psexec", r"paexec", r"xcopy.*\\\\.+\\"],
        "field": "cmd",
    },

    # Credential Access
    {
        "id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access",
        "patterns": [r"mimikatz", r"sekurlsa", r"lsass", r"procdump.*lsass"],
        "field": "cmd",
    },
    {
        "id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access",
        "patterns": [r"findstr.*password", r"type.*\.config", r"select-string.*pass"],
        "field": "cmd",
    },

    # Defense Evasion
    {
        "id": "T1562.001", "name": "Disable/Modify Tools", "tactic": "Defense Evasion",
        "patterns": [r"set-mppreference", r"add-mppreference.*exclusion", r"sc stop.*defender"],
        "field": "cmd",
    },
    {
        "id": "T1070.001", "name": "Clear Windows Event Logs", "tactic": "Defense Evasion",
        "patterns": [r"wevtutil.*cl", r"clear-eventlog", r"remove-eventlog"],
        "field": "cmd",
    },
    {
        "id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
        "patterns": [r"-encodedcommand", r"base64", r"frombase64string", r"char\(\d+\)"],
        "field": "cmd",
    },

    # Persistence
    {
        "id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence",
        "patterns": [r"reg add.*run", r"set-itemproperty.*currentversion\\run"],
        "field": "cmd",
    },
    {
        "id": "T1136.001", "name": "Local Account Creation", "tactic": "Persistence",
        "patterns": [r"net user.*\/add", r"new-localuser"],
        "field": "cmd",
    },

    # Impact
    {
        "id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact",
        "patterns": [r"vssadmin.*delete", r"wbadmin.*delete", r"bcdedit.*recoveryenabled.*no"],
        "field": "cmd",
    },
    {
        "id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact",
        "patterns": [r"\.encrypt\b", r"cryptolocker", r"ransom"],
        "field": "cmd",
    },
]

# Ordered kill chain phases (ATT&CK tactic sequence)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class AttackChainBuilder:
    """
    Builds a MITRE ATT&CK-mapped attack chain from a batch of events and anomalies.
    """

    def build(
        self,
        raw_events: list[dict[str, Any]],
        anomalies: list[Anomaly],
    ) -> AttackChain:
        """
        Main entry point.

        1. Map every event to matching MITRE techniques
        2. Cluster techniques by tactic
        3. Order tactics by kill chain phase
        4. Return AttackChain with KillChainStep list
        """
        if not raw_events:
            return AttackChain()

        events = [self._to_event(e) for e in raw_events]

        # technique_id → {events, technique metadata}
        technique_map: dict[str, dict] = {}
        for event in events:
            for rule in TECHNIQUE_RULES:
                if self._matches(event, rule):
                    tid = rule["id"]
                    if tid not in technique_map:
                        technique_map[tid] = {
                            "rule": rule,
                            "events": [],
                            "hosts": set(),
                            "sources": set(),
                            "dests": set(),
                            "times": [],
                        }
                    technique_map[tid]["events"].append(event)
                    if event.hostname:
                        technique_map[tid]["hosts"].add(event.hostname)
                    if event.sourceip:
                        technique_map[tid]["sources"].add(event.sourceip)
                    if event.destinationip:
                        technique_map[tid]["dests"].add(event.destinationip)
                    if event.devicetime:
                        technique_map[tid]["times"].append(event.devicetime)

        if not technique_map:
            logger.info("No MITRE techniques matched in event batch")
            return AttackChain()

        # Group by tactic
        tactic_techniques: dict[str, list[MitreTechnique]] = defaultdict(list)
        all_hosts: set[str] = set()
        all_sources: set[str] = set()

        for tid, meta in technique_map.items():
            rule = meta["rule"]
            times = sorted(meta["times"])
            tech = MitreTechnique(
                technique_id=tid,
                technique_name=rule["name"],
                tactic=rule["tactic"],
                description=f"Detected via pattern match on {rule['field']} field",
                evidence_events=list(meta["hosts"])[:5],
            )
            tactic_techniques[rule["tactic"]].append(tech)
            all_hosts |= meta["hosts"]
            all_sources |= meta["sources"]

        # Build ordered steps
        steps: list[KillChainStep] = []
        step_num = 1
        for tactic in TACTIC_ORDER:
            techs = tactic_techniques.get(tactic)
            if not techs:
                continue

            # Collect hosts/IPs across techniques in this tactic
            step_hosts: set[str] = set()
            step_sources: set[str] = set()
            step_dests: set[str] = set()
            step_times: list[str] = []

            for tid_meta in [
                technique_map[t.technique_id]
                for t in techs
                if t.technique_id in technique_map
            ]:
                step_hosts |= tid_meta["hosts"]
                step_sources |= tid_meta["sources"]
                step_dests |= tid_meta["dests"]
                step_times.extend(tid_meta["times"])

            step_times_sorted = sorted(step_times)
            steps.append(
                KillChainStep(
                    step=step_num,
                    tactic=tactic,
                    techniques=techs,
                    source_hosts=sorted(step_sources)[:10],
                    dest_hosts=sorted(step_dests)[:10],
                    timestamp_first=step_times_sorted[0] if step_times_sorted else None,
                    timestamp_last=step_times_sorted[-1] if step_times_sorted else None,
                )
            )
            step_num += 1

        techniques_summary = sorted(technique_map.keys())
        logger.info(
            "Attack chain built: %d steps, %d techniques, %d affected hosts",
            len(steps),
            len(techniques_summary),
            len(all_hosts),
        )

        return AttackChain(
            steps=steps,
            source_ips=sorted(all_sources)[:20],
            affected_hosts=sorted(all_hosts)[:20],
            techniques_summary=techniques_summary,
        )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _matches(event: Event, rule: dict) -> bool:
        """Check if an event matches any of a rule's regex patterns."""
        field = rule.get("field", "cmd")
        targets: list[str] = []

        if field in ("cmd", "cmd_or_proc"):
            if event.command_line:
                targets.append(event.command_line.lower())

        if field in ("proc", "cmd_or_proc"):
            if event.process_name:
                targets.append(event.process_name.lower())

        if not targets:
            return False

        for pattern in rule["patterns"]:
            for target in targets:
                try:
                    if re.search(pattern, target, re.IGNORECASE):
                        return True
                except re.error:
                    pass
        return False

    @staticmethod
    def _to_event(raw: dict[str, Any]) -> Event:
        from .models import Event as EventModel
        return EventModel(
            event_name=raw.get("event_name") or raw.get("QIDNAME(qid)"),
            username=raw.get("username"),
            sourceip=raw.get("sourceip"),
            destinationip=raw.get("destinationip"),
            category=raw.get("category"),
            devicetime=str(raw.get("devicetime", "")),
            command_line=raw.get("command_line") or raw.get("Command Line"),
            hostname=raw.get("hostname"),
            process_name=raw.get("process_name") or raw.get("Process Name"),
            raw=raw,
        )
