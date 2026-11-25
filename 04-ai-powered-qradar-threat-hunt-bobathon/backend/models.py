"""
models.py — Pydantic request/response schemas for the Threat Hunt API
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class HuntRequest(BaseModel):
    query_text: str = Field(
        ...,
        min_length=5,
        max_length=500,
        description="Natural language threat hunting hypothesis",
        examples=["Find suspicious lateral movement using PowerShell in last 7 days"],
    )
    days: int = Field(
        default=7,
        ge=1,
        le=90,
        description="Look-back window in days",
    )


# ---------------------------------------------------------------------------
# Events & Anomalies
# ---------------------------------------------------------------------------

class Event(BaseModel):
    event_name: Optional[str] = None
    username: Optional[str] = None
    sourceip: Optional[str] = None
    destinationip: Optional[str] = None
    category: Optional[str] = None
    devicetime: Optional[str] = None
    command_line: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Anomaly(BaseModel):
    event: Event
    reason: str = Field(description="Human-readable explanation of why this is anomalous")
    severity: str = Field(
        default="medium",
        description="low | medium | high | critical",
    )
    zscore: Optional[float] = Field(
        default=None,
        description="Z-score of the anomalous metric, if applicable",
    )


# ---------------------------------------------------------------------------
# Attack chain (MITRE ATT&CK)
# ---------------------------------------------------------------------------

class MitreTechnique(BaseModel):
    technique_id: str = Field(description="e.g. T1059.001")
    technique_name: str = Field(description="e.g. PowerShell")
    tactic: str = Field(description="e.g. Execution")
    description: str = ""
    evidence_events: list[str] = Field(
        default_factory=list,
        description="Hostnames or event snippets supporting this technique",
    )


class KillChainStep(BaseModel):
    step: int
    tactic: str
    techniques: list[MitreTechnique]
    source_hosts: list[str] = Field(default_factory=list)
    dest_hosts: list[str] = Field(default_factory=list)
    timestamp_first: Optional[str] = None
    timestamp_last: Optional[str] = None


class AttackChain(BaseModel):
    steps: list[KillChainStep] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    techniques_summary: list[str] = Field(
        default_factory=list,
        description="List of technique IDs observed, e.g. ['T1059.001', 'T1021.002']",
    )


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class HuntResponse(BaseModel):
    hunt_id: str
    query_text: str
    aql_query: str
    days: int
    total_events: int
    events: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    attack_chain: AttackChain = Field(default_factory=AttackChain)
    created_at: str


class AttackChainResponse(BaseModel):
    hunt_id: str
    attack_chain: AttackChain
    created_at: str


class HuntSummary(BaseModel):
    hunt_id: str
    query_text: str
    total_events: int
    anomaly_count: int
    created_at: str


class HealthResponse(BaseModel):
    status: str
    timestamp: str
