"""
AI-Powered Threat Hunt Pilot
FastAPI backend — IBM Bob-a-thon submission

Endpoints:
  POST /hunt          → accepts natural language query, returns AQL + results + anomalies
  GET  /chains/{id}   → returns MITRE-mapped attack chain for a completed hunt
  GET  /hunts         → list recent hunt sessions
  GET  /health        → liveness check
"""

import uuid
import logging
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import (
    HuntRequest,
    HuntResponse,
    AttackChainResponse,
    HuntSummary,
    HealthResponse,
)
from .qradar_client import QRadarClient
from .llm_engine import LLMEngine
from .anomaly import AnomalyDetector
from .attack_chain import AttackChainBuilder

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("threat-hunt")

# ---------------------------------------------------------------------------
# In-memory hunt store  (replace with Redis / DB in production)
# ---------------------------------------------------------------------------
hunt_store: dict[str, HuntResponse] = {}


# ---------------------------------------------------------------------------
# App lifecycle — initialise shared clients once at startup
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up — initialising QRadar and LLM clients")
    app.state.qradar = QRadarClient()
    app.state.llm = LLMEngine()
    app.state.anomaly = AnomalyDetector()
    app.state.chain_builder = AttackChainBuilder()
    yield
    logger.info("Shutting down")
    await app.state.qradar.close()


app = FastAPI(
    title="AI Threat Hunt Pilot",
    description="Natural-language threat hunting powered by IBM QRadar + LLM (Bob-a-thon)",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------
def get_qradar(request: Request) -> QRadarClient:
    return request.app.state.qradar


def get_llm(request: Request) -> LLMEngine:
    return request.app.state.llm


def get_anomaly(request: Request) -> AnomalyDetector:
    return request.app.state.anomaly


def get_chain_builder(request: Request) -> AttackChainBuilder:
    return request.app.state.chain_builder


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health():
    """Liveness probe."""
    return HealthResponse(status="ok", timestamp=datetime.utcnow().isoformat())


@app.post("/hunt", response_model=HuntResponse, tags=["hunt"])
async def run_hunt(
    body: HuntRequest,
    qradar: QRadarClient = Depends(get_qradar),
    llm: LLMEngine = Depends(get_llm),
    anomaly: AnomalyDetector = Depends(get_anomaly),
    chain_builder: AttackChainBuilder = Depends(get_chain_builder),
):
    """
    Accept a natural-language threat hypothesis and return:
    - Generated AQL query
    - Raw matching events from QRadar
    - Anomalous events flagged against baseline
    - MITRE ATT&CK-mapped attack chain
    """
    hunt_id = str(uuid.uuid4())
    logger.info("Hunt %s started: %s", hunt_id, body.query_text)

    # 1. Translate NL → AQL via LLM (Bob-assisted prompt)
    aql_query = await llm.generate_aql(body.query_text, days=body.days)
    logger.info("Hunt %s  AQL: %s", hunt_id, aql_query)

    # 2. Execute AQL against QRadar
    raw_events = await qradar.run_search(aql_query)
    logger.info("Hunt %s  events returned: %d", hunt_id, len(raw_events))

    # 3. Anomaly detection against rolling baseline
    anomalies = anomaly.detect(raw_events)
    logger.info("Hunt %s  anomalies flagged: %d", hunt_id, len(anomalies))

    # 4. Build MITRE-mapped attack chain
    chain = chain_builder.build(raw_events, anomalies)

    # 5. Persist and return
    response = HuntResponse(
        hunt_id=hunt_id,
        query_text=body.query_text,
        aql_query=aql_query,
        days=body.days,
        total_events=len(raw_events),
        events=raw_events[:200],        # cap payload; full set stored server-side
        anomalies=anomalies,
        attack_chain=chain,
        created_at=datetime.utcnow().isoformat(),
    )
    hunt_store[hunt_id] = response
    return response


@app.get("/chains/{hunt_id}", response_model=AttackChainResponse, tags=["hunt"])
async def get_chain(hunt_id: str):
    """Return the full MITRE-mapped attack chain for a completed hunt."""
    hunt = hunt_store.get(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail=f"Hunt {hunt_id} not found")
    return AttackChainResponse(
        hunt_id=hunt_id,
        attack_chain=hunt.attack_chain,
        created_at=hunt.created_at,
    )


@app.get("/hunts", response_model=list[HuntSummary], tags=["hunt"])
async def list_hunts():
    """List recent hunt sessions (most recent first, capped at 50)."""
    summaries = [
        HuntSummary(
            hunt_id=h.hunt_id,
            query_text=h.query_text,
            total_events=h.total_events,
            anomaly_count=len(h.anomalies),
            created_at=h.created_at,
        )
        for h in hunt_store.values()
    ]
    return sorted(summaries, key=lambda s: s.created_at, reverse=True)[:50]


# ---------------------------------------------------------------------------
# Global error handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )


# ---------------------------------------------------------------------------
# Dev entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
