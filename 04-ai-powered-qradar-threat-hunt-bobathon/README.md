# AI-Powered QRadar Threat Hunt Pilot — Bob-a-thon

## Overview
A Bob-a-thon prototype exploring AI-assisted threat hunting with IBM QRadar. The workflow accepts a natural-language hunting hypothesis, generates QRadar AQL using an LLM (configured for IBM watsonx.ai/Granite), executes the query through the QRadar Ariel REST API, analyzes returned events with heuristic anomaly detectors, and maps observed behaviors to MITRE ATT&CK techniques to build an attack-chain view.

## Components
- **Natural language → AQL:** LLM prompt and query generation with a fallback query template.
- **QRadar API client:** asynchronous Ariel search lifecycle (submit, poll, paginated results), plus offense endpoints.
- **Anomaly detection:** frequency z-score, rare process, off-hours, and fan-out heuristics.
- **Attack-chain mapping:** pattern-based MITRE ATT&CK technique mapping and tactic ordering.
- **API and UI:** FastAPI endpoints and a lightweight HTML dashboard.
- **Tests:** pytest coverage with mocked HTTP calls for QRadar/API workflows and detector/attack-chain logic.

## Status and limitations
This is a **pilot/prototype**, not a production-ready autonomous threat-hunting system. The demo scripts use mock/sample events; live QRadar execution requires an authorized QRadar environment and valid configuration. Anomaly detection and ATT&CK mapping are heuristic and should be validated by an analyst. Hunt results are stored in memory in this implementation.

## Run locally
1. Create a virtual environment and install `requirements.txt`.
2. Copy `.env.example` to `.env` and configure QRadar and watsonx credentials.
3. Start the API from the project root:
   `uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000`
4. Run tests with `pytest tests/ -v`.
5. Review `DEMO_INSTRUCTIONS.md` for the mock demo flow.

## Security notes before publishing or deploying
- Never commit `.env`, API tokens, real QRadar hostnames, client logs, or incident data.
- Use synthetic data in screenshots and examples.
- The sample API currently enables permissive CORS (`*`) and keeps hunt sessions in memory; restrict CORS, add appropriate authentication/authorization, and use durable storage before deployment.
- Keep TLS verification enabled. Do not disable certificate validation in production.
- Confirm employer/client approval before publishing any code or architecture details developed in a work environment.

## Portfolio description
**AI-Assisted QRadar Threat Hunting (Bob-a-thon):** Built a prototype connecting natural-language hunt hypotheses to QRadar AQL generation, asynchronous Ariel search execution, heuristic anomaly detection, and MITRE ATT&CK attack-chain mapping. Designed the backend with FastAPI and an LLM integration configured for IBM watsonx.ai, and added mocked API tests for core workflows.
