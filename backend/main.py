"""AgentGuard FastAPI demo (actor IDs are NOT production authentication)."""
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.agent.runner import run_agent
from backend.monitoring.audit import alerts, recent_events
from backend.tools.documents import execute_tool

app = FastAPI(title="AgentGuard API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class SimulateRequest(BaseModel):
    actor_id: Literal["alice", "bob"]
    tool: Literal["list_documents", "read_document", "request_update"]
    arguments: dict = Field(default_factory=dict)


class ChatRequest(BaseModel):
    actor_id: Literal["alice", "bob"]
    prompt: str = Field(min_length=1, max_length=3000)


@app.get("/api/health")
def health():
    return {"status": "ok", "application": "AgentGuard", "mode": "student-demo"}


@app.get("/api/events")
def events():
    return {"events": recent_events(), "alerts": alerts()}


@app.post("/api/simulate")
def simulate(request: SimulateRequest):
    return execute_tool(request.actor_id, request.tool, request.arguments)


@app.post("/api/chat")
def chat(request: ChatRequest):
    try:
        return run_agent(request.actor_id, request.prompt)
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise HTTPException(
            status_code=503,
            detail="Local Ollama unavailable or too slow. Start Ollama and download qwen3:1.7b.",
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail="Ollama returned an error.") from exc
