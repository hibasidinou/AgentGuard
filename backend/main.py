"""AgentGuard FastAPI demo with server-owned authenticated sessions (AG-66)."""
from contextlib import asynccontextmanager
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

from backend.agent.runner import run_agent
from backend.monitoring.audit import alerts, recent_events
from backend.security.auth.http import (
    AuthenticatedContext, initialize_auth, sanitized_validation_error,
)
from backend.security.auth.routes import router as auth_router
from backend.tools.documents import execute_tool


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: Literal["list_documents", "read_document", "request_update"]
    arguments: dict = Field(default_factory=dict)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    prompt: str = Field(min_length=1, max_length=3000)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Read configuration and initialize the shared server-owned store once.
    # Startup fails closed if provisioning, storage or the signing key is invalid.
    app.state.sessions = initialize_auth()
    try:
        yield
    finally:
        del app.state.sessions


def create_app() -> FastAPI:
    application = FastAPI(title="AgentGuard API", version="0.1.0", lifespan=lifespan)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
    application.add_exception_handler(RequestValidationError, sanitized_validation_error)
    application.include_router(auth_router)
    application.add_api_route("/api/health", health, methods=["GET"])
    application.add_api_route("/api/events", events, methods=["GET"])
    application.add_api_route("/api/simulate", simulate, methods=["POST"])
    application.add_api_route("/api/chat", chat, methods=["POST"])
    return application


def health():
    return {"status": "ok", "application": "AgentGuard", "mode": "student-demo"}


def events():
    return {"events": recent_events(), "alerts": alerts()}


def simulate(request: SimulateRequest, context: AuthenticatedContext, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return execute_tool(context, request.tool, request.arguments)


def chat(request: ChatRequest, context: AuthenticatedContext, response: Response):
    response.headers["Cache-Control"] = "no-store"
    try:
        return run_agent(context, request.prompt)
    except (httpx.ConnectError, httpx.TimeoutException):
        raise HTTPException(
            status_code=503,
            detail="Local Ollama unavailable or too slow. Start Ollama and download qwen3:1.7b.",
            headers={"Cache-Control": "no-store"},
        ) from None
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=502, detail="Ollama returned an error.",
                            headers={"Cache-Control": "no-store"}) from None


app = create_app()
