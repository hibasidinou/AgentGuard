"""Local Ollama API adapter. No cloud API key needed."""
import os
import httpx

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "list_documents",
            "description": "List documents accessible to the current actor.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_document",
            "description": "Read one document by its exact ID.",
            "parameters": {
                "type": "object",
                "properties": {"document_id": {"type": "string"}},
                "required": ["document_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_update",
            "description": "Request a document change; requires human approval.",
            "parameters": {
                "type": "object",
                "properties": {
                    "document_id": {"type": "string"},
                    "proposed_text": {"type": "string"},
                },
                "required": ["document_id", "proposed_text"],
            },
        },
    },
]


def next_message(messages: list[dict]) -> dict:
    """Call local Ollama synchronously for a single assistant turn."""
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": messages,
        "tools": TOOL_SPECS,
        "options": {"temperature": 0},
    }
    with httpx.Client(timeout=120) as client:
        response = client.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        return response.json().get("message", {})
